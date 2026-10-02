"""Dependency-free DNS pcap analyzer.

Usage:
    python _pcap_dns_check.py <file.pcap> [--top=N] [--ports=53,5353]
                              [--local|--utc] [--csv=out.csv]

Supports Ethernet (DLT 1, incl. VLAN) and Linux SLL (DLT 113), IPv4/IPv6.
Parses DNS over UDP and DNS over TCP (messages contained in one segment),
matches queries to responses and reports:

  overview      packets, protocol mix, capture span
  summary       queries / responses / matched / unanswered / orphan responses,
                UDP vs TCP, truncated (TC) answers, EDNS0, latency stats
  anomalies     unanswered queries, retransmitted (repeated) queries,
                slowest responses, NXDOMAIN breakdown
  traffic       top clients, top queried names, query types, response codes,
                resolvers
  indicators    DGA / DNS-tunnelling style heuristics: over-long names,
                high-entropy labels, large TXT answers, many unique
                subdomains under one base domain, ANY-type queries,
                TXT/PTR-heavy clients

Frame numbers are 1-based capture indices (Wireshark's frame.number).
Times are relative to the first packet by default, matching Wireshark's
default time column; --local / --utc switch to absolute time.

Notes / limits
  * DNS over TCP is parsed when the message fits in a single TCP segment;
    split messages are counted but not decoded (no stream reassembly).
  * base-domain grouping uses the last two labels, so multi-part public
    suffixes (co.uk, com.cn, ...) are grouped coarsely.
"""
import hashlib
import math
import socket
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ------------------------------------------------------------------ CLI / mode
_FLAGS = [a for a in sys.argv[1:] if a.startswith("--")]
_ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
UTC_MODE = "--utc" in _FLAGS
LOCAL_MODE = "--local" in _FLAGS
RELATIVE_MODE = not (UTC_MODE or LOCAL_MODE)


def _opt(name, default):
    for f in _FLAGS:
        if f.startswith(name + "="):
            return f.split("=", 1)[1]
    return default


TOP = int(_opt("--top", "15"))
PORTS = set(int(p) for p in _opt("--ports", "53").split(",") if p.strip())
CSV_PATH = _opt("--csv", None)
MAX_LIST = 40                     # cap for "list everything" sections

# Multi-interface captures (common with pcapng: one machine, several NICs)
# record the same frame once per interface. --dedup collapses byte-identical
# frames seen within DUP_WINDOW seconds down to a single copy.
DEDUP = "--dedup" in _FLAGS
DUP_WINDOW = 0.002

PATH = _ARGS[0] if _ARGS else "dns.pcap"
DATA = open(PATH, "rb").read()

T0 = 0.0


# ------------------------------------------------------- capture file reading
def _iter_pcapng(data):
    """Yield (ts, linktype, frame, truncated) from a pcapng stream.

    Handles Section Header, Interface Description, Enhanced/obsolete Packet
    and Simple Packet blocks, little- and big-endian files, multiple sections
    and per-interface timestamp resolution (if_tsresol).
    """
    off = 0
    endian = "<"
    ifaces = []                     # (linktype, timestamp resolution seconds)
    while off + 12 <= len(data):
        raw_type = struct.unpack_from("<I", data, off)[0]
        if raw_type == 0x0A0D0D0A:                       # Section Header Block
            bom = data[off + 8:off + 12]
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                return
            ifaces = []
        btype = struct.unpack_from(endian + "I", data, off)[0]
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if blen < 12 or off + blen > len(data):
            return
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:                          # Interface Description
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            res = 1e-6
            o = 8
            while o + 4 <= len(body):
                code, olen = struct.unpack_from(endian + "HH", body, o)
                o += 4
                if code == 0:
                    break
                if code == 9 and olen >= 1:              # if_tsresol
                    v = body[o]
                    res = (2.0 ** -(v & 0x7F)) if v & 0x80 else (10.0 ** -v)
                o += (olen + 3) & ~3
            ifaces.append((linktype, res))
        elif btype == 0x00000006:                        # Enhanced Packet Block
            iface, tsh, tsl, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
            lt, res = ifaces[iface] if iface < len(ifaces) else (1, 1e-6)
            yield (((tsh << 32) | tsl) * res, lt, body[20:20 + caplen], caplen != origlen)
        elif btype == 0x00000002:                        # obsolete Packet Block
            iface, _drops, tsh, tsl, caplen, origlen = struct.unpack_from(
                endian + "HHIIII", body, 0)
            lt, res = ifaces[iface] if iface < len(ifaces) else (1, 1e-6)
            yield (((tsh << 32) | tsl) * res, lt, body[20:20 + caplen], caplen != origlen)
        elif btype == 0x00000003:                        # Simple Packet Block
            origlen = struct.unpack_from(endian + "I", body, 0)[0]
            lt = ifaces[0][0] if ifaces else 1
            yield (0.0, lt, body[4:4 + origlen], False)
        off += blen


def iter_packets(data):
    """Yield (ts, linktype, frame, truncated) from pcap or pcapng data."""
    if len(data) < 4:
        return
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0x0A0D0D0A:                              # pcapng
        yield from _iter_pcapng(data)
        return
    if magic in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):   # classic pcap
        endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
        _mg, _maj, _min, _tz, _sig, _snap, linktype = struct.unpack_from(
            endian + "IHHiIII", data, 0)
        off = 24
        while off + 16 <= len(data):
            ts_sec, ts_frac, incl, orig = struct.unpack_from(endian + "IIII", data, off)
            off += 16
            frame = data[off:off + incl]
            off += incl
            yield (ts_sec + ts_frac / (1e9 if nano else 1e6), linktype, frame, incl != orig)
    else:
        raise ValueError("unsupported capture format (magic 0x%08X): expected pcap or pcapng"
                         % magic)


def ts2str(ts):
    if RELATIVE_MODE:
        return "+%.6f" % (ts - T0)
    dt = datetime.fromtimestamp(ts, timezone.utc)
    if not UTC_MODE:
        dt = dt.astimezone()
    return dt.strftime("%H:%M:%S.%f")


def tz_label():
    if RELATIVE_MODE:
        return "relative to first packet"
    return "UTC" if UTC_MODE else str(datetime.now().astimezone().tzinfo)


# ------------------------------------------------------------------ DNS tables
QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX",
         16: "TXT", 17: "RP", 28: "AAAA", 29: "LOC", 33: "SRV", 35: "NAPTR",
         36: "KX", 37: "CERT", 39: "DNAME", 41: "OPT", 42: "APL", 43: "DS",
         44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
         49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA",
         55: "HIP", 59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC",
         63: "ZONEMD", 64: "SVCB", 65: "HTTPS", 99: "SPF", 108: "EUI48",
         109: "EUI64", 249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR",
         255: "ANY", 256: "URI", 257: "CAA", 32768: "TA", 32769: "DLV"}
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
         4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
         8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 16: "BADVERS"}
SERVICE = {53: "dns", 5353: "mdns", 5355: "llmnr", 853: "dot", 443: "https"}
SKIP_ENTROPY_PREFIX = ("_", "in-addr.arpa", "ip6.arpa")


def qtype_name(t):
    return QTYPE.get(t, "TYPE%d" % t)


def rcode_name(r):
    return RCODE.get(r, "RCODE%d" % r)


# ------------------------------------------------------------------ DNS parsing
class ParseError(Exception):
    pass


def parse_name(pkt, off, depth=0):
    """Return (name, new_off). Handles compression pointers."""
    labels = []
    jumped = False
    end = off
    for _ in range(128):
        if off >= len(pkt):
            raise ParseError("name past end")
        ln = pkt[off]
        if ln == 0:
            off += 1
            if not jumped:
                end = off
            return ".".join(labels), end
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(pkt):
                raise ParseError("bad pointer")
            ptr = ((ln & 0x3F) << 8) | pkt[off + 1]
            if not jumped:
                end = off + 2
                jumped = True
            if depth > 16:
                raise ParseError("pointer loop")
            sub, _ = parse_name(pkt, ptr, depth + 1)
            if sub:
                labels.append(sub)
            return ".".join(labels), end
        if ln & 0xC0:
            raise ParseError("bad label length")
        if off + 1 + ln > len(pkt):
            raise ParseError("label past end")
        labels.append(pkt[off + 1:off + 1 + ln].decode("latin-1"))
        off += 1 + ln
    raise ParseError("name too long")


def decode_rdata(pkt, off, rtype, rdlen):
    rdata = pkt[off:off + rdlen]
    if len(rdata) < rdlen:
        return "<truncated rdata>"
    try:
        if rtype == 1 and rdlen == 4:
            return socket.inet_ntoa(rdata)
        if rtype == 28 and rdlen == 16:
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if rtype in (2, 5, 12, 39):
            return parse_name(pkt, off)[0]
        if rtype == 15 and rdlen >= 3:
            pref = struct.unpack_from(">H", pkt, off)[0]
            return "%d %s" % (pref, parse_name(pkt, off + 2)[0])
        if rtype == 6:
            mname, o = parse_name(pkt, off)
            rname, o = parse_name(pkt, o)
            serial, refresh, retry, expire, minimum = struct.unpack_from(">IIIII", pkt, o)
            return "%s %s serial=%d" % (mname, rname, serial)
        if rtype == 16:
            out, o = [], off
            while o < off + rdlen:
                ln = pkt[o]
                out.append(pkt[o + 1:o + 1 + ln].decode("latin-1"))
                o += 1 + ln
            return " ".join(out)
        if rtype == 33 and rdlen >= 7:
            prio, weight, port = struct.unpack_from(">HHH", pkt, off)
            return "%d %d %d %s" % (prio, weight, port, parse_name(pkt, off + 6)[0])
        if rtype == 257 and rdlen >= 2:
            flags = pkt[off]
            tlen = pkt[off + 1]
            tag = pkt[off + 2:off + 2 + tlen].decode("latin-1", "replace")
            val = pkt[off + 2 + tlen:off + rdlen].decode("latin-1", "replace")
            return "%d %s %s" % (flags, tag, val)
        if rtype == 41:                      # OPT pseudo-RR
            return "EDNS0"
    except Exception:
        return "<undecodable>"
    if rdlen <= 16 and all(32 <= b < 127 for b in rdata):
        return rdata.decode("latin-1")
    return "<%d bytes>" % rdlen


def parse_dns(pkt, off=0):
    """Parse one DNS message; returns a dict or raises ParseError."""
    if len(pkt) - off < 12:
        raise ParseError("short header")
    (mid, flags, qd, an, ns, ar) = struct.unpack_from(">HHHHHH", pkt, off)
    msg = {
        "id": mid, "flags": flags, "qr": (flags >> 15) & 1, "opcode": (flags >> 11) & 0xF,
        "aa": (flags >> 10) & 1, "tc": (flags >> 9) & 1, "rd": (flags >> 8) & 1,
        "ra": (flags >> 7) & 1, "rcode": flags & 0xF,
        "questions": [], "answers": [], "authority": [], "additional": [],
    }
    o = off + 12
    for _ in range(qd):
        name, o = parse_name(pkt, o)
        if o + 4 > len(pkt):
            raise ParseError("short question")
        qtype, qclass = struct.unpack_from(">HH", pkt, o)
        o += 4
        msg["questions"].append((name, qtype, qclass))
    for section, count in (("answers", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            rname, o = parse_name(pkt, o)
            if o + 10 > len(pkt):
                raise ParseError("short rr")
            rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH", pkt, o)
            o += 10
            if o + rdlen > len(pkt):
                raise ParseError("rdata past end")
            value = decode_rdata(pkt, o, rtype, rdlen)
            o += rdlen
            if rtype == 41:                                   # OPT pseudo-RR = EDNS0
                msg["edns"] = True
                msg["edns_udp"] = rclass
                continue
            msg[section].append({"name": rname, "type": rtype, "class": rclass,
                                 "ttl": ttl, "rdlen": rdlen, "value": value})
    return msg


# ------------------------------------------------------------------ statistics
questions = []          # every query record
responses = 0           # every parsed response message
tx = []                 # matched transactions
orphans = []            # responses with no matching query
unparsed = []           # dns payloads that failed to parse / partial TCP
pending = defaultdict(list)

packets = tcp_packets = udp_packets = dns_udp = dns_tcp = dns_tcp_partial = 0
other_udp_ports = Counter()
t_first = t_last = None


def base_domain(name):
    parts = name.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = float(len(s))
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def max_consonant_run(s):
    best = run = 0
    for ch in s.lower():
        if ch.isalpha() and ch not in "aeiou":
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def looks_random(label):
    """Heuristic: high entropy plus machine-generated shape.

    Requires two independent signals so ordinary hyphenated English names
    (which also have high character entropy) are not flagged.
    """
    if len(label) < 12:
        return False
    low = label.lower()
    if low.endswith(SKIP_ENTROPY_PREFIX):
        return False
    if entropy(low) < 3.6:
        return False
    digits = sum(c.isdigit() for c in low)
    return digits >= 2 or max_consonant_run(low) >= 5


def tx_key(rec):
    """Direction-independent transaction key (works for query and response)."""
    return (rec["client"], rec["client_port"], rec["server"], rec["server_port"], rec["id"])


def note_query(rec):
    questions.append(rec)
    pending[tx_key(rec)].append(rec)


def match_response(rec):
    """Attach a response to the oldest matching pending query."""
    bucket = pending.get(tx_key(rec))
    if not bucket:
        orphans.append(rec)
        return
    q = None
    if rec["questions"]:
        qname, qtype = rec["questions"][0][0].lower(), rec["questions"][0][1]
        for cand in bucket:
            if cand["qname"].lower() == qname and cand["qtype"] == qtype:
                q = cand
                break
    if q is None:
        q = bucket[0]
    bucket.remove(q)
    if not bucket:
        pending.pop(tx_key(rec), None)
    q["response"] = rec
    q["latency"] = rec["ts"] - q["ts"]
    q["rcode"] = rec["rcode"]
    q["answer_count"] = len(rec["answers"])
    q["tc"] = rec["tc"]
    tx.append(q)


# ------------------------------------------------------------------- main loop
linktypes = set()
truncated_pkts = 0
dup_frames = 0
sig_seen = {}
for (ts, linktype, pkt, trunc_flag) in iter_packets(DATA):
    packets += 1
    frame = packets
    linktypes.add(linktype)
    if trunc_flag:
        truncated_pkts += 1
    t_first = ts if t_first is None else min(t_first, ts)
    t_last = ts
    if linktype == 1:                                 # Ethernet II
        if len(pkt) < 14:
            continue
        etype = struct.unpack_from(">H", pkt, 12)[0]
        pl = pkt[14:]
        if etype in (0x8100, 0x88A8):
            if len(pl) < 4:
                continue
            etype = struct.unpack_from(">H", pl, 2)[0]
            pl = pl[4:]
    elif linktype == 113:                             # Linux cooked capture (SLL)
        if len(pkt) < 16:
            continue
        etype = struct.unpack_from(">H", pkt, 14)[0]
        pl = pkt[16:]
    else:
        continue
    # duplicate-frame detection: hash the L3 packet, so copies of the same
    # packet that differ only in link-layer tags still collapse to one
    sig = hashlib.md5(pl).digest()
    prev = sig_seen.get(sig)
    if prev is not None and 0.0 <= ts - prev <= DUP_WINDOW:
        dup_frames += 1
        sig_seen[sig] = ts
        if DEDUP:
            continue
    else:
        sig_seen[sig] = ts
    if etype == 0x0800:
        if len(pl) < 20 or (pl[0] >> 4) != 4:
            continue
        ihl = (pl[0] & 0x0F) * 4
        frag = pl[6] & 0x20 or ((pl[6] & 0x1F) << 8) | pl[7]
        if frag:
            continue                                  # no IP reassembly
        total = struct.unpack_from(">H", pl, 2)[0]
        proto = pl[9]
        sip, dip = pl[12:16], pl[16:20]
    elif etype == 0x86DD:
        if len(pl) < 40 or (pl[0] >> 4) != 6:
            continue
        proto = pl[6]
        sip, dip = pl[8:24], pl[24:40]
        total = 40 + struct.unpack_from(">H", pl, 4)[0]
        ihl = 40
        if proto in (0, 43, 60, 44):
            continue                                  # extension headers: skip
    else:
        continue
    sport = dport = 0
    dns_payload = None
    if proto == 17:                                   # UDP
        udp_packets += 1
        if len(pl) < ihl + 8:
            continue
        sport, dport, ulen = struct.unpack_from(">HHH", pl, ihl)
        if sport in PORTS or dport in PORTS:
            dns_udp += 1
            dns_payload = pl[ihl + 8:total if total <= len(pl) else len(pl)]
        else:
            other_udp_ports[min(sport, dport)] += 1
    elif proto == 6:                                  # TCP
        tcp_packets += 1
        if len(pl) < ihl + 20:
            continue
        sport, dport = struct.unpack_from(">HH", pl, ihl)
        if sport not in PORTS and dport not in PORTS:
            continue
        doff = (pl[ihl + 12] >> 4) * 4
        tcp_payload = pl[ihl + doff:]
        if tcp_payload:
            dns_tcp += 1
            if len(tcp_payload) >= 2:
                mlen = struct.unpack_from(">H", tcp_payload, 0)[0]
                if mlen == len(tcp_payload) - 2:
                    dns_payload = tcp_payload[2:]
                else:
                    dns_tcp_partial += 1
            else:
                dns_tcp_partial += 1
    else:
        continue
    if dns_payload is None or not dns_payload:
        continue
    try:
        dns = parse_dns(dns_payload)
    except ParseError as exc:
        unparsed.append((frame, ts, str(exc)))
        continue
    src_ip = socket.inet_ntoa(sip) if len(sip) == 4 else socket.inet_ntop(socket.AF_INET6, sip)
    dst_ip = socket.inet_ntoa(dip) if len(dip) == 4 else socket.inet_ntop(socket.AF_INET6, dip)
    common = {"frame": frame, "ts": ts, "id": dns["id"], "src": src_ip, "dst": dst_ip,
              "sport": sport, "dport": dport, "dns": dns, "questions": dns["questions"],
              "answers": dns["answers"], "authority": dns["authority"],
              "additional": dns["additional"],
              "proto": "udp" if proto == 17 else "tcp"}
    if dns["qr"] == 0:
        qname = dns["questions"][0][0] if dns["questions"] else "<none>"
        qtype = dns["questions"][0][1] if dns["questions"] else -1
        rec = dict(common, client=src_ip, client_port=sport, server=dst_ip,
                   server_port=dport, qname=qname, qtype=qtype,
                   rd=dns["rd"], edns=dns.get("edns", False))
        note_query(rec)
    else:
        responses += 1
        rec = dict(common, client=dst_ip, client_port=dport, server=src_ip,
                   server_port=sport, rcode=dns["rcode"], tc=dns["tc"], aa=dns["aa"],
                   opcode=dns["opcode"])
        match_response(rec)

T0 = t_first if t_first is not None else 0.0

# ------------------------------------------------------------------- analysis
unanswered = [q for bucket in pending.values() for q in bucket]
repeated = defaultdict(list)
for q in questions:
    repeated[(q["client"], q["qname"].lower(), q["qtype"])].append(q)
repeated = {k: v for k, v in repeated.items() if len(v) > 1}

rcodes = Counter(t["rcode"] for t in tx)
qtypes = Counter(q["qtype"] for q in questions)
clients = Counter(q["client"] for q in questions)
servers = Counter(q["server"] for q in questions)
names = Counter(q["qname"].lower() for q in questions)
nxdomain = Counter(t["qname"].lower() for t in tx if t["rcode"] == 3)

lat = sorted(t["latency"] for t in tx if "latency" in t)


def pct(values, p):
    if not values:
        return 0.0
    return values[min(len(values) - 1, int(round((len(values) - 1) * p)))]


# --- suspicious indicators
long_names, high_entropy, big_txt, any_queries = [], [], [], []
subdomains = defaultdict(set)
for q in questions:
    name = q["qname"].rstrip(".")
    labels = name.split(".")
    longest = max(labels, key=len) if labels else ""
    low = name.lower()
    if len(name) > 52 or len(longest) > 40:
        long_names.append(q)
    if looks_random(longest):
        high_entropy.append((q, round(entropy(longest), 2), len(longest)))
    if q["qtype"] == 255:
        any_queries.append(q)
    subdomains[base_domain(low)].add(low)
tunnelling_bases = [(b, len(s)) for b, s in subdomains.items() if len(s) > 20]
for t in tx:
    for a in t["response"]["answers"]:
        if a["type"] == 16 and a["rdlen"] > 200:
            big_txt.append((t, a["rdlen"]))

truncated = [t for t in tx if t.get("tc")]
tcp_dns_tx = [t for t in tx if t["proto"] == "tcp"]

# ------------------------------------------------------------------- report
print("=" * 100)
print("PCAP: %s  |  %d pkts (tcp %d, udp %d, trunc %d)  |  linktype %s  |  dns ports %s%s"
      % (PATH, packets, tcp_packets, udp_packets, truncated_pkts,
         ",".join(str(t) for t in sorted(linktypes)),
         ",".join(str(p) for p in sorted(PORTS)),
         "  [protocol counts after --dedup]" if (DEDUP and dup_frames) else ""))
if dup_frames:
    print("NOTE: %d of %d frames are duplicate captures of the same packet "
          "(multi-interface capture) - %s"
          % (dup_frames, packets,
             "collapsed by --dedup" if DEDUP else "rerun with --dedup to collapse them"))
if t_first is not None:
    print("capture span: %s .. %s (%s)  |  duration %.6f s"
          % (ts2str(t_first), ts2str(t_last), tz_label(), t_last - t_first))
print("=" * 100)

if not questions and not responses and not orphans:
    print("\nNo DNS traffic found on port(s) %s."
          % ",".join(str(p) for p in sorted(PORTS)))
    if other_udp_ports:
        print("Top UDP ports seen instead: %s"
              % ", ".join("%d(%d)" % kv for kv in other_udp_ports.most_common(8)))
    sys.exit(0)

print("\nDNS SUMMARY")
print("   queries %d | responses %d | matched %d | unanswered %d | orphan responses %d"
      % (len(questions), responses, len(tx), len(unanswered), len(orphans)))
print("   dns/udp messages %d | dns/tcp messages %d | tcp dns not decoded %d | unparsable %d"
      % (dns_udp, dns_tcp - dns_tcp_partial, dns_tcp_partial, len(unparsed)))
if lat:
    print("   latency: min %.6f s | median %.6f s | p95 %.6f s | max %.6f s  (%d measured)"
          % (lat[0], pct(lat, 0.5), pct(lat, 0.95), lat[-1], len(lat)))
print("   truncated (TC=1) answers %d | EDNS0 queries %d | TCP fallback transactions %d"
      % (len(truncated), sum(1 for q in questions if q.get("edns")), len(tcp_dns_tx)))
rcode_text = ", ".join("%s %d" % (rcode_name(r), n) for r, n in rcodes.most_common(8))
print("   response codes: %s" % (rcode_text if rcode_text else "none"))
print("   query types: %s"
      % ", ".join("%s %d" % (qtype_name(t), n) for t, n in qtypes.most_common(10)))
print("   resolvers: %s"
      % ", ".join("%s (%d)" % (s, n) for s, n in servers.most_common(5)))

# --- unanswered
print("\n" + "-" * 100)
print("UNANSWERED QUERIES (%d)" % len(unanswered))
for q in sorted(unanswered, key=lambda q: q["ts"])[:MAX_LIST]:
    print("   #%-6d %s  %-15s -> %-15s %-6s %s"
          % (q["frame"], ts2str(q["ts"]), q["client"], q["server"],
             qtype_name(q["qtype"]), q["qname"]))
if len(unanswered) > MAX_LIST:
    print("   ... and %d more" % (len(unanswered) - MAX_LIST))

# --- orphan responses
print("\n" + "-" * 100)
print("ORPHAN RESPONSES (no matching query in capture) (%d)" % len(orphans))
for r in sorted(orphans, key=lambda r: r["ts"])[:MAX_LIST]:
    q = r["questions"][0][0] if r["questions"] else "<no question>"
    qt = qtype_name(r["questions"][0][1]) if r["questions"] else "-"
    print("   #%-6d %s  %-15s -> %-15s %-6s %-34s %s"
          % (r["frame"], ts2str(r["ts"]), r["server"], r["client"], qt, q[:34],
             rcode_name(r["rcode"])))
if len(orphans) > MAX_LIST:
    print("   ... and %d more" % (len(orphans) - MAX_LIST))

# --- repeated queries
print("\n" + "-" * 100)
print("REPEATED QUERIES (same client asked the same name+type more than once): %d"
      % len(repeated))
for (client, qname, qtype), recs in sorted(repeated.items(), key=lambda kv: -len(kv[1]))[:TOP]:
    gap = recs[-1]["ts"] - recs[0]["ts"]
    frames = ", ".join("#%d" % r["frame"] for r in recs[:6])
    print("   %-15s %-6s %-40s x%-3d over %.6f s  (%s%s)"
          % (client, qtype_name(qtype), qname, len(recs), gap, frames,
             ", ..." if len(recs) > 6 else ""))

# --- slowest
print("\n" + "-" * 100)
print("SLOWEST RESPONSES (top %d)" % min(TOP, len(tx)))
for t in sorted(tx, key=lambda t: -t.get("latency", 0))[:TOP]:
    print("   #%-6d +%.6f s  %-15s -> %-15s %-6s %-34s %s"
          % (t["frame"], t.get("latency", 0), t["client"], t["server"],
             qtype_name(t["qtype"]), t["qname"][:34], rcode_name(t["rcode"])))

# --- nxdomain
print("\n" + "-" * 100)
print("NXDOMAIN (top %d of %d)" % (min(TOP, len(nxdomain)), len(nxdomain)))
for name, n in nxdomain.most_common(TOP):
    print("   %-60s %d" % (name, n))

# --- traffic
print("\n" + "-" * 100)
print("TOP CLIENTS (top %d of %d)" % (min(TOP, len(clients)), len(clients)))
for ip, n in clients.most_common(TOP):
    nx = sum(1 for t in tx if t["client"] == ip and t["rcode"] == 3)
    uniq = len({q["qname"] for q in questions if q["client"] == ip})
    print("   %-40s %5d queries | %5d unique names | NXDOMAIN %d" % (ip, n, uniq, nx))

print("\nTOP QUERIED NAMES (top %d)" % min(TOP, len(names)))
for name, n in names.most_common(TOP):
    print("   %-60s %d" % (name, n))

# --- indicators
print("\n" + "-" * 100)
print("SUSPICIOUS INDICATORS (heuristics - verify manually)")
print("   over-long names (>52 chars or label >40): %d" % len(long_names))
for q in long_names[:8]:
    print("      #%-6d %-15s %s" % (q["frame"], q["client"], q["qname"][:70]))
print("   high-entropy labels (DGA / tunnelling): %d" % len(high_entropy))
for q, ent, ln in sorted(high_entropy, key=lambda x: -x[1])[:8]:
    print("      #%-6d %-15s entropy %.2f len %-3d %s" % (q["frame"], q["client"], ent, ln, q["qname"][:60]))
print("   large TXT answers (>200 B): %d" % len(big_txt))
for t, rdlen in big_txt[:8]:
    print("      #%-6d %-15s %-40s %d B" % (t["frame"], t["client"], t["qname"][:40], rdlen))
print("   base domains with many unique subdomains: %d" % len(tunnelling_bases))
for b, n in sorted(tunnelling_bases, key=lambda x: -x[1])[:8]:
    print("      %-50s %d unique names" % (b, n))
print("   ANY-type queries: %d" % len(any_queries))
for q in any_queries[:5]:
    print("      #%-6d %-15s %s" % (q["frame"], q["client"], q["qname"]))

# --- csv export
if CSV_PATH:
    with open(CSV_PATH, "w", encoding="utf-8") as fh:
        fh.write("tx,query_frame,time_s,client,server,qname,qtype,rcode,latency_s,answers,proto\n")
        for i, t in enumerate(sorted(tx, key=lambda t: t["ts"]), 1):
            ans = ";".join("%s=%s" % (qtype_name(a["type"]), a["value"])
                           for a in t["response"]["answers"])
            fh.write("%d,%d,%.6f,%s,%s,%s,%s,%s,%.6f,%s,%s\n"
                     % (i, t["frame"], t["ts"] - T0, t["client"], t["server"],
                        t["qname"], qtype_name(t["qtype"]),
                        rcode_name(t["rcode"]), t.get("latency", 0), ans.replace(",", "|"),
                        t["proto"]))
        for q in unanswered:
            fh.write(",%d,%.6f,%s,%s,%s,%s,,,%s,%s\n"
                     % (q["frame"], q["ts"] - T0, q["client"], q["server"], q["qname"],
                        qtype_name(q["qtype"]), "UNANSWERED", q["proto"]))
    print("\nCSV written: %s" % CSV_PATH)
