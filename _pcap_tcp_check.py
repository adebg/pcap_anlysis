"""Dependency-free pcap TCP-handshake auditor.

Usage: python _pcap_tcp_check.py <file.pcap>

Supports Ethernet (DLT 1, incl. VLAN) and Linux SLL (DLT 113), IPv4/IPv6.
Builds a per-flow handshake state machine and reports every TCP connection
that was NOT established, plus a full flow table and summary statistics.

Verdicts:
  unanswered SYN        SYN sent, no SYN-ACK and no RST in the capture
  refused (RST)         SYN answered with RST (connection refused)
  incomplete handshake  SYN + SYN-ACK but client never ACKed the SYN-ACK
  handshake reset       SYN-ACK seen then RST before the handshake completed
  established           full 3-way handshake completed
  established-before    data flow whose SYN predates the capture
  orphan SYN-ACK        SYN-ACK with no matching SYN in the capture
  bare RST              RST with no SYN/SYN-ACK in the capture
  teardown-only         only FIN/ACK segments captured; handshake and data
                        happened before the capture started
  undetermined          nothing that identifies the flow's state

Also detects TCP retransmissions per flow (see find_retransmissions):
  - data/SYN retransmissions: same sequence number re-sent in the same
    direction (relative sequence numbers, 32-bit wrap-safe)
  - retransmitted bytes, duplicate ACKs (fast-retransmit triggers),
    SYN / SYN-ACK retransmissions, and out-of-order segments
  - keepalive probes (0/1-byte re-send of the last octet, seq = next - 1)
    are recognized and NOT counted as retransmissions or duplicate ACKs

Each TCP flow carries a 0-based stream id assigned in order of first
appearance, matching Wireshark's tcp.stream numbering. Frame numbers are
1-based capture packet indices, matching Wireshark's frame.number.

Time display modes (like Wireshark's Time Display Format):
  default : relative seconds since first packet, e.g. +0.048814
  --local : absolute local time   |   --utc : absolute UTC
"""
import hashlib
import struct
import socket
import sys
from datetime import datetime, timezone

# Time display modes (matching Wireshark's Time Display Format options):
#   default : relative seconds since first packet (Wireshark's default column)
#   --local : absolute local time   (Wireshark "local time" display)
#   --utc   : absolute UTC          (Wireshark "UTC" display)
_FLAGS = [a for a in sys.argv[1:] if a.startswith("--")]
UTC_MODE = "--utc" in _FLAGS
LOCAL_MODE = "--local" in _FLAGS
RELATIVE_MODE = not (UTC_MODE or LOCAL_MODE)
_ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
PATH = _ARGS[0] if _ARGS else "FPX-VM16-Test2-port2_root.pcap"

# Multi-interface captures (common with pcapng: one machine, several NICs)
# record the same frame once per interface, which shows up as bogus
# retransmissions and duplicate ACKs. --dedup collapses byte-identical
# frames seen within DUP_WINDOW seconds down to a single copy.
DEDUP = "--dedup" in _FLAGS
DUP_WINDOW = 0.002


def _int_opt(name, default=None):
    for f in _FLAGS:
        if f.startswith(name + "="):
            try:
                return int(f.split("=", 1)[1])
            except ValueError:
                return default
    return default


# --stream=N: dump every packet of that TCP stream (Wireshark's tcp.stream)
STREAM_FILTER = _int_opt("--stream")
DATA = open(PATH, "rb").read()


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


SYN, FIN, RST, ACK = 0x02, 0x01, 0x04, 0x10
SERVICE = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "bootps", 68: "bootpc", 69: "tftp", 80: "http", 110: "pop3", 123: "ntp",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 554: "rtsp", 587: "submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "ms-sql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5000: "upnp", 5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt2", 9200: "elastic",
    27017: "mongodb",
}

flows = {}
dns_names = {}
packets = tcp_packets = udp_packets = icmp_packets = arp_packets = 0
other_ip = 0
t_first = t_last = None
truncated = 0
vlan_count = 0


T0 = 0.0    # first packet time; set once the capture loop finishes


def ts2str(ts):
    if RELATIVE_MODE:
        # seconds since first packet (Wireshark's default time column)
        return "+%.6f" % (ts - T0)
    dt = datetime.fromtimestamp(ts, timezone.utc)
    if not UTC_MODE:
        dt = dt.astimezone()
    return dt.strftime("%H:%M:%S.%f")


def tz_label():
    if RELATIVE_MODE:
        return "relative to first packet"
    if UTC_MODE:
        return "UTC"
    return str(datetime.now().astimezone().tzinfo)


def new_dir():
    return {"base": None, "next": None, "retx": 0, "retx_bytes": 0, "oo": 0,
            "dup_acks": 0, "last_ack": None, "events": [], "seen": [],
            "keepalive": 0}


def track_seq(d, frame, ts, di, seq, payload, is_syn, is_fin):
    """Track sequence coverage for one direction of a flow.

    Works in absolute 64-bit sequence space anchored at the first observed
    sequence number, so 32-bit wrap-around is handled naturally. A segment
    whose [start, end) range overlaps space already covered counts as a
    retransmission; a segment that starts beyond current coverage counts as
    out-of-order. Covered ranges are kept as merged intervals, so a late
    gap-filler is NOT mislabeled as a retransmission. SYN and FIN each
    consume one sequence number, so retransmitted FINs are caught too.
    """
    adv = payload + (1 if is_syn else 0) + (1 if is_fin else 0)
    if d["base"] is None:
        d["base"] = seq
        d["next"] = seq + adv
        d["seen"] = [[seq, seq + adv]]
        return
    rel = (seq - d["base"]) & 0xFFFFFFFF
    start = d["base"] + rel
    end = start + adv
    overlap = 0
    for (s, e) in d["seen"]:
        overlap += max(0, min(end, e) - max(start, s))
    if overlap > 0:
        d["retx"] += 1
        d["retx_bytes"] += overlap
        if len(d["events"]) < 40:
            d["events"].append((frame, ts, di, seq, payload))
    if end > d["next"]:
        if start > d["next"]:
            d["oo"] += 1                       # gap ahead: out-of-order
        d["next"] = end
        d["seen"].append([start, end])
        d["seen"].sort()
        merged = []
        for (s, e) in d["seen"]:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        d["seen"] = merged


def new_flow():
    return {"client": None, "server": None, "client_syn": 0, "client_syn_ts": None,
            "client_syn_seq": None, "server_synack": 0, "server_synack_ts": None,
            "server_synack_seq": None, "final_ack": False, "server_rst": 0,
            "client_rst": 0, "client_fin": 0, "server_fin": 0, "data_c2s": 0,
            "data_s2c": 0, "pkts": 0, "first": None, "last": None,
            "first_frame": 0, "last_frame": 0,
            "stream": 0, "synack_ends": set(), "pinned_fallback": False,
            "acklist": {"c2s": [], "s2c": []},
            "dir": {"c2s": new_dir(), "s2c": new_dir()}}


def parse_tcp(p, ts, src, dst, frame):
    global tcp_packets
    tcp_packets += 1
    if len(p) < 20:
        return
    sport, dport, seq, acknum, off_flags = struct.unpack_from(">HHIIH", p, 0)
    doff = (off_flags >> 12) * 4
    if doff > len(p):
        return
    flags = off_flags & 0x01FF
    payload = len(p) - doff
    key = tuple(sorted([(src, sport), (dst, dport)]))
    f = flows.get(key)
    if f is None:
        f = flows[key] = new_flow()
        f["stream"] = len(flows) - 1   # 0-based, order of first appearance
                                        # (matches Wireshark's tcp.stream)
    f["pkts"] += 1
    if f["first"] is None:
        f["first"] = ts
        f["first_frame"] = frame
    f["last"] = max(f["last"] or ts, ts)
    f["last_frame"] = frame
    is_syn, is_ack = flags & SYN, flags & ACK
    is_rst, is_fin = flags & RST, flags & FIN

    if STREAM_FILTER is not None and f["stream"] == STREAM_FILTER:
        # per-packet log for the --stream dump (payload preview only)
        f.setdefault("pktlog", []).append({
            "frame": frame, "ts": ts, "src": src, "sport": sport,
            "dst": dst, "dport": dport, "seq": seq, "ack": acknum,
            "flags": flags, "len": payload, "win": struct.unpack_from(">H", p, 14)[0],
            "data": p[doff:doff + payload] if payload else b"",
        })

    # pin the client/server roles as early as possible (first SYN, or a
    # SYN-ACK whose SYN we missed, or the sorted tuple as a provisional
    # fallback that is re-pinned on the first SYN-ish packet)
    if f["client"] is None:
        if is_syn and not is_ack:
            f["client"] = (src, sport)
            f["server"] = (dst, dport)
        elif is_syn and is_ack:
            f["client"] = (dst, dport)
            f["server"] = (src, sport)
        else:
            f["client"] = key[0]
            f["server"] = key[1]
            f["pinned_fallback"] = True
    elif f["pinned_fallback"] and is_syn:
        if is_ack:
            f["client"] = (dst, dport)
            f["server"] = (src, sport)
        else:
            f["client"] = (src, sport)
            f["server"] = (dst, dport)
        f["pinned_fallback"] = False
    di = "c2s" if (src, sport) == f["client"] else "s2c"
    if is_ack:
        # remember recent ack numbers per direction (bounded) so a SYN-ACK
        # captured after its own final ACK can still complete the handshake
        acks = f["acklist"][di]
        if len(acks) >= 16:
            acks.pop(0)
        acks.append(acknum)

    # ---- retransmission / sequence tracking (per direction) ----
    # SYN and FIN each consume one sequence number; pure ACKs do not advance.
    d = f["dir"][di]
    is_keepalive = False
    if d["next"] is not None and is_ack and not is_syn and not is_rst \
            and not is_fin and payload <= 1:
        start = d["base"] + ((seq - d["base"]) & 0xFFFFFFFF)
        # keepalive probe (RFC 1122 4.2.3.6), Wireshark's tcp.analysis.keep_alive
        # pattern: ACK, payload of 0 or 1 byte, sequence number one below the
        # next expected one. A normal pure ACK sits exactly at next.
        if start == d["next"] - 1:
            is_keepalive = True
    if is_keepalive:
        d["keepalive"] += 1
    elif payload or is_syn or is_fin:
        track_seq(d, frame, ts, di, seq, payload, is_syn, is_fin)
    elif is_ack and not is_rst and not is_fin:
        # duplicate ACK (same ack number, no payload) - fast-retransmit trigger
        if d["last_ack"] == acknum:
            d["dup_acks"] += 1
        d["last_ack"] = acknum

    if is_syn and not is_ack:
        if f["client_syn_ts"] is None:
            f["client_syn_ts"] = ts
            f["client_syn_seq"] = seq
        f["client_syn"] += 1
        return
    if is_syn and is_ack:
        if f["server_synack_ts"] is None:
            f["server_synack_ts"] = ts
            f["server_synack_seq"] = seq
        # the final ACK must acknowledge everything the SYN-ACK carried
        # (seq + 1 + payload, so TCP Fast Open SYN-ACK data is handled)
        end = (seq + 1 + payload) & 0xFFFFFFFF
        f["synack_ends"].add(end)
        f["server_synack"] += 1
        # the client's final ACK may have been captured before this SYN-ACK
        # (retransmission, or capture started between SYN-ACK and ACK)
        if end in f["acklist"]["c2s"] or end in f["acklist"]["s2c"]:
            f["final_ack"] = True
        return
    if f["client"] is not None and (src, sport) == f["client"] and is_ack \
            and acknum in f["synack_ends"]:
        f["final_ack"] = True
    if is_rst:
        if f["client"] is not None and (src, sport) == f["client"]:
            f["client_rst"] += 1
        elif f["client"] is not None and (src, sport) == f["server"]:
            f["server_rst"] += 1
        return
    if is_fin:
        if f["client"] is not None and (src, sport) == f["client"]:
            f["client_fin"] += 1
        elif f["client"] is not None and (src, sport) == f["server"]:
            f["server_fin"] += 1
    if payload:
        if f["client"] is not None and (src, sport) == f["client"]:
            f["data_c2s"] += payload
        elif f["client"] is not None and (src, sport) == f["server"]:
            f["data_s2c"] += payload


def parse_dns(p, ts):
    if len(p) < 12:
        return
    qd, an, ns, ar = struct.unpack_from(">HHHH", p, 4)
    if not (qd and an):
        return
    off, labels = 12, []
    while off < len(p):
        ln = p[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            off += 2
            break
        off += 1
        labels.append(p[off:off + ln].decode("latin-1"))
        off += ln
    qname = ".".join(labels).lower()
    off += 4
    for _ in range(an):
        if off + 12 > len(p):
            break
        if p[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while off < len(p):
                ln = p[off]
                if ln == 0:
                    off += 1
                    break
                if ln & 0xC0 == 0xC0:
                    off += 2
                    break
                off += 1 + ln
        rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH", p, off)
        off += 10
        rdata = p[off:off + rdlen]
        off += rdlen
        if rclass == 1 and rtype == 1 and rdlen == 4:
            dns_names.setdefault(socket.inet_ntoa(rdata), qname)


def parse_udp(p, ts):
    global udp_packets
    udp_packets += 1
    if len(p) < 8:
        return
    sport, dport, ulen, csum = struct.unpack_from(">HHHH", p, 0)
    if dport == 53 or sport == 53:
        parse_dns(p[8:], ts)


def parse_ipv4(p, ts, frame):
    if len(p) < 20 or (p[0] >> 4) != 4:
        return
    ihl = (p[0] & 0x0F) * 4
    total = struct.unpack_from(">H", p, 2)[0]
    src, dst = p[12:16], p[16:20]
    end = total if total and total <= len(p) else len(p)
    if end < ihl:
        return
    proto = p[9]
    if proto == 6:
        parse_tcp(p[ihl:end], ts, socket.inet_ntoa(src), socket.inet_ntoa(dst), frame)
    elif proto == 17:
        parse_udp(p[ihl:end], ts)


def parse_ipv6(p, ts, frame):
    global other_ip
    if len(p) < 40 or (p[0] >> 4) != 6:
        return
    nxt = p[6]
    src, dst = p[8:24], p[24:40]
    off = 40
    for _ in range(8):
        if nxt == 6:
            parse_tcp(p[off:], ts, socket.inet_ntop(socket.AF_INET6, src),
                      socket.inet_ntop(socket.AF_INET6, dst), frame)
            return
        if nxt == 17:
            parse_udp(p[off:], ts)
            return
        if nxt in (0, 43, 60):
            if off + 2 > len(p):
                return
            nxt, off = p[off], off + (p[off + 1] + 1) * 8
        elif nxt == 44:
            if off + 8 > len(p):
                return
            nxt, off = p[off], off + 8
        else:
            other_ip += 1
            return


# ------------------------------------------------------------------- main loop
linktypes = set()
dup_frames = 0
sig_seen = {}
for (ts, linktype, pkt, trunc_flag) in iter_packets(DATA):
    packets += 1
    frame = packets              # Wireshark's frame.number (1-based)
    linktypes.add(linktype)
    t_first = ts if t_first is None else min(t_first, ts)
    t_last = ts
    if trunc_flag:
        truncated += 1
    is_vlan = False
    if linktype == 1:                               # Ethernet II
        if len(pkt) < 14:
            continue
        etype = struct.unpack_from(">H", pkt, 12)[0]
        pl = pkt[14:]
        if etype == 0x8100 or etype == 0x88A8:      # VLAN
            is_vlan = True
            if len(pl) < 4:
                continue
            etype = struct.unpack_from(">H", pl, 2)[0]
            pl = pl[4:]
    elif linktype == 113:                           # Linux cooked capture (SLL)
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
    if is_vlan:
        vlan_count += 1
    if etype == 0x0800:
        parse_ipv4(pl, ts, frame)
    elif etype == 0x86DD:
        parse_ipv6(pl, ts, frame)
    elif etype == 0x0806:
        arp_packets += 1
    else:
        other_ip += 1

T0 = t_first if t_first is not None else 0.0   # anchor for relative times

# ------------------------------------------------------------------ classify
def ep(ip, port):
    label = dns_names.get(ip) or SERVICE.get(port)
    return "%s:%d%s" % (ip, port, (" (%s)" % label) if label else "")


def classify(f):
    syn = f["client_syn"] > 0
    sa = f["server_synack"] > 0
    if syn and not sa and not f["server_rst"] and not f["client_rst"]:
        return "unanswered SYN"
    if syn and not sa and (f["server_rst"] or f["client_rst"]):
        return "refused (RST)"
    if syn and sa and not f["final_ack"]:
        if f["client_rst"] or f["server_rst"]:
            return "handshake reset"
        if f["data_c2s"] > 0:
            # client sent payload after the SYN-ACK: its final ACK was
            # implicit in that segment, so the handshake completed
            return "established"
        return "incomplete handshake"
    if sa and f["final_ack"]:
        # SYN-ACK + final ACK = completed handshake, even when the client's
        # SYN fell outside the capture window
        return "established"
    if not syn and sa:
        return "orphan SYN-ACK"
    if f["data_c2s"] or f["data_s2c"]:
        return "established-before-capture"
    if f["client_rst"] or f["server_rst"]:
        return "bare RST"
    if f["client_fin"] or f["server_fin"]:
        # only FIN/ACK segments captured: the handshake and any data
        # happened before the capture started
        return "teardown-only"
    return "undetermined"


def find_retransmissions(flow_table, min_retx=1):
    """Return the TCP connections that contain retransmissions.

    A retransmission is a segment re-sent with a sequence number that the
    same side has already sent and covered (data and SYN retransmissions,
    32-bit wrap-safe). Also reported per flow: retransmitted bytes,
    duplicate ACKs (the receiver asking for a fast retransmit), out-of-order
    segments, and SYN / SYN-ACK retransmissions.

    Returns a list of dicts sorted by retransmission count, most first.
    """
    out = []
    for key, f in flow_table.items():
        d = f["dir"]
        retx = d["c2s"]["retx"] + d["s2c"]["retx"]
        rbytes = d["c2s"]["retx_bytes"] + d["s2c"]["retx_bytes"]
        dup_acks = d["c2s"]["dup_acks"] + d["s2c"]["dup_acks"]
        oo = d["c2s"]["oo"] + d["s2c"]["oo"]
        syn_rt = max(0, f["client_syn"] - 1) + max(0, f["server_synack"] - 1)
        if retx + syn_rt < min_retx:
            continue
        events = []
        for di in ("c2s", "s2c"):
            for (frame, ts, direction, seq, length) in d[di]["events"]:
                events.append((frame, ts, direction, seq, length))
        events.sort()
        out.append({
            "stream": f["stream"],
            "client": ep(f["client"][0], f["client"][1]) if f["client"] else ep(key[0][0], key[0][1]),
            "server": ep(f["server"][0], f["server"][1]) if f["server"] else ep(key[1][0], key[1][1]),
            "retx": retx, "retx_bytes": rbytes, "dup_acks": dup_acks, "oo": oo,
            "syn_rt": syn_rt, "c2s": d["c2s"]["retx"], "s2c": d["s2c"]["retx"],
            "keepalive": d["c2s"]["keepalive"] + d["s2c"]["keepalive"],
            "events": events, "pkts": f["pkts"], "t0": f["first"], "t_last": f["last"],
            "f0": f["first_frame"], "f1": f["last_frame"],
            "verdict": classify(f),
        })
    out.sort(key=lambda r: (-r["retx"], -r["retx_bytes"]))
    return out

counts = {}
bad = []
good = []
for key, f in flows.items():
    v = classify(f)
    counts[v] = counts.get(v, 0) + 1
    row = {
        "stream": f["stream"],
        "client": ep(f["client"][0], f["client"][1]) if f["client"] else ep(key[0][0], key[0][1]),
        "server": ep(f["server"][0], f["server"][1]) if f["server"] else ep(key[1][0], key[1][1]),
        "syn": f["client_syn"], "synack": f["server_synack"],
        "t0": f["first"], "t_syn": f["client_syn_ts"], "t_sa": f["server_synack_ts"],
        "t_last": f["last"], "pkts": f["pkts"], "c2s": f["data_c2s"], "s2c": f["data_s2c"],
        "sr": f["server_rst"], "cr": f["client_rst"], "cf": f["client_fin"],
        "sf": f["server_fin"], "v": v,
        "f0": f["first_frame"], "f1": f["last_frame"],
        "retx": f["dir"]["c2s"]["retx"] + f["dir"]["s2c"]["retx"],
    }
    (bad if v not in ("established", "established-before-capture") else good).append(row)

print("=" * 104)
print("PCAP: %s  |  %d pkts (tcp %d, udp %d, icmp %d, arp %d, vlan %d, trunc %d)%s"
      % (PATH, packets, tcp_packets, udp_packets, icmp_packets, arp_packets, vlan_count, truncated,
         "  [protocol counts after --dedup]" if (DEDUP and dup_frames) else ""))
print("capture span: %s .. %s (%s)  |  duration %.6f s  |  TCP flows: %d"
      % (ts2str(t_first), ts2str(t_last), tz_label(), t_last - t_first, len(flows)))
if dup_frames:
    print("NOTE: %d of %d frames are duplicate captures of the same packet "
          "(multi-interface capture) - %s"
          % (dup_frames, packets,
             "collapsed by --dedup" if DEDUP else "rerun with --dedup to collapse them"))
print("=" * 104)
print("\nVerdict counts:")
for k in sorted(counts, key=lambda k: -counts[k]):
    print("   %-28s %d" % (k, counts[k]))

print("\n" + "=" * 104)
print("TCP CONNECTIONS NOT ESTABLISHED (%d)" % len(bad))
print("=" * 104)
for r in sorted(bad, key=lambda r: r["t0"]):
    print("\n  stream %-4d %-30s -> %-34s %s" % (r["stream"], r["client"], r["server"], r["v"]))
    print("     first %s (#%d) | last %s (#%d) | SYNs %d | SYN-ACKs %d | RST c/s %d/%d | pkts %d | bytes c2s %d s2c %d"
          % (ts2str(r["t0"]), r["f0"], ts2str(r["t_last"]), r["f1"], r["syn"], r["synack"], r["cr"], r["sr"],
             r["pkts"], r["c2s"], r["s2c"]))
    if r["v"] == "unanswered SYN":
        print("     no reply for %.3f s before end of capture" % (t_last - r["t0"]))
    if r["syn"] > 1:
        print("     client retransmitted SYN %d times" % (r["syn"] - 1))
    if r["synack"] > 1:
        print("     server retransmitted SYN-ACK %d times (final ACK never seen)" % (r["synack"] - 1))
    if r["t_syn"] and r["t_sa"]:
        print("     SYN -> SYN-ACK latency %.3f s" % (r["t_sa"] - r["t_syn"]))

scan = {}
for r in bad:
    if r["v"] in ("unanswered SYN", "refused (RST)", "incomplete handshake", "handshake reset"):
        cip = r["client"].split(":")[0]
        scan.setdefault(cip, set()).add(r["server"].split(":")[0])
print("\n" + "-" * 104)
print("failed attempts by source host (possible scan / flood signal):")
for cip in sorted(scan, key=lambda c: -len(scan[c])):
    dsts = sorted(scan[cip], key=lambda x: (x.count(":") > 1, x))
    print("   %-40s %3d failed attempts to: %s" % (cip, len(dsts), ", ".join(dsts[:20])))

# ----------------------------------------------------------- retransmissions
retx_flows = find_retransmissions(flows)
print("\n" + "=" * 104)
print("TCP RETRANSMISSIONS (%d connections)" % len(retx_flows))
print("=" * 104)
if not retx_flows:
    print("  none - no flow re-sent any sequence number in this capture")
else:
    tot_segs = sum(r["retx"] for r in retx_flows)
    tot_bytes = sum(r["retx_bytes"] for r in retx_flows)
    tot_dups = sum(r["dup_acks"] for r in retx_flows)
    tot_ka = sum(f["dir"]["c2s"]["keepalive"] + f["dir"]["s2c"]["keepalive"]
                 for f in flows.values())
    print("  totals: %d retransmitted segments, %d retransmitted bytes, %d duplicate ACKs"
          % (tot_segs, tot_bytes, tot_dups))
    if tot_ka:
        print("  keepalive probes: %d (excluded from retransmission counts)" % tot_ka)
    for r in retx_flows:
        print("\n  stream %-4d %-30s -> %-34s [%s]" % (r["stream"], r["client"], r["server"], r["verdict"]))
        print("     retx segs %d (%d c2s / %d s2c) | retx bytes %d | dup ACKs %d | "
              "out-of-order %d | keepalive %d | pkts %d | frames #%d..#%d | first %s | last %s"
              % (r["retx"], r["c2s"], r["s2c"], r["retx_bytes"], r["dup_acks"], r["oo"],
                 r["keepalive"], r["pkts"], r["f0"], r["f1"], ts2str(r["t0"]), ts2str(r["t_last"])))
        if r["syn_rt"]:
            print("     handshake retransmissions: %d (SYN or SYN-ACK re-sent)" % r["syn_rt"])
        for (frame, ts, di, seq, length) in r["events"][:10]:
            print("       #%-5d %s  %s re-sent seq=%u len=%d" % (frame, ts2str(ts), di, seq, length))
        if len(r["events"]) > 10:
            print("       ... and %d more" % (len(r["events"]) - 10))

print("\nestablished flows: %d" % len(good))
print("(full flow table follows)" if len(flows) <= 200 else "(full table omitted: >200 flows)")
if len(flows) <= 200:
    print("-" * 104)
    print("%-4s %-10s %-30s %-34s %-26s %4s %4s %5s %8s %8s %s" %
          ("stm", "frames", "client", "server", "verdict", "pkts", "RST", "retx", "c2sB", "s2cB", "t0"))
    for r in sorted(bad + good, key=lambda r: r["t0"]):
        print("%-4d %-10s %-30s %-34s %-26s %4d %4d %5d %8d %8d %s" %
              (r["stream"], "%d..%d" % (r["f0"], r["f1"]), r["client"], r["server"], r["v"],
               r["pkts"], r["cr"] + r["sr"],
               r.get("retx", 0), r["c2s"], r["s2c"], ts2str(r["t0"])))

# ------------------------------------------------------------ per-stream dump
FLAG_NAMES = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
              (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"))


def flag_str(flags):
    return ",".join(n for bit, n in FLAG_NAMES if flags & bit) or "-"


def payload_preview(data, limit=200):
    if not data:
        return ""
    try:
        text = data.decode("ascii")
        if all(32 <= ord(ch) < 127 or ch in "\r\n\t" for ch in text):
            shown = text.replace("\r\n", "\\r\\n").replace("\n", "\\n").replace("\t", "\\t")
            return shown[:limit] + ("..." if len(shown) > limit else "")
    except UnicodeDecodeError:
        pass
    return data[:64].hex(" ") + ("..." if len(data) > 64 else "")


if STREAM_FILTER is not None:
    print("\n" + "=" * 104)
    print("TCP STREAM %d (Wireshark: tcp.stream eq %d)" % (STREAM_FILTER, STREAM_FILTER))
    print("=" * 104)
    target = next((fl for fl in flows.values() if fl["stream"] == STREAM_FILTER), None)
    if target is None:
        print("  no such stream in this capture (streams 0..%d)" % (len(flows) - 1))
    else:
        c = target["client"]
        s = target["server"]
        log = target.get("pktlog", [])
        c2s_pkts = [r for r in log if (r["src"], r["sport"]) == c]
        s2c_pkts = [r for r in log if (r["src"], r["sport"]) == s]
        print("  endpoints : %s  <->  %s" % (ep(*c), ep(*s)))
        print("  verdict   : %s" % classify(target))
        print("  frames    : #%d .. #%d   |  first %s  |  last %s  |  duration %.6f s"
              % (target["first_frame"], target["last_frame"], ts2str(target["first"]),
                 ts2str(target["last"]), target["last"] - target["first"]))
        print("  packets   : %d  (client->server %d pkts / %d B, server->client %d pkts / %d B)"
              % (len(log), len(c2s_pkts), sum(r["len"] for r in c2s_pkts),
                 len(s2c_pkts), sum(r["len"] for r in s2c_pkts)))
        print("  handshake : SYN %d, SYN-ACK %d, final ACK %s, RST %d/%d, FIN %d/%d"
              % (target["client_syn"], target["server_synack"],
                 "yes" if target["final_ack"] else "no",
                 target["client_rst"], target["server_rst"],
                 target["client_fin"], target["server_fin"]))
        d = target["dir"]
        print("  analysis  : retx %d (%d B), dup ACKs %d, out-of-order %d, keepalives %d"
              % (d["c2s"]["retx"] + d["s2c"]["retx"],
                 d["c2s"]["retx_bytes"] + d["s2c"]["retx_bytes"],
                 d["c2s"]["dup_acks"] + d["s2c"]["dup_acks"],
                 d["c2s"]["oo"] + d["s2c"]["oo"],
                 d["c2s"]["keepalive"] + d["s2c"]["keepalive"]))
        if not target["client_syn"] and not target["server_synack"]:
            print("  note      : no handshake in the capture; these segments belong to a")
            print("              connection whose SYN (and any early data) predates frame #%d"
                  % target["first_frame"])
        if not log:
            print("  no packets recorded for this stream")
        print("-" * 104)
        print("%-7s %-12s %-5s %-38s %-12s %-11s %-11s %5s %6s" %
              ("frame", "time", "dir", "endpoints", "flags", "seq", "ack", "len", "win"))
        for r in log:
            c2s = (r["src"], r["sport"]) == c
            if c2s:
                arrow, endpoints = "c->s", "%-16s -> %s" % (
                    "%s:%d" % (r["src"], r["sport"]), "%s:%d" % (r["dst"], r["dport"]))
            else:
                arrow, endpoints = "s->c", "%-16s -> %s" % (
                    "%s:%d" % (r["src"], r["sport"]), "%s:%d" % (r["dst"], r["dport"]))
            print("#%-6d %-12s %-5s %-38s %-12s %-11u %-11u %5d %6d"
                  % (r["frame"], ts2str(r["ts"]), arrow, endpoints, flag_str(r["flags"]),
                     r["seq"], r["ack"], r["len"], r["win"]))
            if r["len"]:
                print("        %s" % payload_preview(r["data"]))

