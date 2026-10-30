import sys
import argparse
import csv
import ipaddress
import os
import statistics
from datetime import datetime, timezone
from collections import defaultdict, Counter
from urllib.parse import urlsplit

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS
except ImportError:
    sys.exit("scapy not found: pip install scapy")


W_TIMING = 35  
W_SIZE   = 30   
W_SMALL  = 15   
W_EVENTS = 20   
BULK_MSS = 1400    
MIN_CTRL = 16       


USE_COLOR = False
ANSI = {
    "bold": "1",
    "dim": "2",
    "cyan": "36",
    "yellow": "33",
    "red": "31",
}


def paint(value, *styles):
    text = str(value)
    if not USE_COLOR or not styles:
        return text
    codes = ";".join(ANSI[style] for style in styles if style in ANSI)
    if not codes:
        return text
    return f"\033[{codes}m{text}\033[0m"


def print_table(headers, rows, right_align=(), row_styles=None):
    if not rows:
        return
    rows = [[str(value) for value in row] for row in rows]
    widths = [
        max(len(str(headers[index])), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]

    def render(row):
        cells = []
        for index, value in enumerate(row):
            cells.append(value.rjust(widths[index]) if index in right_align
                         else value.ljust(widths[index]))
        return "    " + " | ".join(cells)

    print(paint(render(headers), "bold"))
    print(paint("    " + "-+-".join("-" * width for width in widths), "dim"))
    for index, row in enumerate(rows):
        style = row_styles[index] if row_styles and index < len(row_styles) else None
        print(paint(render(row), style) if style else render(row))


# Per-signal scoring
def score_timing(cv):
    if cv is None:
        return 0
    for thr, pts in [(0.05, 35), (0.12, 30), (0.20, 22),
                     (0.30, 14), (0.45, 7), (0.65, 3)]:
        if cv < thr:
            return pts
    return 0


def score_size_recurrence(rec):
    if rec is None:
        return 0
    for thr, pts in [(0.90, 30), (0.75, 24), (0.60, 16), (0.40, 8), (0.25, 3)]:
        if rec >= thr:
            return pts
    return 0


def score_smallness(modal):
    if modal is None or modal <= 0:
        return 0
    if modal < 256:
        return 15
    if modal < 1024:
        return 10
    if modal < 4096:
        return 5
    return 0


def score_events(n):
    for thr, pts in [(50, 20), (25, 16), (15, 12), (10, 8), (6, 4), (4, 1)]:
        if n >= thr:
            return pts
    return 0


# Auto burst-merge threshold 
def auto_min_gap(timestamps):
    ts = sorted(timestamps)
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
    if len(gaps) < 4:
        return 1.0, "default (too few gaps)"

    g = sorted(gaps)
    best_ratio, best_gap = 1.0, 1.0
    for lo, hi in zip(g, g[1:]):
        if lo < 0.2:          
            continue
        ratio = hi / lo
        if ratio > best_ratio:
            best_ratio, best_gap = ratio, (lo * hi) ** 0.5

    if best_ratio < 3.0:    
        return 1.0, "default (no clear burst/sleep split)"
    return round(best_gap, 1), f"auto (knee ratio {best_ratio:.1f}x)"


# Core analysis:  samples = list of (timestamp, payload_len)
def analyze_beacon(samples, min_gap=None, threshold=0.55, debug_events=False):
    if len(samples) < 4:
        return None

    samples = sorted(samples, key=lambda s: s[0])

    if min_gap is None:
        min_gap, gap_src = auto_min_gap([s[0] for s in samples])
    else:
        gap_src = "manual"

    # group packets into check-in events
    groups = [[samples[0]]]
    anchor = samples[0][0]
    for ts, sz in samples[1:]:
        if ts - anchor >= min_gap:
            groups.append([(ts, sz)])
            anchor = ts
        else:
            groups[-1].append((ts, sz))

    n_events = len(groups)
    event_details = [
        {"start": group[0][0], "packets": group}
        for group in groups
    ]
    if n_events < 4:
        result = {
            'raw_packets': len(samples),
            'events': n_events,
            'min_gap': f"{min_gap} ({gap_src})",
            'note': 'not enough separate events',
            'is_beacon_suspect': False,
        }
        if debug_events:
            result['event_details'] = event_details
        return result

    # timing signal
    event_starts = [g[0][0] for g in groups]
    intervals = [event_starts[i + 1] - event_starts[i] for i in range(n_events - 1)]
    mean = statistics.mean(intervals)
    stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
    cv = stdev / mean if mean > 0 else 0.0

    non_bulk = [sz for _, sz in samples if MIN_CTRL <= sz < BULK_MSS]
    has_size = len(non_bulk) >= 3
    if has_size:
        modal_size = Counter(non_bulk).most_common(1)[0][0]
        tol = max(8, modal_size * 0.06)
        ev_with_modal = sum(
            1 for grp in groups
            if any(0 < sz and abs(sz - modal_size) <= tol for _, sz in grp)
        )
        recurrence = ev_with_modal / n_events
    else:
        modal_size, recurrence = None, None

    # additive scoring
    s_timing = score_timing(cv)
    s_events = score_events(n_events)
    score = s_timing + s_events
    max_possible = W_TIMING + W_EVENTS
    breakdown = {'timing': s_timing, 'events': s_events}

    if has_size:
        s_size = score_size_recurrence(recurrence)
        s_small = score_smallness(modal_size)
        score += s_size + s_small
        max_possible += W_SIZE + W_SMALL
        breakdown['size_recurrence'] = s_size
        breakdown['size_smallness'] = s_small

    ratio = score / max_possible if max_possible else 0.0

    result = {
        'raw_packets': len(samples),
        'events': n_events,
        'min_gap': f"{min_gap} ({gap_src})",
        'mean_interval': round(mean, 4),
        'stdev_interval': round(stdev, 4),
        'timing_cv': round(cv, 6),
        'jitter_pct': round(cv * 100, 4),
        'modal_pkt_size': modal_size if has_size else 'n/a',
        'modal_recurrence': round(recurrence, 2) if has_size else 'n/a',
        'breakdown': breakdown,
        'score': f"{score}/{max_possible}",
        'score_pct': round(ratio * 100, 1),
        'is_beacon_suspect': ratio >= threshold,
    }
    if debug_events:
        result['event_details'] = event_details
    return result


# Helpers
def is_external(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or
                ip.is_multicast or ip.is_link_local or ip.is_reserved)


def infra_hint(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return ""
    if ip.version == 4:
        last = int(str(ip).split('.')[-1])
        if last in (1, 254):
            return " [infra? likely gateway]"
        if last == 255:
            return " [infra? broadcast]"
    return ""


def get_ip_layer(pkt):
    if pkt.haslayer(IP):
        return pkt[IP]
    if pkt.haslayer(IPv6):
        return pkt[IPv6]
    return None


def payload_len(pkt):
    if pkt.haslayer(TCP):
        return len(pkt[TCP].payload)
    if pkt.haslayer(UDP):
        return len(pkt[UDP].payload)
    return 0


class SessionTracker:
    def __init__(self):
        self.sessions = {}
        self.packet_lookup = {}
        self.next_session_id = 0

    def update(self, pkt, ip):
        if pkt.haslayer(TCP):
            proto = "TCP"
            sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            flags = 0
        else:
            return None

        src = (str(ip.src), sport)
        dst = (str(ip.dst), dport)
        packet_key, reverse_key = (src, dst, proto), (dst, src, proto)
        session = self.packet_lookup.get(packet_key) or self.packet_lookup.get(reverse_key)
        syn = proto == "TCP" and bool(flags & 0x02) and not bool(flags & 0x10)
        syn_ack = proto == "TCP" and bool(flags & 0x02) and bool(flags & 0x10)
        if session and syn and session["tcp_state"] in ("CLOSED", "RESET"):
            session = None

        if session is None:
            if syn:
                client, server, basis = src, dst, "observed SYN"
            elif syn_ack:
                client, server, basis = dst, src, "observed SYN-ACK"
            elif is_external(dst[0]) and not is_external(src[0]):
                client, server, basis = src, dst, "address heuristic"
            elif is_external(src[0]) and not is_external(dst[0]):
                client, server, basis = dst, src, "address heuristic"
            else:
                client, server, basis = src, dst, "first observed packet; uncertain"

            key = (client[0], client[1], server[0], server[1], proto)
            state = "SYN_SENT" if syn else "SYN_ACK_SEEN" if syn_ack else "MIDSTREAM" if proto == "TCP" else "UDP"
            self.next_session_id += 1
            session_id = f"S{self.next_session_id:06d}"
            session = {
                "session_id": session_id,
                "key": key, "start_time": float(pkt.time), "end_time": float(pkt.time),
                "start_kind": "TCP SYN" if syn else "first observed packet" if proto == "TCP" else "first UDP datagram",
                "direction_basis": basis, "tcp_state": state,
                "outbound_bytes": 0, "inbound_bytes": 0,
                "outbound_packets": 0, "inbound_packets": 0, "fin_sides": set(),
            }
            self.sessions[session_id] = session
            self.packet_lookup[packet_key] = session
            self.packet_lookup[reverse_key] = session

        client = (session["key"][0], session["key"][1])
        direction = "outbound" if src == client else "inbound"
        session[f"{direction}_packets"] += 1
        session[f"{direction}_bytes"] += payload_len(pkt)
        session["end_time"] = float(pkt.time)

        if proto == "TCP":
            if flags & 0x04:
                session["tcp_state"] = "RESET"
            elif flags & 0x01:
                session["fin_sides"].add(direction)
                session["tcp_state"] = "CLOSED" if len(session["fin_sides"]) == 2 else "CLOSING"
            elif syn_ack:
                session["tcp_state"] = "SYN_ACK_SEEN"
            elif flags & 0x10 and session["tcp_state"] in ("SYN_SENT", "SYN_ACK_SEEN"):
                session["tcp_state"] = "ESTABLISHED"
        return session


def print_session_report(sessions, limit):
    if not sessions:
        return
    print(paint("[*] Bidirectional session observations:\n", "bold", "cyan"))
    ordered = sorted(sessions.values(), key=lambda session: session["start_time"])
    shown = ordered[:limit]
    rows = []
    styles = []
    for session in shown:
        src, sport, dst, dport, proto = session["key"]
        label = f"{src}:{sport} -> {dst}:{dport} ({proto})"
        rows.append([
            label, session["tcp_state"], session["outbound_packets"],
            session["inbound_packets"], session["outbound_bytes"],
            session["inbound_bytes"],
        ])
        styles.append({
            "RESET": "red", "CLOSING": "yellow", "SYN_SENT": "yellow",
            "SYN_ACK_SEEN": "yellow", "CLOSED": "cyan",
            "ESTABLISHED": "cyan", "MIDSTREAM": "dim",
        }.get(session["tcp_state"]))

    print_table(
        ["Client -> server", "State", "Out pkts", "In pkts", "Out bytes", "In bytes"],
        rows, right_align=(2, 3, 4, 5), row_styles=styles,
    )
    for session in shown:
        if session["direction_basis"] == "first observed packet; uncertain":
            src, sport, dst, dport, proto = session["key"]
            print(paint(
                f"      Direction uncertain for {src}:{sport} -> {dst}:{dport}/{proto}",
                "dim",
            ))
    if len(ordered) > limit:
        print(paint(f"    ... {len(ordered) - limit} more sessions (raise --top to show more)", "dim"))
    print()


DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV",
}

DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}


def dns_text(value):
    if isinstance(value, bytes):
        return value.decode("ascii", errors="replace").rstrip(".")
    return str(value).rstrip(".")


def valid_dns_qname(name):
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    return all(0 < len(label) <= 63 and
               all(ch.isalnum() or ch in "-_" for ch in label)
               for label in labels)


def dns_answer_records(dns):
    answers = []
    answer_count = int(dns.ancount or 0)
    answer_section = dns.an
    if isinstance(answer_section, (list, tuple)):
        records = answer_section[:answer_count]
    else:
        records = []
        rr = answer_section
        for _ in range(answer_count):
            if not hasattr(rr, "rrname"):
                break
            records.append(rr)
            rr = rr.payload

    for rr in records:
        rdata = getattr(rr, "rdata", "")
        answers.append({
            "name": dns_text(rr.rrname),
            "type": DNS_QTYPES.get(int(rr.type), str(rr.type)),
            "value": dns_text(rdata) if isinstance(rdata, (bytes, str)) else str(rdata),
            "ttl": int(rr.ttl),
        })
    return answers


def dns_resolved_addresses(record):
    by_owner = defaultdict(list)
    for answer in record["answers"]:
        owner = answer["name"].lower().rstrip(".")
        by_owner[owner].append(answer)

    resolved = set()

    def follow(owner, ttl_chain, visited):
        if owner in visited:
            return
        visited = visited | {owner}
        for answer in by_owner.get(owner, []):
            rr_type = answer["type"]
            if rr_type in ("A", "AAAA"):
                try:
                    answer_ip = str(ipaddress.ip_address(answer["value"]))
                except ValueError:
                    continue
                effective_ttl = min(ttl_chain + [answer["ttl"]])
                resolved.add((answer_ip, effective_ttl))
            elif rr_type == "CNAME":
                target = answer["value"].lower().rstrip(".")
                follow(target, ttl_chain + [answer["ttl"]], visited)

    start_name = record["qname"].lower().rstrip(".")
    follow(start_name, [], set())
    return sorted(resolved)


def print_dns_report(records, limit):
    if not records:
        return

    summaries = defaultdict(lambda: {
        "queries": 0,
        "names": Counter(),
        "types": Counter(),
        "rcodes": Counter(),
        "answers": defaultdict(list),
        "name_rcodes": defaultdict(Counter),
        "latencies": [],
        "unanswered": 0,
    })
    for record in records:
        key = (record["client"], record["resolver"])
        summary = summaries[key]
        summary["queries"] += 1
        summary["names"][record["qname"]] += 1
        summary["types"][record["qtype"]] += 1
        if record["rcode"] is None:
            summary["unanswered"] += 1
        else:
            summary["rcodes"][record["rcode"]] += 1
            summary["name_rcodes"][record["qname"]][record["rcode"]] += 1
        if record["latency_ms"] is not None:
            summary["latencies"].append(record["latency_ms"])
        for answer in record["answers"]:
            item = (answer["type"], answer["value"], answer["ttl"])
            if item not in summary["answers"][record["qname"]]:
                summary["answers"][record["qname"]].append(item)

    print(paint("[*] DNS observations (context only; excluded from generic scoring):\n", "bold", "cyan"))
    for (client, resolver), summary in summaries.items():
        types = ", ".join(f"{name}={count}" for name, count in summary["types"].most_common())
        rcodes = ", ".join(f"{name}={count}" for name, count in summary["rcodes"].most_common()) or "none"
        avg_latency = (statistics.mean(summary["latencies"])
                       if summary["latencies"] else None)
        latency_text = f"; mean RTT {avg_latency:.2f} ms" if avg_latency is not None else ""
        print(f"  {client} -> {resolver}: {summary['queries']} queries, "
              f"{len(summary['names'])} unique names; types {types}; "
              f"responses {rcodes}; unanswered {summary['unanswered']}{latency_text}")
        print(f"      {'qname':<42}{'type':<8}{'count':>7}  {'rcode':<10}answers (TTL)")
        print(f"      {'-'*42}{'-'*8}{'-'*7}  {'-'*10}{'-'*28}")
        names = summary["names"].most_common(limit)
        for qname, count in names:
            sample = next(r for r in records
                          if r["client"] == client and r["resolver"] == resolver
                          and r["qname"] == qname)
            answers = summary["answers"].get(qname, [])
            answer_text = ", ".join(
                f"{rr_type} {value} ({ttl}s)"
                for rr_type, value, ttl in answers[:3]
            ) if answers else "-"
            name_rcodes = summary["name_rcodes"].get(qname, Counter())
            rcode_text = name_rcodes.most_common(1)[0][0] if name_rcodes else "no reply"
            print(f"      {qname:<42}{sample['qtype']:<8}{count:>7}  {rcode_text:<10}{answer_text}")
        if len(summary["names"]) > limit:
            print(f"      ... {len(summary['names']) - limit} more names (raise --top to show more)")
    print()


def extract_http_request(payload):
    lines = payload.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
    request_parts = lines[0].split(b" ", 2) if lines else []
    if len(request_parts) != 3 or not request_parts[2].startswith(b"HTTP/"):
        return None
    host = None
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"host":
            host_value = value.decode("ascii", errors="replace").strip()
            host = urlsplit("//" + host_value).hostname
            if host:
                host = host.lower().rstrip(".")
            break
    if not host:
        return None
    target = request_parts[1].decode("ascii", errors="replace")
    return host, target


def extract_tls_sni(payload):
    if len(payload) < 9 or payload[0] != 22 or payload[5] != 1:
        return None
    record_end = 5 + int.from_bytes(payload[3:5], "big")
    hello_len = int.from_bytes(payload[6:9], "big")
    if len(payload) < record_end or hello_len + 4 > record_end - 5:
        return None
    hello_end = 9 + hello_len
    body = payload[9:hello_end]
    try:
        pos = 34  # legacy_version and random
        session_len = body[pos]
        pos += 1 + session_len
        cipher_len = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2 + cipher_len
        compression_len = body[pos]
        pos += 1 + compression_len
        extensions_len = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        extensions_end = pos + extensions_len
        if extensions_end > len(body):
            return None
        while pos + 4 <= extensions_end:
            ext_type = int.from_bytes(body[pos:pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
            if pos + 4 + ext_len > extensions_end:
                return None
            ext = body[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len
            if ext_type != 0 or len(ext) < 5:
                continue
            names_end = 2 + int.from_bytes(ext[:2], "big")
            if names_end > len(ext):
                continue
            name_pos = 2
            while name_pos + 3 <= names_end:
                name_type = ext[name_pos]
                name_len = int.from_bytes(ext[name_pos + 1:name_pos + 3], "big")
                name_pos += 3
                name = ext[name_pos:name_pos + name_len]
                name_pos += name_len
                if name_type == 0 and name:
                    return name.decode("ascii", errors="replace").strip().lower().rstrip(".")
    except (IndexError, ValueError):
        return None
    return None


def print_dns_connection_correlations(records, connections):
    answers_by_client_ip = defaultdict(list)
    for record in records:
        response_ts = record.get("response_ts")
        if response_ts is None or record.get("rcode") != "NOERROR":
            continue
        for answer_ip, effective_ttl in dns_resolved_addresses(record):
            answers_by_client_ip[(record["client"], answer_ip)].append({
                "qname": record["qname"].lower().rstrip("."),
                "start": response_ts,
                "expires": response_ts + effective_ttl,
                "ttl": effective_ttl,
            })

    rows = []
    for connection in connections:
        src, sport, dst, dport, proto = connection["tuple"]
        observed_sni = sorted(connection["tls_snis"])
        candidates = {
            item["qname"]: item
            for item in answers_by_client_ip.get((src, dst), [])
            if item["start"] <= connection["start_ts"] <= item["expires"]
        }
        if not candidates and not observed_sni:
            continue

        http_matches = [
            (host, target) for host, target in connection["http_requests"]
            if host in candidates
        ]
        direct_http = sorted({host for host, _ in http_matches})
        direct_sni = sorted(candidates.keys() & set(observed_sni))
        if direct_http:
            targets = sorted({target for host, target in http_matches if host in direct_http})
            level = "CONFIRMED"
            evidence = "HTTP_REQUEST_TARGET"
            detail = f"Host={', '.join(direct_http)}; target={', '.join(targets[:3])}"
        elif direct_sni:
            level = "HIGH"
            evidence, detail = "TLS_SNI_DNS_MATCH", "ClientHello SNI matches a DNS candidate resolved to this IP"
        elif observed_sni and candidates:
            level = "CONFLICT"
            evidence = "TLS_SNI_DNS_CONFLICT"
            detail = "SNI does not match any observed DNS candidate"
        elif observed_sni:
            level = "HIGH"
            evidence, detail = "TLS_SNI_ONLY", "ClientHello SNI observed; no matching DNS answer was captured"
        elif len(candidates) > 1:
            level = "AMBIGUOUS"
            evidence, detail = "DNS_IP_TIME_MATCH", "multiple DNS names match this client, IP, and connection-start window"
        elif connection["start_kind"] == "TCP SYN":
            level = "MEDIUM"
            evidence, detail = "DNS_IP_TIME_UNIQUE", "one DNS name matches the observed TCP SYN"
        else:
            level = "LOW"
            evidence, detail = "DNS_IP_TIME_FIRST_OBSERVED", "DNS name matches, but the connection start was not captured"

        started = datetime.fromtimestamp(connection["start_ts"], timezone.utc).isoformat(timespec="milliseconds")
        tuple_text = f"{src}:{sport} -> {dst}:{dport}/{proto}"
        rows.append((started, level, tuple_text, sorted(candidates), observed_sni,
                     evidence, detail, connection["start_kind"],
                     connection["session_id"]))

    if not rows:
        return []

    print(paint("[*] DNS-to-connection correlations (evidence-based):\n", "bold", "cyan"))
    report_rows = []
    row_styles = []
    for started, level, tuple_text, candidates, observed_sni, evidence, detail, start_kind, session_id in sorted(rows):
        started_text = started.replace("T", " ").replace("+00:00", "")
        context_parts = []
        if candidates:
            context_parts.append("DNS: " + ", ".join(candidates))
        if observed_sni:
            context_parts.append("SNI: " + ", ".join(observed_sni))
        if detail:
            context_parts.append(detail)
        context = " | ".join(context_parts) or "-"
        if len(context) > 64:
            context = context[:61] + "..."

        start_label = "SYN" if start_kind == "TCP SYN" else "first seen"
        report_rows.append([started_text, tuple_text, start_label, level, evidence, context])
        row_styles.append({
            "CONFIRMED": "cyan", "HIGH": "cyan", "MEDIUM": "yellow",
            "AMBIGUOUS": "yellow", "CONFLICT": "red", "LOW": "dim",
        }.get(level))

    print_table(
        ["Started (UTC)", "Flow", "Start", "Attribution", "Evidence", "DNS / SNI / detail"],
        report_rows,
        row_styles=row_styles,
    )
    print(paint(
        "    TTL is checked at connection start; established sessions remain associated after expiry.\n",
        "dim",
    ))
    return rows



def parse_beacon_flow_label(label):
    src_ip, remainder = label.split(" -> ", 1)
    dst_part, transport_part = remainder.rsplit(" (", 1)
    protocol, port = transport_part.rstrip(")").rsplit("/", 1)
    return src_ip, dst_part, protocol, int(port)


def write_csv_reports(base_path, dns_records, correlation_rows, flow_rows,
                      analysis_rows, sessions, debug_rows, shadows,
                      capture_start, show_sessions=False):
    base, _ = os.path.splitext(base_path)
    written_paths = []

    def write_section(path, fields, rows, write_empty=False):
        if not rows and not write_empty:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        written_paths.append(path)

    packet_counts = {flow: packets for flow, packets, _ in flow_rows}

    beacon_fields = [
        "status", "src_ip", "dst_ip", "protocol", "dst_port",
        "packet_count", "payload_samples", "events", "mean_interval_seconds",
        "timing_cv_percent", "modal_payload_bytes", "modal_recurrence",
        "score_out_of_100",
    ]
    beacon_rows = []
    for row in analysis_rows:
        flow, samples, events, interval, jitter, modal, recurrence, score, status = row
        src_ip, dst_ip, protocol, dst_port = parse_beacon_flow_label(flow)
        score_value = score.split(" ", 1)[0] if score not in ("", "-") else ""
        score_value = score_value.split("/", 1)[0] if score_value else ""
        beacon_rows.append({
            "status": status,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "dst_port": dst_port,
            "packet_count": packet_counts.get(flow, ""),
            "payload_samples": samples,
            "events": "" if events == "-" else events,
            "mean_interval_seconds": interval[:-1] if interval.endswith("s") else "",
            "timing_cv_percent": jitter[:-1] if jitter.endswith("%") else "",
            "modal_payload_bytes": modal[:-1] if modal.endswith("B") else "",
            "modal_recurrence": "" if recurrence == "-" else recurrence,
            "score_out_of_100": score_value,
        })
    write_section(base_path, beacon_fields, beacon_rows, write_empty=True)

    dns_fields = [
        "dns_query_id", "query_time_utc", "client_ip", "resolver_ip", "qname", "qtype",
        "rcode", "answer_type", "answer_value", "ttl_seconds", "latency_ms", "note",
    ]
    dns_rows = []
    for record in dns_records:
        answers = record.get("answers") or [None]
        for answer in answers:
            dns_rows.append({
                "dns_query_id": record["query_id"],
                "query_time_utc": datetime.fromtimestamp(record["ts"], timezone.utc).isoformat(),
                "client_ip": record["client"],
                "resolver_ip": record["resolver"],
                "qname": record["qname"],
                "qtype": record["qtype"],
                "rcode": record.get("rcode") or "",
                "answer_type": answer["type"] if answer else "",
                "answer_value": answer["value"] if answer else "",
                "ttl_seconds": answer["ttl"] if answer else "",
                "latency_ms": record.get("latency_ms") if record.get("latency_ms") is not None else "",
                "note": "unanswered" if record.get("rcode") is None else "",
            })
    write_section(f"{base}_dns.csv", dns_fields, dns_rows)

    connection_fields = [
        "session_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "started_utc", "start_observed", "attribution", "evidence",
        "dns_candidates", "observed_sni", "details",
    ]
    connection_rows = []
    for started, level, flow, candidates, observed_sni, evidence, detail, start_kind, session_id in correlation_rows:
        src_endpoint, dst_endpoint = flow.split(" -> ", 1)
        src_ip, src_port = src_endpoint.rsplit(":", 1)
        dst_transport, protocol = dst_endpoint.rsplit("/", 1)
        dst_ip, dst_port = dst_transport.rsplit(":", 1)
        connection_rows.append({
            "session_id": session_id,
            "src_ip": src_ip, "src_port": src_port,
            "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol,
            "started_utc": started,
            "start_observed": start_kind,
            "attribution": level,
            "evidence": evidence,
            "dns_candidates": "; ".join(candidates),
            "observed_sni": "; ".join(observed_sni),
            "details": detail,
        })
    write_section(f"{base}_attribution.csv", connection_fields, connection_rows)

    if show_sessions:
        session_fields = [
            "client_ip", "client_port", "server_ip", "server_port", "protocol",
            "start_time_utc", "end_time_utc", "tcp_state", "direction_basis",
            "outbound_packets", "inbound_packets", "outbound_payload_bytes",
            "inbound_payload_bytes",
        ]
        session_rows = []
        for session in sessions.values():
            src, sport, dst, dport, proto = session["key"]
            session_rows.append({
                "client_ip": src, "client_port": sport,
                "server_ip": dst, "server_port": dport, "protocol": proto,
                "start_time_utc": datetime.fromtimestamp(session["start_time"], timezone.utc).isoformat(),
                "end_time_utc": datetime.fromtimestamp(session["end_time"], timezone.utc).isoformat(),
                "tcp_state": session["tcp_state"],
                "direction_basis": session["direction_basis"],
                "outbound_packets": session["outbound_packets"],
                "inbound_packets": session["inbound_packets"],
                "outbound_payload_bytes": session["outbound_bytes"],
                "inbound_payload_bytes": session["inbound_bytes"],
            })
        write_section(f"{base}_sessions.csv", session_fields, session_rows)

    if debug_rows:
        debug_fields = ["flow", "record_type", "event_index", "time_seconds", "payload_bytes", "tcp_flags"]
        debug_export_rows = []
        for label, result, controls in debug_rows:
            if result:
                for event_index, event in enumerate(result.get("event_details", []), start=1):
                    for ts, size in event["packets"]:
                        debug_export_rows.append({
                            "flow": label, "record_type": "event_packet",
                            "event_index": event_index,
                            "time_seconds": f"{ts - capture_start:.6f}",
                            "payload_bytes": size,
                        })
            for ts, flags in controls:
                debug_export_rows.append({
                    "flow": label, "record_type": "control_packet",
                    "time_seconds": f"{ts - capture_start:.6f}",
                    "tcp_flags": flags,
                })
        write_section(f"{base}_debug.csv", debug_fields, debug_export_rows)

    if shadows:
        shadow_rows = []
        for flow, owner in shadows:
            src, dst, proto, port = flow
            osrc, odst, oproto, oport = owner
            shadow_rows.append({
                "shadow_flow": f"{src} -> {dst} ({proto}/{port})",
                "matching_beacon": f"{osrc} -> {odst} ({oproto}/{oport})",
            })
        write_section(
            f"{base}_shadows.csv", ["shadow_flow", "matching_beacon"], shadow_rows,
        )

    print("[*] CSV reports written:")
    for path in written_paths:
        print(f"    {path}")




# Main
def main():
    ap = argparse.ArgumentParser(description="PCAP beacon hunter v2 (modal + auto-gap)")
    ap.add_argument("pcap", help="path to pcap / pcapng file")
    ap.add_argument("--syn-only", action="store_true",
                    help="only count TCP SYN packets (no UDP or established TCP traffic)")
    ap.add_argument("--min-gap", type=float, default=None,
                    help="burst-merge threshold in seconds (default: auto knee detection)")
    ap.add_argument("--threshold", type=float, default=0.55,
                    help="suspect if score ratio >= this (default 0.55)")
    ap.add_argument("--top", type=int, default=15,
                    help="how many candidates to show (default 15)")
    ap.add_argument("--include-internal", action="store_true",
                    help="also include internal IPs (needed for lab / RFC1918 C2)")
    ap.add_argument("--debug-events", action="store_true",
                    help="show which packet timestamps and payload sizes form each event")
    ap.add_argument("--show-sessions", action="store_true",
                    help="show bidirectional TCP/UDP session packet and payload-byte counts")
    ap.add_argument("--no-color", action="store_true",
                    help="disable ANSI colors in terminal output")
    ap.add_argument("--csv", metavar="FILE",
                    help="save a beacon summary, DNS answers, and evidence-backed attribution CSV using FILE as the base path")
    args = ap.parse_args()
    if args.csv and os.path.normcase(os.path.abspath(args.csv)) == os.path.normcase(os.path.abspath(args.pcap)):
        ap.error("--csv output path must differ from the input PCAP path")

    global USE_COLOR
    USE_COLOR = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ

    print(f"[*] Reading: {args.pcap}")
    packets = rdpcap(args.pcap)
    print(f"[*] Total packets: {len(packets)}\n")
    capture_start = min((float(pkt.time) for pkt in packets), default=0.0)

    application_samples_by_flow = defaultdict(list)
    control_packets_by_flow = defaultdict(list)
    syn_samples_by_flow = defaultdict(list)
    connections = []
    connections_by_session = {}
    flow_counter = Counter()
    dns_records = []
    dns_pending = defaultdict(list)
    session_tracker = SessionTracker()

    for pkt in packets:
        ip = get_ip_layer(pkt)
        if ip is None:
            continue

        # Track both directions before DNS and destination filtering.
        session = session_tracker.update(pkt, ip)

        is_dns_transport = pkt.haslayer(DNS) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))
        if is_dns_transport:
            dns = pkt[DNS]
            if pkt.haslayer(TCP):
                dns_proto = "TCP"
                sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            else:
                dns_proto = "UDP"
                sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            dns_id = int(dns.id)

            if int(dns.qr) == 0 and dns.qd is not None:
                qname = dns_text(dns.qd.qname)
                if valid_dns_qname(qname):
                    qtype_num = int(dns.qd.qtype)
                    record = {
                        "query_id": f"Q{len(dns_records) + 1:06d}",
                        "client": ip.src,
                        "resolver": ip.dst,
                        "qname": qname,
                        "qtype": DNS_QTYPES.get(qtype_num, str(qtype_num)),
                        "ts": float(pkt.time),
                        "rcode": None,
                        "answers": [],
                        "latency_ms": None,
                        "response_ts": None,
                    }
                    dns_records.append(record)
                    query_key = (dns_proto, ip.src, ip.dst, sport, dport, dns_id)
                    dns_pending[query_key].append(record)
            elif int(dns.qr) == 1:
                response_key = (dns_proto, ip.dst, ip.src, dport, sport, dns_id)
                waiting = dns_pending.get(response_key)
                if waiting:
                    record = waiting.pop(0)
                    rcode_num = int(dns.rcode)
                    record["rcode"] = DNS_RCODES.get(rcode_num, str(rcode_num))
                    record["answers"] = dns_answer_records(dns)
                    record["latency_ms"] = round((float(pkt.time) - record["ts"]) * 1000, 2)
                    record["response_ts"] = float(pkt.time)

            # DNS has its own context report above. Do not feed recognized DNS
            # packets into the generic timing and payload-size beacon score.
            continue

        dst = ip.dst

        if not args.include_internal and not is_external(dst):
            continue

        if pkt.haslayer(TCP):
            proto = "TCP"
            dst_port = int(pkt[TCP].dport)
            src_port = int(pkt[TCP].sport)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            dst_port = int(pkt[UDP].dport)
            src_port = int(pkt[UDP].sport)
        else:
            continue

        ts = float(pkt.time)
        if session is None:
            continue

        current = connections_by_session.get(session["session_id"])
        if current is None:
            session_tuple = session["key"]
            current = {
                "tuple": session_tuple,
                "session_id": session["session_id"],
                "start_ts": session["start_time"],
                "start_kind": session["start_kind"],
                "http_requests": set(),
                "tls_snis": set(),
            }
            connections.append(current)
            connections_by_session[session["session_id"]] = current

        if proto == "TCP":
            tcp_payload = bytes(pkt[TCP].payload)
            http_request = extract_http_request(tcp_payload)
            if http_request:
                current["http_requests"].add(http_request)
            tls_sni = extract_tls_sni(tcp_payload)
            if tls_sni:
                current["tls_snis"].add(tls_sni)

        flow = (ip.src, dst, proto, dst_port)
        payload_size = payload_len(pkt)
        is_syn = (proto == "TCP" and bool(pkt[TCP].flags & 0x02)
                  and not bool(pkt[TCP].flags & 0x10))

        if is_syn:
            syn_samples_by_flow[flow].append((ts, payload_size))
        if proto == "TCP" and payload_size == 0 and not is_syn:
            control_packets_by_flow[flow].append((ts, str(pkt[TCP].flags)))

        if args.syn_only:
            if not is_syn:
                continue
            flow_counter[flow] += 1
            continue

        flow_counter[flow] += 1
        if payload_size > 0:
            application_samples_by_flow[flow].append((ts, payload_size))

    print_dns_report(dns_records, args.top)
    correlation_rows = print_dns_connection_correlations(dns_records, connections)
    if args.show_sessions:
        print_session_report(session_tracker.sessions, args.top)

    if not flow_counter:
        print("[!] No candidates. Try --include-internal or check pcap direction.")
        if args.csv:
            write_csv_reports(
                args.csv, dns_records, correlation_rows, [], [], session_tracker.sessions,
                [], [], capture_start, show_sessions=args.show_sessions,
            )
        return

    candidate_rows = []
    for flow, count in flow_counter.most_common():
        src, dst, proto, port = flow
        candidate_rows.append([
            f"{src} -> {dst} ({proto}/{port})",
            count,
            infra_hint(dst).strip(),
        ])
    flow_rows = candidate_rows[:args.top]
    print(paint(f"[*] {'External' if not args.include_internal else 'All'} "
                  f"connection candidates (by packet count; top {args.top} shown):\n", "bold", "cyan"))
    print_table(["Flow", "Packets", "Note"], flow_rows, right_align=(1,))
    print()

    analysis_mode = "TCP SYN attempts" if args.syn_only else "payload-bearing packets"
    print(paint(
        f"[*] Beacon analysis ({analysis_mode}; v2 scoring; all flows scored, top {args.top} shown):\n",
        "bold", "cyan",
    ))
    scored = []
    analysis_rows = []
    analysis_score_pct = {}
    debug_rows = []

    for flow, _ in flow_counter.most_common():
        src, dst, proto, port = flow
        label = f"{src} -> {dst} ({proto}/{port})"
        samples = (syn_samples_by_flow[flow] if args.syn_only
                   else application_samples_by_flow[flow])
        result = analyze_beacon(
            samples,
            min_gap=args.min_gap,
            threshold=args.threshold,
            debug_events=args.debug_events,
        )

        if result is None:
            analysis_rows.append([
                label, len(samples), "-", "-", "-", "-", "-", "-", "INSUFFICIENT",
            ])
            analysis_score_pct[label] = -1
            if args.debug_events:
                debug_rows.append((label, None, control_packets_by_flow.get(flow, [])))
            continue

        suspect = result.get("is_beacon_suspect", False)
        interval = f"{result['mean_interval']}s" if "mean_interval" in result else "-"
        jitter = f"{result['jitter_pct']}%" if "jitter_pct" in result else "-"
        modal = f"{result['modal_pkt_size']}B" if result.get("modal_pkt_size") not in (None, "n/a") else "-"
        recurrence_value = result.get("modal_recurrence")
        recurrence = str(recurrence_value) if recurrence_value not in (None, "n/a") else "-"
        score = result.get("score", "-")
        if "score_pct" in result:
            score += f" ({result['score_pct']}%)"
        if result.get("note"):
            status = "INSUFFICIENT"
        else:
            status = "SUSPECT" if suspect else "BELOW"
        analysis_score_pct[label] = result.get("score_pct", -1)

        analysis_rows.append([
            label, result.get("raw_packets", len(samples)), result.get("events", "-"),
            interval, jitter, modal, recurrence, score, status,
        ])
        if args.debug_events:
            debug_rows.append((label, result, control_packets_by_flow.get(flow, [])))
        if suspect:
            scored.append((flow, result, bool(infra_hint(dst))))

    status_order = {"SUSPECT": 0, "BELOW": 1, "INSUFFICIENT": 2}
    analysis_rows.sort(key=lambda row: (
        status_order.get(row[-1], 3),
        -analysis_score_pct.get(row[0], -1),
        -int(row[1]) if str(row[1]).isdigit() else 0,
    ))
    visible_rows = analysis_rows[:args.top]
    display_rows = []
    for row in visible_rows:
        label, samples, events, interval, cv, modal, recurrence, score, status = row
        _, dst, _, port = parse_beacon_flow_label(label)
        if interval.endswith("s"):
            interval = f"{float(interval[:-1]):.3f}s"
        cv = cv[:-1] if cv.endswith("%") else cv
        score_value = score.split("/", 1)[0] if score not in ("", "-") else "-"
        display_rows.append([status, f"{dst}:{port}", events, interval, cv, score_value])

    row_styles = [
        "yellow" if row[0] == "SUSPECT" else
        "dim" if row[0] == "INSUFFICIENT" else None
        for row in display_rows
    ]
    print_table(
        ["Status", "Destination", "Events", "Interval", "CV %", "Score /100"],
        display_rows,
        right_align=(2, 4, 5),
        row_styles=row_styles,
    )

    if args.debug_events:
        for label, result, controls in debug_rows:
            print(paint(f"  {label}", "bold"))
            if result:
                event_rows = []
                for event_index, event in enumerate(result.get("event_details", []), start=1):
                    for ts, size in event["packets"]:
                        event_rows.append([
                            event_index, f"{ts - capture_start:.6f}", size,
                        ])
                if event_rows:
                    print_table(["Event", "Packet time (s)", "Payload (B)"], event_rows,
                                right_align=(0, 1, 2))
            if controls:
                control_rows = [
                    (f"{ts - capture_start:.6f}", flags)
                    for ts, flags in controls
                ]
                print(paint("    Excluded zero-payload TCP control packets:", "dim"))
                print_table(["Packet time (s)", "TCP flags"], control_rows, right_align=(0,))

    def same_cadence(a, b):
        if not a.get('mean_interval') or not b.get('mean_interval'):
            return False
        rel = abs(a['mean_interval'] - b['mean_interval']) / b['mean_interval']
        return rel < 0.10 and abs(a['events'] - b['events']) <= 2

    primary = [(flow, r) for flow, r, inf in scored if not inf]
    beacons, shadows = [], []
    for flow, r, inf in scored:
        owner = next((pflow for pflow, pr in primary if same_cadence(r, pr)), None)
        if inf and owner:
            shadows.append((flow, owner))
        else:
            beacons.append((flow, r))

    print(paint("=" * 56, "dim"))
    if beacons:
        print(paint(
            f"[+] {len(beacons)} beacon candidate(s) found; see the analysis table above.",
            "bold", "yellow",
        ))
    else:
        print(paint("[-] No beacon suspects.", "dim"))
        print(paint("    Try: --threshold 0.45 (looser)", "dim"))

    if shadows:
        print()
        print(paint("[i] Routing shadows:", "cyan"))
        shadow_rows = []
        for flow, owner in shadows:
            src, dst, proto, port = flow
            osrc, odst, oproto, oport = owner
            shadow_rows.append([
                f"{src} -> {dst} ({proto}/{port})",
                f"{osrc} -> {odst} ({oproto}/{oport})",
            ])
        print_table(["Shadow flow", "Matching beacon"], shadow_rows)

    if args.csv:
        write_csv_reports(
            args.csv, dns_records, correlation_rows, candidate_rows,
            analysis_rows, session_tracker.sessions, debug_rows, shadows,
            capture_start, show_sessions=args.show_sessions,
        )




if __name__ == "__main__":
    main()
