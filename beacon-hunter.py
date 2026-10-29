import sys
import argparse
import ipaddress
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
    """
    Find the gap that separates intra-check-in packets (request/response over
    a few seconds) from inter-check-in sleeps (tens of seconds). We look for
    the largest *ratio* jump in the sorted inter-packet gaps and sit between
    the two sides of it. Falls back to 1.0 if no clear bimodal split exists.
    """
    ts = sorted(timestamps)
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
    if len(gaps) < 4:
        return 1.0, "default (too few gaps)"

    g = sorted(gaps)
    best_ratio, best_gap = 1.0, 1.0
    for lo, hi in zip(g, g[1:]):
        if lo < 0.2:            # ignore sub-200ms noise on the low end
            continue
        ratio = hi / lo
        if ratio > best_ratio:
            best_ratio, best_gap = ratio, (lo * hi) ** 0.5

    if best_ratio < 3.0:        # no clean burst/sleep separation
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

    # modal control-packet signal
    # Mode of NON-bulk payload sizes = the recurring poll/control packet.
    # Padding inflates bodies, but the small framing packet stays constant.
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
    """Flag likely gateway / broadcast addresses (analysed, but labelled)."""
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
    """Follow answer-section CNAMEs and return final IPs with effective TTLs."""
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

    print("[*] DNS observations (context only; excluded from generic scoring):\n")
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
    """Return (host, request-target) from a plaintext HTTP request segment."""
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
    """Read a Server Name Indication from a complete TLS ClientHello record."""
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
    """Correlate a connection's start with DNS TTL and report evidence strength."""
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
                     evidence, detail,
                     connection["start_kind"]))

    if not rows:
        return

    print("[*] DNS-to-connection correlations (evidence-based):\n")
    for started, level, tuple_text, candidates, observed_sni, evidence, detail, start_kind in sorted(rows):
        print(f"  Flow: {tuple_text}")
        print(f"    Started: {started} UTC ({start_kind})")
        if candidates:
            print("    DNS candidates:")
            for name in candidates:
                print(f"      {name}")
        else:
            print("    DNS candidates: none observed")
        if observed_sni:
            print(f"    Observed SNI: {', '.join(observed_sni)}")
        print(f"    Attribution: {level}")
        print(f"    Evidence: {evidence} ({detail})")
    print("    TTL is checked at connection start; an established connection remains associated after TTL expiry.\n")


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
    args = ap.parse_args()

    print(f"[*] Reading: {args.pcap}")
    packets = rdpcap(args.pcap)
    print(f"[*] Total packets: {len(packets)}\n")
    capture_start = min((float(pkt.time) for pkt in packets), default=0.0)

    # Beacon timing uses payload-bearing packets by default. Keep zero-payload
    # TCP control packets and connection attempts in separate diagnostic series.
    application_samples_by_flow = defaultdict(list)
    control_packets_by_flow = defaultdict(list)
    syn_samples_by_flow = defaultdict(list)
    connections = []
    active_connections = {}
    flow_counter = Counter()
    dns_records = []
    dns_pending = defaultdict(list)

    for pkt in packets:
        ip = get_ip_layer(pkt)
        if ip is None:
            continue

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
        connection_tuple = (ip.src, src_port, dst, dst_port, proto)
        if proto == "TCP":
            flags = int(pkt[TCP].flags)
            starts_connection = bool(flags & 0x02) and not bool(flags & 0x10)
            tcp_payload = bytes(pkt[TCP].payload)
            current = active_connections.get(connection_tuple)
            if starts_connection and current is None:
                current = {
                    "tuple": connection_tuple,
                    "start_ts": ts,
                    "start_kind": "TCP SYN",
                    "http_requests": set(),
                    "tls_snis": set(),
                }
                connections.append(current)
                active_connections[connection_tuple] = current
            elif current is None:
                current = {
                    "tuple": connection_tuple,
                    "start_ts": ts,
                    "start_kind": "first observed packet",
                    "http_requests": set(),
                    "tls_snis": set(),
                }
                connections.append(current)
                active_connections[connection_tuple] = current

            http_request = extract_http_request(tcp_payload)
            if http_request:
                current["http_requests"].add(http_request)
            tls_sni = extract_tls_sni(tcp_payload)
            if tls_sni:
                current["tls_snis"].add(tls_sni)
            if flags & (0x01 | 0x04):  # FIN or RST closes this observed TCP tuple.
                active_connections.pop(connection_tuple, None)
        else:
            current = active_connections.get(connection_tuple)
            if current is None:
                current = {
                    "tuple": connection_tuple,
                    "start_ts": ts,
                    "start_kind": "first UDP datagram",
                    "http_requests": set(),
                    "tls_snis": set(),
                }
                connections.append(current)
                active_connections[connection_tuple] = current

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
    print_dns_connection_correlations(dns_records, connections)

    if not flow_counter:
        print("[!] No candidates. Try --include-internal or check pcap direction.")
        return

    print(f"[*] {'External' if not args.include_internal else 'All'} "
          f"connection candidates (by packet count):\n")
    print(f"    {'source -> destination (protocol/port)':<55}{'packets':>8}")
    print(f"    {'-'*55}{'-'*8}")
    for flow, c in flow_counter.most_common(args.top):
        src, dst, proto, port = flow
        label = f"{src} -> {dst} ({proto}/{port})"
        print(f"    {label:<55}{c:>8}{infra_hint(dst)}")
    print()

    analysis_mode = "TCP SYN attempts" if args.syn_only else "payload-bearing packets"
    print(f"[*] Beacon analysis ({analysis_mode}; v2 scoring):\n")
    scored = []   # (flow, result, is_infra)
    for flow, _ in flow_counter.most_common(args.top):
        src, dst, proto, port = flow
        label = f"{src} -> {dst} ({proto}/{port})"
        samples = (syn_samples_by_flow[flow] if args.syn_only
                   else application_samples_by_flow[flow])
        result = analyze_beacon(samples,
                                min_gap=args.min_gap,
                                threshold=args.threshold,
                                debug_events=args.debug_events)
        if result is None:
            if args.debug_events and control_packets_by_flow.get(flow):
                control_times = ", ".join(
                    f"{ts - capture_start:.6f}s/{flags}"
                    for ts, flags in control_packets_by_flow[flow]
                )
                print(f"  [{label}] insufficient {analysis_mode} packets; "
                      f"zero-payload TCP control packets are excluded from scoring")
                print(f"      control packets ({len(control_packets_by_flow[flow])}): "
                      f"{control_times}\n")
            continue

        is_infra = bool(infra_hint(dst))
        flag = "  <<< BEACON SUSPECT" if result.get('is_beacon_suspect') else ""
        print(f"  [{label}]{infra_hint(dst)}{flag}")
        for k, v in result.items():
            if k == 'breakdown':
                parts = ", ".join(f"{kk}={vv}" for kk, vv in v.items())
                print(f"      {'breakdown':<16}: {parts}")
            elif k == 'event_details':
                continue
            else:
                print(f"      {k:<16}: {v}")
        if args.debug_events:
            print("      event groups:")
            for index, event in enumerate(result.get('event_details', []), start=1):
                start_relative = event['start'] - capture_start
                sizes = [size for _, size in event['packets']]
                members = ", ".join(
                    f"{ts - capture_start:.6f}s/{size}B"
                    for ts, size in event['packets']
                )
                print(f"        Event {index:<3} start={start_relative:.6f}s "
                      f"packets={len(sizes)} payload_sizes={sizes} members=[{members}]")
            controls = control_packets_by_flow.get(flow, [])
            if controls:
                control_times = ", ".join(
                    f"{ts - capture_start:.6f}s/{flags}" for ts, flags in controls
                )
                print(f"      excluded zero-payload TCP control packets ({len(controls)}): "
                      f"{control_times}")
        print()

        if result.get('is_beacon_suspect'):
            scored.append((flow, result, is_infra))

    # shadow resolution
    # An infra (gateway/broadcast) hit that shares a non-infra beacon's exact
    # cadence is that beacon's routed reflection, not an independent C2.
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

    print("=" * 56)
    if beacons:
        print(f"[+] {len(beacons)} beacon candidate(s) found:")
        for flow, r in beacons:
            src, dst, proto, port = flow
            label = f"{src} -> {dst} ({proto}/{port})"
            print(f"    {label}  ->  ~{r['mean_interval']}s, jitter {r['jitter_pct']}%, "
                  f"modal {r['modal_pkt_size']}B x{r['modal_recurrence']}, "
                  f"{r['events']} check-ins, score {r['score_pct']}%")
    else:
        print("[-] No beacon suspects.")
        print("    Try: --threshold 0.45 (looser)")

    if shadows:
        print()
        print("[i] Routing shadows (same cadence as a beacon above, not independent):")
        for flow, owner in shadows:
            src, dst, proto, port = flow
            label = f"{src} -> {dst} ({proto}/{port})"
            osrc, odst, oproto, oport = owner
            owner_label = f"{osrc} -> {odst} ({oproto}/{oport})"
            print(f"    {label}  -> reflection of {owner_label}")


if __name__ == "__main__":
    main()
