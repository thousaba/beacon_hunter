import sys
import argparse
import ipaddress
import statistics
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP
except ImportError:
    sys.exit("scapy not found: pip install scapy")


# Scoring weights  (max per signal)
W_TIMING = 35   # interval regularity            (behavioural, jitter-limited)
W_SIZE   = 30   # modal control-packet recurrence (structural, beats padding)
W_SMALL  = 15   # how small that modal poll is
W_EVENTS = 20   # persistence: many check-ins



BULK_MSS = 1400     # payloads >= this are treated as bulk data segments, not
                    # control packets (they are just TCP/MSS fragmentation).
MIN_CTRL = 16       # payloads < this are TCP keepalives / tiny ACK framing,
                    # never a real C2 poll. Excluding them stops gateways and
                    # other infra from faking a modal recurrence on 6-byte ACKs.


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
def analyze_beacon(samples, min_gap=None, threshold=0.55):
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
    if n_events < 4:
        return {
            'raw_packets': len(samples),
            'events': n_events,
            'min_gap': f"{min_gap} ({gap_src})",
            'note': 'not enough separate events',
            'is_beacon_suspect': False,
        }

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

    return {
        'raw_packets': len(samples),
        'events': n_events,
        'min_gap': f"{min_gap} ({gap_src})",
        'mean_interval': round(mean, 2),
        'stdev_interval': round(stdev, 2),
        'timing_cv': round(cv, 3),
        'jitter_pct': round(cv * 100, 1),
        'modal_pkt_size': modal_size if has_size else 'n/a',
        'modal_recurrence': round(recurrence, 2) if has_size else 'n/a',
        'breakdown': breakdown,
        'score': f"{score}/{max_possible}",
        'score_pct': round(ratio * 100, 1),
        'is_beacon_suspect': ratio >= threshold,
    }


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


# Main
def main():
    ap = argparse.ArgumentParser(description="PCAP beacon hunter v2 (modal + auto-gap)")
    ap.add_argument("pcap", help="path to pcap / pcapng file")
    ap.add_argument("--syn-only", action="store_true",
                    help="only count TCP SYN packets (disables size signals)")
    ap.add_argument("--min-gap", type=float, default=None,
                    help="burst-merge threshold in seconds (default: auto knee detection)")
    ap.add_argument("--threshold", type=float, default=0.55,
                    help="suspect if score ratio >= this (default 0.55)")
    ap.add_argument("--top", type=int, default=15,
                    help="how many candidates to show (default 15)")
    ap.add_argument("--include-internal", action="store_true",
                    help="also include internal IPs (needed for lab / RFC1918 C2)")
    args = ap.parse_args()

    print(f"[*] Reading: {args.pcap}")
    packets = rdpcap(args.pcap)
    print(f"[*] Total packets: {len(packets)}\n")

    samples_by_dst = defaultdict(list)
    dst_counter = Counter()

    for pkt in packets:
        ip = get_ip_layer(pkt)
        if ip is None:
            continue
        dst = ip.dst

        if not args.include_internal and not is_external(dst):
            continue

        if args.syn_only:
            if not pkt.haslayer(TCP):
                continue
            if not (pkt[TCP].flags & 0x02) or (pkt[TCP].flags & 0x10):
                continue

        dst_counter[dst] += 1
        samples_by_dst[dst].append((float(pkt.time), payload_len(pkt)))

    if not dst_counter:
        print("[!] No candidates. Try --include-internal or check pcap direction.")
        return

    print(f"[*] {'External' if not args.include_internal else 'All'} "
          f"destination candidates (by packet count):\n")
    print(f"    {'IP':<24}{'packets':>8}")
    print(f"    {'-'*24}{'-'*8}")
    for ip, c in dst_counter.most_common(args.top):
        print(f"    {ip:<24}{c:>8}{infra_hint(ip)}")
    print()

    print("[*] Beacon analysis (v2 scoring):\n")
    scored = []   # (ip, result, is_infra)
    for ip, _ in dst_counter.most_common(args.top):
        result = analyze_beacon(samples_by_dst[ip],
                                min_gap=args.min_gap,
                                threshold=args.threshold)
        if result is None:
            continue

        is_infra = bool(infra_hint(ip))
        flag = "  <<< BEACON SUSPECT" if result.get('is_beacon_suspect') else ""
        print(f"  [{ip}]{infra_hint(ip)}{flag}")
        for k, v in result.items():
            if k == 'breakdown':
                parts = ", ".join(f"{kk}={vv}" for kk, vv in v.items())
                print(f"      {'breakdown':<16}: {parts}")
            else:
                print(f"      {k:<16}: {v}")
        print()

        if result.get('is_beacon_suspect'):
            scored.append((ip, result, is_infra))

    # shadow resolution
    # An infra (gateway/broadcast) hit that shares a non-infra beacon's exact
    # cadence is that beacon's routed reflection, not an independent C2.
    def same_cadence(a, b):
        if not a.get('mean_interval') or not b.get('mean_interval'):
            return False
        rel = abs(a['mean_interval'] - b['mean_interval']) / b['mean_interval']
        return rel < 0.10 and abs(a['events'] - b['events']) <= 2

    primary = [(ip, r) for ip, r, inf in scored if not inf]
    beacons, shadows = [], []
    for ip, r, inf in scored:
        owner = next((pip for pip, pr in primary if same_cadence(r, pr)), None)
        if inf and owner:
            shadows.append((ip, owner))
        else:
            beacons.append((ip, r))

    print("=" * 56)
    if beacons:
        print(f"[+] {len(beacons)} beacon candidate(s) found:")
        for ip, r in beacons:
            print(f"    {ip}  ->  ~{r['mean_interval']}s, jitter {r['jitter_pct']}%, "
                  f"modal {r['modal_pkt_size']}B x{r['modal_recurrence']}, "
                  f"{r['events']} check-ins, score {r['score_pct']}%")
    else:
        print("[-] No beacon suspects.")
        print("    Try: --threshold 0.45 (looser)")

    if shadows:
        print()
        print("[i] Routing shadows (same cadence as a beacon above, not independent):")
        for ip, owner in shadows:
            print(f"    {ip}  -> reflection of {owner}")


if __name__ == "__main__":
    main()