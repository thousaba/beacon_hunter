import sys
import argparse
import ipaddress
import statistics
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP
except ImportError:
    sys.exit("scapy not found: pip install scapy")


# Beacon analysis function
def analyze_beacon(timestamps, min_gap=1.0,
                   cv_threshold=0.25, min_mean=5.0, min_events=8):
    """
    timestamps : list of float epoch timestamps (packets to one destination)
    min_gap    : packets closer than this are counted as one event (burst merge)
    """
    if len(timestamps) < 4:
        return None  # not enough samples

    timestamps = sorted(timestamps)

    # collapse sub-second bursts into single check-in events
    events = [timestamps[0]]
    for t in timestamps[1:]:
        if t - events[-1] >= min_gap:
            events.append(t)

    if len(events) < 4:
        return {
            'raw_packets': len(timestamps),
            'events': len(events),
            'note': 'not enough separate events (most packets fall in the same burst)',
            'is_beacon_suspect': False,
        }

    intervals = [events[i + 1] - events[i] for i in range(len(events) - 1)]
    mean = statistics.mean(intervals)
    stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
    cv = stdev / mean if mean > 0 else 0.0

    return {
        'raw_packets': len(timestamps),
        'events': len(events),
        'mean_interval': round(mean, 2),
        'stdev': round(stdev, 2),
        'cv': round(cv, 3),
        'jitter_pct': round(cv * 100, 1),
        'is_beacon_suspect': (cv < cv_threshold
                              and mean > min_mean
                              and len(events) >= min_events),
    }


# Helpers
def is_external(ip_str):
    """Is this an internet (public, non-private) IP?"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or
                ip.is_multicast or ip.is_link_local or ip.is_reserved)


def get_ip_layer(pkt):
    """Return the IPv4 or IPv6 layer, or None if absent."""
    if pkt.haslayer(IP):
        return pkt[IP]
    if pkt.haslayer(IPv6):
        return pkt[IPv6]
    return None


# Main flow
def main():
    ap = argparse.ArgumentParser(description="PCAP beacon hunter")
    ap.add_argument("pcap", help="path to pcap / pcapng file")
    ap.add_argument("--syn-only", action="store_true",
                    help="only count TCP SYN packets (each new connection = check-in)")
    ap.add_argument("--min-gap", type=float, default=1.0,
                    help="burst-merge threshold in seconds (default 1.0)")
    ap.add_argument("--top", type=int, default=15,
                    help="how many external candidates to show (default 15)")
    ap.add_argument("--include-internal", action="store_true",
                    help="also include internal IPs as candidates")
    args = ap.parse_args()

    print(f"[*] Reading: {args.pcap}")
    packets = rdpcap(args.pcap)
    print(f"[*] Total packets: {len(packets)}\n")

    # collect timestamps per destination IP
    ts_by_dst = defaultdict(list)
    dst_counter = Counter()

    for pkt in packets:
        ip = get_ip_layer(pkt)
        if ip is None:
            continue

        dst = ip.dst

        # filter: external only? (unless --include-internal given)
        if not args.include_internal and not is_external(dst):
            continue

        # SYN-only mode: only packets opening a new connection
        if args.syn_only:
            if not pkt.haslayer(TCP):
                continue
            # SYN set, not ACK -> initial SYN
            if not (pkt[TCP].flags & 0x02) or (pkt[TCP].flags & 0x10):
                continue

        dst_counter[dst] += 1
        ts_by_dst[dst].append(float(pkt.time))

    if not dst_counter:
        print("[!] No candidates. Try --include-internal or check the pcap direction.")
        return

    # candidate list 
    print(f"[*] {'External' if not args.include_internal else 'All'} "
          f"destination candidates (by packet count):\n")
    print(f"    {'IP':<24}{'packets':>8}")
    print(f"    {'-'*24}{'-'*8}")
    for ip, c in dst_counter.most_common(args.top):
        print(f"    {ip:<24}{c:>8}")
    print()

    # beacon analysis for each candidate
    print("[*] Beacon analysis:\n")
    suspects = []
    for ip, _ in dst_counter.most_common(args.top):
        result = analyze_beacon(ts_by_dst[ip], min_gap=args.min_gap)
        if result is None:
            continue

        flag = "  <<< BEACON SUSPECT" if result.get('is_beacon_suspect') else ""
        print(f"  [{ip}]{flag}")
        for k, v in result.items():
            print(f"      {k:<16}: {v}")
        print()

        if result.get('is_beacon_suspect'):
            suspects.append((ip, result))

    # summary
    print("=" * 50)
    if suspects:
        print(f"[+] {len(suspects)} beacon candidate(s) found:")
        for ip, r in suspects:
            print(f"    {ip}  ->  every ~{r['mean_interval']}s, "
                  f"jitter {r['jitter_pct']}%, {r['events']} check-ins")
    else:
        print("[-] No beacon suspects.")
        print("    Try: --syn-only  (cleaner for HTTP/HTTPS C2)")
        print("    Try: --min-gap 2.0  (for slow beacons)")


if __name__ == "__main__":
    main()
