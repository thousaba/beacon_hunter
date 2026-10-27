"""Generate deterministic, production-like synthetic PCAP fixtures.

Requires Scapy (already listed in the project requirements). No packets are
sent to the network; this script only writes offline capture files.
"""

import json
import random
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP, Raw, wrpcap


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures" / "production-like"
BASE = 1_735_689_600  # 2025-01-01 UTC
SEED = 20251027
CLIENT = "192.168.10.25"
CLIENT_2 = "192.168.10.26"
BEACON_HOST = "93.184.216.34"
WEB_HOST = "142.250.72.14"
DNS_RESOLVER = "8.8.8.8"
CLIENT_MAC = "02:00:00:00:10:25"
SERVER_MAC = "02:00:00:00:00:01"


class Capture:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.packets = []
        self.next_port = 40000
        self.next_seq = 100000
        self.next_dns_id = 1

    def add(self, offset, packet):
        packet.time = BASE + float(offset)
        self.packets.append(packet)

    def tcp_exchange(self, offset, src, dst, dport, request, response=b"ok",
                     src_mac=CLIENT_MAC):
        """Add a compact TCP open/request/response/close exchange."""
        sport = self.next_port
        self.next_port += 1
        cseq = self.next_seq
        sseq = self.next_seq + 500000
        self.next_seq += 1000
        dst_mac = SERVER_MAC

        def frame(a, b, payload=None):
            return Ether(src=a, dst=b) / IP(src=src, dst=dst)

        def tcp_packet(t, a, b, sport_, dport_, seq, ack, flags, payload=None):
            pkt = frame(a, b) / TCP(sport=sport_, dport=dport_, seq=seq,
                                    ack=ack, flags=flags, window=64240)
            if payload:
                pkt = pkt / Raw(load=payload)
            self.add(t, pkt)

        tcp_packet(offset, src_mac, dst_mac, sport, dport, cseq, 0, "S")
        tcp_packet(offset + 0.025, dst_mac, src_mac, dport, sport, sseq,
                   cseq + 1, "SA")
        tcp_packet(offset + 0.050, src_mac, dst_mac, sport, dport, cseq + 1,
                   sseq + 1, "A")
        tcp_packet(offset + 0.100, src_mac, dst_mac, sport, dport, cseq + 1,
                   sseq + 1, "PA", request)
        tcp_packet(offset + 0.180, dst_mac, src_mac, dport, sport, sseq + 1,
                   cseq + 1 + len(request), "PA", response)
        tcp_packet(offset + 0.220, src_mac, dst_mac, sport, dport,
                   cseq + 1 + len(request), sseq + 1 + len(response), "FA")
        tcp_packet(offset + 0.245, dst_mac, src_mac, dport, sport,
                   sseq + 1 + len(response), cseq + 2 + len(request), "FA")

    def http_request(self, path, host, pad=0, user_agent="LabClient/1.0"):
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}",
            f"User-Agent: {user_agent}",
            "Accept: */*",
            "Connection: close",
        ]
        if pad:
            headers.append("X-Lab-Padding: " + ("p" * pad))
        return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")

    def http_response(self, size=32):
        body = b"r" * size
        return (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body)

    def dns_exchange(self, offset, qname, src=CLIENT, resolver=DNS_RESOLVER):
        qid = self.next_dns_id & 0xffff
        self.next_dns_id += 1
        sport = self.next_port
        self.next_port += 1
        query = (Ether(src=CLIENT_MAC, dst=SERVER_MAC)
                 / IP(src=src, dst=resolver)
                 / UDP(sport=sport, dport=53)
                 / DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype="A")))
        answer = (Ether(src=SERVER_MAC, dst=CLIENT_MAC)
                  / IP(src=resolver, dst=src)
                  / UDP(sport=53, dport=sport)
                  / DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=qname, qtype="A"),
                        an=DNSRR(rrname=qname, type="A", ttl=60, rdata="93.184.216.34")))
        self.add(offset, query)
        self.add(offset + 0.035, answer)

    def udp_datagram(self, offset, src, dst, dport, payload, sport=None):
        if sport is None:
            sport = self.next_port
            self.next_port += 1
        pkt = (Ether(src=CLIENT_MAC, dst=SERVER_MAC)
               / IP(src=src, dst=dst)
               / UDP(sport=sport, dport=dport)
               / Raw(load=payload))
        self.add(offset, pkt)

    def write(self, name, truth, description, parameters):
        self.packets.sort(key=lambda pkt: float(pkt.time))
        path = OUT / f"{name}.pcap"
        wrpcap(str(path), self.packets)
        return {
            "file": path.name,
            "packets": len(self.packets),
            "ground_truth_beacon_present": truth,
            "description": description,
            "parameters": parameters,
        }


def beacon_capture(name, intervals, size_mode="fixed", transport="tcp", seed=SEED):
    cap = Capture(seed)
    t = 0.0
    sizes = []
    for i, gap in enumerate(intervals):
        t += gap
        if size_mode == "fixed":
            pad = 0
        elif size_mode == "variable":
            pad = cap.rng.randint(5, 420)
        elif size_mode == "growing":
            pad = min(900, 20 + i * 70)
        elif size_mode == "variable_with_control":
            pad = cap.rng.randint(40, 500)
        else:
            raise ValueError(size_mode)

        if transport == "tcp":
            req = cap.http_request("/api/poll", "beacon.example.test", pad=pad)
            sizes.append(len(req))
            cap.tcp_exchange(t, CLIENT, BEACON_HOST, 80, req,
                             cap.http_response(size=cap.rng.randint(20, 700)))
            if size_mode == "variable_with_control":
                # A stable small control request remains within each event,
                # alongside variable-sized application data.
                ctrl = b"GET /p HTTP/1.0\r\n\r\n"
                cap.tcp_exchange(t + 0.5, CLIENT, BEACON_HOST, 80, ctrl,
                                 cap.http_response(size=cap.rng.randint(100, 900)))
        elif transport == "udp":
            length = 48 if size_mode == "fixed" else cap.rng.randint(35, 700)
            cap.udp_datagram(t, CLIENT, BEACON_HOST, 9999,
                             bytes([65 + (i % 26)]) * length)
            sizes.append(length)
        else:
            raise ValueError(transport)
    return cap, sizes


def add_bursty_http(cap, start, host, dport=80, src=CLIENT, count=24):
    offsets = []
    t = start
    for i in range(count):
        if i and i % 4 == 0:
            t += cap.rng.uniform(18, 85)
        else:
            t += cap.rng.uniform(0.15, 3.5)
        offsets.append(t)
        pad = cap.rng.choice([0, 0, 12, 85, 180, 350])
        req = cap.http_request(f"/assets/{i}?v={cap.rng.randrange(10000)}",
                               "www.example.test", pad=pad,
                               user_agent="BrowserLike/124.0")
        cap.tcp_exchange(t, src, host, dport, req,
                         cap.http_response(size=cap.rng.randint(200, 1200)))
    return offsets


def build_suite():
    OUT.mkdir(parents=True, exist_ok=True)
    entries = []
    rng = random.Random(SEED)

    profiles = [
        ("01_beacon_regular_tcp", [30.0] * 12, "fixed", "tcp",
         "Low-jitter repeated HTTP check-ins over new TCP connections.", True),
        ("02_beacon_additive_jitter_tcp",
         [12.0 + rng.uniform(0, 12) for _ in range(14)], "fixed", "tcp",
         "Positive additive jitter; fixed-size request shape.", True),
        ("03_beacon_high_jitter_tcp",
         [rng.uniform(8, 42) for _ in range(16)], "fixed", "tcp",
         "High interval jitter with a recurring request size.", True),
        ("04_beacon_variable_size_tcp",
         [24.0 + rng.uniform(-5, 5) for _ in range(14)], "variable", "tcp",
         "Moderate timing variation and changing request sizes.", True),
        ("05_beacon_growing_interval_size_tcp",
         [8.0 + 1.8 * i for i in range(13)], "growing", "tcp",
         "Intervals and request padding grow across check-ins.", True),
        ("06_beacon_sparse_tcp", [180.0] * 8, "fixed", "tcp",
         "Long, regular intervals with a short event count.", True),
        ("07_beacon_jittered_udp",
         [18.0 + rng.uniform(-6, 10) for _ in range(14)], "variable", "udp",
         "UDP datagrams with jitter and varying payload lengths.", True),
        ("08_beacon_variable_payload_control_tcp",
         [35.0 + rng.uniform(-8, 10) for _ in range(14)],
         "variable_with_control", "tcp",
         "Variable application exchanges plus a recurring small request.", True),
        ("13_short_capture_tcp", [30.0] * 3, "fixed", "tcp",
         "Only three check-ins; tests minimum-observation behavior.", True),
    ]
    for idx, (name, intervals, size_mode, transport, description, truth) in enumerate(profiles):
        cap, sizes = beacon_capture(name, intervals, size_mode, transport,
                                    seed=SEED + idx)
        entries.append(cap.write(name, truth, description, {
            "transport": transport,
            "intervals_seconds": [round(x, 3) for x in intervals],
            "size_mode": size_mode,
            "request_or_datagram_sizes": sizes,
            "seed": SEED + idx,
        }))

    # Benign bursty web-like traffic: valid HTTP messages, short sessions,
    # varied paths, request lengths, response lengths, and clustered timing.
    cap = Capture(SEED + 20)
    offsets = add_bursty_http(cap, 2.0, WEB_HOST, count=32)
    entries.append(cap.write("09_benign_bursty_http", False,
        "Bursty HTTP-like browsing with variable timing and payload sizes.",
        {"requests": len(offsets), "timing": "clustered and irregular", "seed": SEED + 20}))

    # A benign periodic update is intentionally beacon-like. It should expose
    # the detector's false-positive limit, not be treated as malicious ground truth.
    cap = Capture(SEED + 21)
    for i in range(10):
        req = cap.http_request("/update/check", "updates.example.test")
        cap.tcp_exchange(i * 300.0 + 1.0, CLIENT_2, WEB_HOST, 80, req,
                         cap.http_response(size=cap.rng.randint(300, 1200)),
                         src_mac="02:00:00:00:10:26")
    entries.append(cap.write("10_benign_periodic_update", False,
        "Benign periodic update traffic; intentionally resembles a beacon.",
        {"requests": 10, "interval_seconds": 300, "seed": SEED + 21}))

    # Real DNS wire-format queries/responses in irregular bursts.
    cap = Capture(SEED + 22)
    t = 0.0
    for i in range(32):
        t += rng.choice([0.25, 0.7, 1.4, 12.0, 27.0, 63.0])
        cap.dns_exchange(t, f"host-{i:02d}.example.test")
    entries.append(cap.write("11_benign_bursty_dns", False,
        "Valid DNS A queries and responses in irregular bursts.",
        {"queries": 32, "qname_family": "host-NN.example.test", "seed": SEED + 22}))

    # Same destination/service contamination: benign requests interleave with
    # beacon check-ins and are deliberately merged by the current flow key.
    cap, _ = beacon_capture("12_same_service_contamination", [60.0] * 12,
                            "fixed", "tcp", seed=SEED + 23)
    add_bursty_http(cap, 15.0, BEACON_HOST, count=18)
    entries.append(cap.write("12_same_service_contamination", True,
        "Beacon and browser-like HTTP sessions share source, destination, TCP and port.",
        {"beacon_intervals_seconds": [60] * 12, "background_requests": 18,
         "seed": SEED + 23}))

    # Composite capture combines independent beacon, DNS, web, and a periodic
    # benign updater so candidate ranking is tested with simultaneous profiles.
    cap, _ = beacon_capture("14_mixed_background", [21.0 + rng.uniform(0, 9)
        for _ in range(14)], "fixed", "tcp", seed=SEED + 24)
    add_bursty_http(cap, 7.0, WEB_HOST, count=28)
    t = 4.0
    for i in range(24):
        t += rng.choice([0.4, 1.1, 3.0, 16.0, 44.0])
        cap.dns_exchange(t, f"query-{i:02d}.example.test")
    entries.append(cap.write("14_mixed_background", True,
        "Composite capture with beacon, bursty HTTP, and valid DNS traffic.",
        {"beacon_events": 14, "background_http_requests": 28,
         "dns_queries": 24, "seed": SEED + 24}))

    manifest = {
        "title": "Beacon Hunter production-like synthetic PCAP suite",
        "generated_by": "tests/pcap_suite/generate.py",
        "seed": SEED,
        "synthetic_only": True,
        "note": "No real malware, live traffic, or real user data is included. Ground truth describes generated behavior, not maliciousness.",
        "captures": entries,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                        encoding="utf-8")
    print(f"Generated {len(entries)} PCAP files in {OUT}")
    print(f"Manifest: {OUT / 'manifest.json'}")


if __name__ == "__main__":
    build_suite()
