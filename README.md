# beacon-hunter

`beacon-hunter` is an offline PCAP/PCAPNG analysis prototype that ranks network traffic patterns for review. It looks for repeated timing and payload-size patterns that can occur in C2 beaconing. A result is a **heuristic investigation lead**, not proof of malware or a calibrated probability.


## What it currently does

- Reads saved PCAP/PCAPNG files with Scapy; it does not capture live traffic.
- Extracts IPv4/IPv6 packets carrying TCP or UDP.
- By default, analyzes packets whose destination IP is classified as external.
- Groups packets by **source IP, destination IP, transport protocol, and destination port**. The source port is intentionally omitted so repeat TCP connections using new ephemeral source ports stay together.
- Scores event timing, repeated payload sizes, payload smallness, and event count.
- Reports DNS query/response context when Scapy recognizes DNS packets. DNS context is informational only; DNS packets still receive the generic UDP beacon score.
- Labels some IPv4 addresses ending in `.1`, `.254`, or `.255` as possible infrastructure addresses and applies a cadence-based routing-shadow heuristic.

The grouping key is a service-family heuristic, not a reconstructed TCP session or a full 5-tuple. Different applications using the same source host and remote service can be merged.

## Installation

```bash
python -m venv venv

# Windows PowerShell
.\venv\Scripts\Activate.ps1

# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

`requirements.txt` currently contains Scapy.

## Usage

```powershell
# Analyze public/external destination candidates
python beacon-hunter.py capture.pcap

# Include internal destination IPs, for example in a lab
python beacon-hunter.py capture.pcap --include-internal

# Manually set the event separation threshold to one second
python beacon-hunter.py capture.pcap --min-gap 1

# Consider only new TCP SYN packets
python beacon-hunter.py capture.pcap --syn-only
```

| Option | Default | Purpose |
|---|---:|---|
| `pcap` | required | PCAP or PCAPNG path |
| `--include-internal` | off | Also include internal, loopback, link-local, multicast, and reserved destination addresses |
| `--min-gap N` | auto | Event-separation threshold in seconds |
| `--threshold R` | `0.55` | Flag when score ratio is at least `R` |
| `--top N` | `15` | Analyze the N candidate groups with the most packets, not the N highest scores |
| `--syn-only` | off | Keep TCP SYN packets without ACK; excludes UDP and established TCP packets |

`--syn-only` changes which packets are sampled. The code does not explicitly disable size scoring; SYN payloads are usually empty, but payload-bearing SYNs can exist.

## How scoring works

For each candidate group, packet timestamps are merged into events using `--min-gap`. The default is an automatic heuristic that searches for a large ratio jump between sorted packet gaps; it falls back to one second when it finds no clear split.

| Signal | Maximum | Current interpretation |
|---|---:|---|
| Timing regularity | 35 | Coefficient of variation (standard deviation / mean) of intervals between event starts; lower is more regular |
| Modal-size recurrence | 30 | Share of events containing a payload near the most common eligible payload size |
| Modal smallness | 15 | Adds points when that modal payload is small |
| Event count | 20 | Adds points for more observed events |

Eligible payload sizes are `16 <= size < 1400` bytes. `1400` is a fixed heuristic cutoff named `BULK_MSS`; it is **not** the TCP MSS negotiated for a connection, and the same cutoff is applied to UDP. If fewer than three eligible payloads exist, size-based signals are omitted and the score is normalized to the signals available.

The default threshold is 55% of the available points. The score is not a malware probability. Small or repeated DNS/HTTP/control messages can raise the size signals, and event count depends on capture duration.

## DNS context

The DNS report pairs recognized queries and responses by transport, endpoint addresses and ports, and DNS transaction ID. It displays query names and types, response codes, answer values and TTLs, unanswered queries, and mean query/response time when available.

This report does not yet correlate DNS answers with later connections or change beacon scoring. UDP/53 traffic is still scored using generic timing and payload-size rules; the synthetic suite demonstrates that this can flag benign DNS traffic. Encrypted DNS such as DoH/DoT is not parsed as ordinary DNS.

## Synthetic PCAP evaluation

The reproducible suite is under [`tests/fixtures/production-like/`](tests/fixtures/production-like/), with scenario details in its [`manifest.json`](tests/fixtures/production-like/manifest.json). Generate it with:

```powershell
python tests/pcap_suite/generate.py
```

Run every capture with the analyzer:

```powershell
Get-ChildItem tests/fixtures/production-like/*.pcap | ForEach-Object {
    Write-Host "`n=== $($_.Name) ==="
    python beacon-hunter.py $_.FullName
}
```

The captures are synthetic and deterministic; they are not production captures and contain no real malware or user data. They cover regular and jittered timing, changing payload sizes, growing intervals, sparse check-ins, TCP/UDP, DNS, bursty background traffic, and mixed same-service traffic. See [`tests/pcap_suite/README.md`](tests/pcap_suite/README.md) for the full matrix and current baseline results.

The baseline illustrates both strengths and limits: fixed-size TCP patterns were detected at several jitter levels, while variable-size/growing patterns and variable-size UDP were missed. Bursty DNS and a benign periodic updater were flagged; benign traffic mixed into the same service group hid a beacon. These are results from controlled synthetic cases, not field accuracy measurements.


## Known limitations

- It is offline-only and loads the full capture into memory.
- It does not reconstruct TCP sessions, reassemble streams, or identify the originating process.
- Source-port omission can merge separate applications sharing a remote service.
- Timing/event thresholds and score weights are hand-written heuristics, not calibrated against a representative labeled corpus.
- The payload-size heuristic is not application-aware; the fixed 1400-byte cutoff is not a measured MSS.
- DNS is reported separately but still enters generic scoring; DNS answers are not yet correlated with later flows.
- It does not use destination reputation, HTTP metadata, TLS fingerprints, or endpoint telemetry.
- IPv4 infrastructure hints and routing-shadow matching are rough heuristics and can mislabel unrelated traffic.

