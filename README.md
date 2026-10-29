# beacon-hunter

`beacon-hunter` is an offline PCAP/PCAPNG analysis prototype that ranks network traffic patterns for review. It looks for repeated timing and payload-size patterns that can occur in C2 beaconing. A result is a **heuristic investigation lead**, not proof of malware or a calibrated probability.


## What it currently does

- Reads saved PCAP/PCAPNG files with Scapy; it does not capture live traffic.
- Extracts IPv4/IPv6 packets carrying TCP or UDP.
- By default, analyzes packets whose destination IP is classified as external.
- Groups packets by **source IP, destination IP, transport protocol, and destination port**. The source port is intentionally omitted so repeat TCP connections using new ephemeral source ports stay together.
- Scores event timing, repeated payload sizes, payload smallness, and event count.
- Reports DNS query/response context when Scapy recognizes DNS packets. Recognized DNS packets are excluded from generic beacon scoring.
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

# Print the packets assigned to each generated event
python beacon-hunter.py capture.pcap --debug-events

# Inspect event grouping with a 0.7-second threshold
python beacon-hunter.py capture.pcap --min-gap 0.7 --debug-events
```

| Option | Default | Purpose |
|---|---:|---|
| `pcap` | required | PCAP or PCAPNG path |
| `--include-internal` | off | Also include internal, loopback, link-local, multicast, and reserved destination addresses |
| `--min-gap N` | auto | Event-separation threshold in seconds |
| `--threshold R` | `0.55` | Flag when score ratio is at least `R` |
| `--top N` | `15` | Analyze the N candidate groups with the most packets, not the N highest scores |
| `--syn-only` | off | Keep TCP SYN packets without ACK; excludes UDP and established TCP packets |
| `--debug-events` | off | Print each event's relative start time, packet count, payload sizes, and packet members |

By default, beacon timing and payload-size scoring use only packets carrying
application payload. Zero-payload TCP control packets are kept separately and
shown by `--debug-events`, but do not start or distort application-data events.
`--syn-only` switches scoring to the separate TCP SYN-without-ACK series;
payload-size scoring can still apply if a SYN carries data.

`--debug-events` shows how the selected `--min-gap` groups the active series.
By default that is payload-bearing packets; with `--syn-only` it is connection
attempts. Zero-payload TCP control packets are printed separately. With an
automatic threshold, the output includes the chosen value and its source. Event
membership is anchored at the first packet in each event: a packet joins the
current event while its timestamp is less than `min_gap` after that event's
start; otherwise it starts a new event. The option is diagnostic and does not
change scoring.

## How scoring works

For each candidate group, timestamps from the active series are merged into
events using `--min-gap`. The default series is packets with non-empty TCP or
UDP payload; `--syn-only` uses TCP SYN packets without ACK. Zero-payload TCP
control packets are not part of application-data timing. The default gap is an
automatic heuristic that searches for a large ratio jump between sorted packet
gaps; it falls back to one second when it finds no clear split.

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

Answer-section CNAME chains are followed to their final A/AAAA records for
connection correlation. The effective TTL is the shortest TTL across the
alias chain and final address record.

Recognized DNS packets are reported separately and excluded from generic beacon scoring, avoiding false positives caused by repeated, similarly sized DNS queries. For A/AAAA answers, the analyzer compares the DNS client and response time with connection starts to the returned IP. It tracks TCP connections by 5-tuple and uses the observed SYN timestamp; TTL is checked at connection start, so an established connection stays correlated after the TTL expires. Results carry an attribution and evidence code: `CONFIRMED` / `HTTP_REQUEST_TARGET` when a matching plaintext HTTP request target and Host are observed, `HIGH` / `TLS_SNI_DNS_MATCH` when TLS SNI matches a DNS candidate, `HIGH` / `TLS_SNI_ONLY` when SNI is visible but DNS is absent, `CONFLICT` / `TLS_SNI_DNS_CONFLICT` when SNI differs from observed DNS candidates, `MEDIUM` / `DNS_IP_TIME_UNIQUE` for one DNS-name candidate at an observed TCP SYN, `LOW` / `DNS_IP_TIME_FIRST_OBSERVED` when only the first packet of a connection is captured, and `AMBIGUOUS` / `DNS_IP_TIME_MATCH` when multiple DNS names share the IP and time window without direct hostname evidence. These labels describe correlation evidence, not maliciousness. HTTP Host is normally encrypted inside HTTPS and is not readable from an ordinary PCAP; TLS SNI can be visible in the ClientHello unless Encrypted ClientHello (ECH) is used. HTTP request parsing and TLS SNI parsing currently require the relevant header or complete ClientHello to appear in one TCP packet; TCP stream reassembly is not implemented. DNS-specific beacon scoring is not implemented. Encrypted DNS such as DoH/DoT is not parsed as ordinary DNS.

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

The baseline illustrates both strengths and limits: fixed-size TCP patterns were detected at several jitter levels, while variable-size/growing patterns and variable-size UDP were missed. A benign periodic updater was flagged; recognized DNS is now excluded from generic scoring. Benign traffic mixed into the same service group hid a beacon. These are results from controlled synthetic cases, not field accuracy measurements.


## Known limitations

- It is offline-only and loads the full capture into memory.
- It does not reconstruct TCP sessions, reassemble streams, or identify the originating process.
- TCP retransmissions are not deduplicated; payload-bearing retransmissions can still affect event timing and size signals.
- Source-port omission can merge separate applications sharing a remote service.
- Timing/event thresholds and score weights are hand-written heuristics, not calibrated against a representative labeled corpus.
- The payload-size heuristic is not application-aware; the fixed 1400-byte cutoff is not a measured MSS.
- DNS is reported separately and excluded from generic scoring; A/AAAA answers are correlated to connection starts by client IP, answer IP, 5-tuple, and TTL window. This is DNS context, not DNS-specific beacon scoring.
- It does not use destination reputation, TLS fingerprints, or endpoint telemetry; HTTP Host and TLS SNI are used only as DNS-correlation evidence, not in beacon scoring.
- IPv4 infrastructure hints and routing-shadow matching are rough heuristics and can mislabel unrelated traffic.

