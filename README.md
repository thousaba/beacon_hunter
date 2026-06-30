# beacon-hunter

A PCAP analysis tool that hunts C2 beacons using **two independent detection bases** —
behavioural timing analysis and structural packet-size fingerprinting — combined through
additive multi-signal scoring.

Validated against real **Sliver C2** HTTPS/HTTP beacon telemetry across a range of jitter
configurations. The headline result: a `--seconds 30 --jitter 70` Sliver beacon (jitter at
2.3× the sleep interval) that defeats pure timing analysis is still flagged, because the
structural signal survives both jitter *and* payload padding.

---


## Installation

```bash
# 1. Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Lab C2 is on an RFC1918 address, so --include-internal is required:
python beacon-hunter.py capture.pcap --include-internal

# Public-internet C2 (external candidates only):
python beacon-hunter.py capture.pcap
```

| Flag                 | Default | Purpose                                              |
|----------------------|---------|------------------------------------------------------|
| `--include-internal` | off     | include RFC1918 destinations (needed for lab C2)     |
| `--min-gap N`        | auto    | override burst-merge threshold (seconds)             |
| `--threshold R`      | 0.55    | suspect if score ratio ≥ R                            |
| `--top N`            | 15      | number of candidates to analyse                      |
| `--syn-only`         | off     | count TCP SYNs only (disables size signals)          |

### Example output (real Sliver telemetry, 30s sleep / 70s jitter)

```
  [192.168.56.102]  <<< BEACON SUSPECT
      events          : 17
      min_gap         : 5.8 (auto (knee ratio 33.4x))
      mean_interval   : 61.96
      timing_cv       : 0.367
      modal_pkt_size  : 23
      modal_recurrence: 1.0
      breakdown       : timing=7, events=12, size_recurrence=30, size_smallness=15
      score           : 64/100
      is_beacon_suspect: True

[+] 1 beacon candidate(s) found:
    192.168.56.102  ->  ~61.96s, jitter 36.7%, modal 23B x1.0, 17 check-ins, score 64.0%

[i] Routing shadows (same cadence as a beacon above, not independent):
    192.168.56.1  -> reflection of 192.168.56.102
```

---


## The problem: jitter blinds timing-only detectors

The classic behavioural beacon detector measures how regular the check-in interval is, via
the coefficient of variation of inter-arrival times:

```
CV = stdev(intervals) / mean(intervals)
```

Low CV = machine-like regularity = beacon. The weakness is **jitter**: a C2 that
randomises its sleep inflates the CV until the traffic looks as irregular as human browsing.

Sliver applies jitter additively — `--jitter m` adds a random delay of 0…m seconds to the
base `--seconds` interval, so the interval is uniform over `[S, S+J]`. With `r = J/S`:

```
CV = r / (√3 · (2 + r))
```

This means a timing-only detector with a fixed CV cut-off (e.g. 0.25) has a hard ceiling:

| Sliver config | r = J/S | CV    | Caught by CV < 0.25? |
|---------------|---------|-------|----------------------|
| `60 / 10`     | 0.17    | 0.044 | yes                  |
| `30 / 30`     | 1.0     | 0.19  | yes (borderline)     |
| `30 / 70`     | 2.33    | 0.31* | **no**               |

\* measured 0.367 before burst-merge correction; ~0.31 after. Either way, above the cut-off.

No purely statistical timing detector — RITA included — reliably resolves a single beacon at
this jitter level, because the signal no longer separates from organic noise. **That is a
mathematical limit, not a tuning problem.** More capture time does not fix it: a longer PCAP
makes the measured CV *more precise*, not *lower*. The interval genuinely is that irregular.

The answer is not to push timing harder, but to add a signal that jitter cannot touch.

---

## How it works

Each destination is scored by four signals. The verdict is the score ratio against the
maximum achievable for the signals available (default suspect threshold: **0.55**).

### Signal 1 — timing regularity (behavioural, max 35)

CV of check-in intervals. Strong at low jitter, degrades as jitter rises. This is the
*behavioural* axis, and its envelope is jitter-limited by design.

### Signal 2 — modal control-packet recurrence (structural, max 30)

The key signal. A beacon polls its C2 with a **constant-size request** every check-in
("any tasks for me?"). Even when Sliver pads the response body with random data, that small
poll-request packet stays a fixed size.

`beacon-hunter` finds the modal (most common) payload size among non-bulk packets, then
measures how many check-in events contain a packet of that size:

```
recurrence = events_containing_modal_size / total_events
```

A constant-size packet appearing in ~every check-in is a beacon fingerprint that is
**independent of timing** — it survives arbitrary jitter — and **independent of padding**,
because padding inflates the body, not the poll. This is what catches the high-jitter case.

Two bounds keep this signal honest:
- `BULK_MSS = 1400` — payloads at/above MSS are bulk data fragmentation, not control packets.
- `MIN_CTRL = 16` — payloads below this are TCP keepalives / bare ACK framing. Excluding them
  stops gateways and other infrastructure from faking a modal recurrence on 6-byte ACKs.

### Signal 3 — modal smallness (max 15)

A small modal poll (tens of bytes) is more beacon-like than a large one.

### Signal 4 — persistence (max 20)

More check-ins = more confidence. Encodes the "long-lived, many short connections to one
destination" property that real beaconing exhibits.

### Why additive scoring, not a boolean gate

An earlier version used a hard `AND` of the conditions. A high-jitter beacon fails the timing
condition and the whole verdict collapses — one weak signal vetoes everything. Additive
scoring lets a strong structural signal carry the verdict when the behavioural signal is dead:

```
30/70 beacon breakdown:  timing=7  +  events=12  +  size_recurrence=30  +  smallness=15  =  64/100  ->  SUSPECT
                         ^^^^^^^                      ^^^^^^^^^^^^^^^^^^
                         jitter killed timing         structural signal carried it
```

---

## Engineering features

**Auto burst-merge (`--min-gap` defaults to automatic).** A single check-in is several
packets (request + response) spread over a few seconds; the sleep between check-ins is tens
of seconds. The tool finds the knee separating these two regimes by locating the largest
ratio jump in the sorted inter-packet gaps, and merges sub-knee packets into one event. This
removes a manual-tuning footgun: a wrong `--min-gap` fragments check-ins and inflates the
measured CV (observed: CV 0.453 → 0.18 once the gap was corrected on real data).

**Routing-shadow resolution.** On a host-only lab network, beacon traffic is reflected by the
gateway, so the gateway IP shows the *same cadence* as the real C2 and scores as a second
beacon. The tool flags likely infrastructure addresses (`.1`, `.254`, `.255`), and any
infra hit that shares a real beacon's cadence (mean interval within 10%, event count within
±2) is reported as a **routing shadow**, not an independent C2.

---


## Detection envelope

Validated against Sliver C2 beacons captured on a VirtualBox host-only network (Kali C2 at
`192.168.56.102`, Sliver HTTP beacon, capture via `tcpdump`/`dumpcap` filtered to the C2 host
on port 443).

| Config  | r    | timing CV | timing pts | modal | recurrence | score | verdict |
|---------|------|-----------|------------|-------|------------|-------|---------|
| `60/10` | 0.17 | 0.044     | 35         | —     | —          | high  | ✅ caught (baseline) |
| `30/30` | 1.0  | 0.18      | 22         | 24 B  | 1.0        | 75 %  | ✅ caught |
| `30/70` | 2.33 | 0.367     | 7          | 23 B  | 1.0        | 64 %  | ✅ caught |

The table tells the whole story: as jitter rises, the **behavioural** contribution collapses
(35 → 22 → 7), while the **structural** contribution holds steady (recurrence stays at 1.0).
The two axes cover different failure modes.

- **Behavioural axis** — reliable up to roughly `r ≤ 1` (jitter ≤ sleep). Degrades beyond that.
- **Structural axis** — independent of jitter, catches current Sliver across all tested
  configs. But it is **implementation-specific**.

---

## Limitations — and why detection needs depth

The structural signal is closer to a *signature* than a behavioural invariant. It works
because Sliver emits a constant-size poll request. A more advanced C2 that **randomises its
control-packet sizes** (padding the request as well as the response) would defeat it, and a
C2 that does both that *and* high jitter sits in a genuine blind spot for any single-host,
single-flow statistical detector.

That blind spot is not a tool bug — it is the reason beacon detection is layered in practice.
A determined beacon can hide its timing and its sizes, but it cannot hide:

- **where it talks** — destination reputation, newly-registered domains, unseen ASNs
- **how its TLS looks** — JA3/JA3S client-hello fingerprints (jitter-invariant)
- **its connection profile** — many short, low-data connections to one destination over hours

`beacon-hunter` is the first line, not the only line. The honest framing of its capability is
a two-axis envelope with a known gap, closed by correlation with reputation, TLS
fingerprinting, and connection-profile signals — defence in depth.

---

## Future work

- **Robust timing (median absolute deviation)** instead of CV, to reduce sensitivity to a
  single outlier check-in (e.g. an oversized registration on first contact).
- **Distribution-shape test** (`scipy.stats.kstest` against a uniform interval model). A
  machine `sleep ± jitter` produces a uniform/triangular interval distribution; organic
  traffic trends exponential (Poisson arrivals). This tests *what kind* of randomness the
  intervals are, rather than only how much.
- **Connection-profile signal** (RITA-style): distinct connection count and total duration as
  a timing-independent weight.

> **Note on autocorrelation:** an obvious idea is to recover a hidden period under the jitter
> noise via autocorrelation. It does **not** apply to Sliver's additive jitter: intervals are
> i.i.d. (a renewal process with no preserved phase), so there is no fixed period for
> autocorrelation to surface. It only helps against C2s that aim for a target time ± jitter
> and preserve phase. Documented here because ruling it out is part of the analysis.

---
