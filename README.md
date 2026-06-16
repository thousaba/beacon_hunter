# Beacon Hunter

A PCAP analysis tool that automatically detects C2 (command-and-control) beacon candidates by measuring the jitter (coefficient of variation) of check-in intervals to external destinations.

## How it works

1. Counts all external (public, non-private) destination IPs seen in the capture — these become beacon candidates.
2. Groups packets to each candidate into "check-in events," merging sub-second bursts into a single event.
3. Computes the coefficient of variation (CV) of the intervals between events — this is the jitter.
4. Flags a destination as a beacon suspect when the jitter is low, the average interval is reasonable, and there are enough check-ins.

Low jitter combined with a regular interval is a strong indicator of an automated beacon rather than normal human-driven traffic.

## Requirements

- Python 3
- [scapy](https://scapy.net/)

## Setup

It's recommended to install dependencies in a virtual environment.

### Windows (PowerShell)

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

To leave the virtual environment later, run `deactivate`.

## Usage

```bash
python beacon-hunter.py <pcap_file>
```

### Options

| Flag | Description | Default |
|---|---|---|
| `--syn-only` | Only count TCP SYN packets (each new connection = one check-in) | off |
| `--min-gap` | Burst-merge threshold in seconds | `1.0` |
| `--top` | Number of external candidates to display | `15` |
| `--include-internal` | Also include internal IPs as candidates | off |

### Examples

```bash
python beacon-hunter.py capture.pcap
python beacon-hunter.py capture.pcap --syn-only --min-gap 1.0
python beacon-hunter.py capture.pcap --include-internal --top 25
```

## Output

For each candidate destination, the tool reports:

- `raw_packets` — total packets sent to that IP
- `events` — number of distinct check-in events after burst merging
- `mean_interval` — average time between check-ins (seconds)
- `stdev` — standard deviation of intervals
- `cv` — coefficient of variation (jitter ratio)
- `jitter_pct` — jitter as a percentage
- `is_beacon_suspect` — whether the destination matches beacon-like behavior

A summary at the end lists all flagged beacon candidates with their interval and jitter.

## Tuning tips

- No suspects found? Try `--syn-only` for cleaner detection over HTTP/HTTPS C2 traffic.
- Missing slow beacons? Try a larger `--min-gap` (e.g. `2.0`).

## Disclaimer

This tool is intended for authorized security research, threat hunting, and defensive analysis of network captures you are permitted to inspect.
