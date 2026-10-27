# Synthetic PCAP evaluation suite

This suite creates reproducible, offline PCAPs for exercising beacon-hunter's
current packet grouping and scoring behavior. It is synthetic and production-
like; it is not a capture of real production traffic and contains no malware.

## Generate

From the repository root, with the project virtual environment active:

```powershell
python tests/pcap_suite/generate.py
```

The generator uses a fixed random seed and writes captures plus ground-truth
metadata to `tests/fixtures/production-like/`. It uses Scapy, already listed in
`requirements.txt`. It does not open sockets or send packets.

## Run the analyzer

```powershell
Get-ChildItem tests/fixtures/production-like/*.pcap | ForEach-Object {
    Write-Host "`n=== $($_.Name) ==="
    python beacon-hunter.py $_.FullName
}
```

The `manifest.json` file describes the generated traffic and expected
beacon-presence label for each capture. That label is ground truth about the
scenario generator, not a claim that a traffic pattern is malicious. In
particular, the benign periodic updater is intentionally beacon-like and may
be flagged; it measures a false-positive limitation.

## Coverage

The captures cover low and high jitter, fixed and variable request sizes,
gradually growing intervals and payloads, long sparse check-ins, TCP and UDP,
short observations, periodic benign updates, bursty HTTP-like activity, valid
DNS queries and responses, traffic mixed into the same service group, and a
composite background capture. The DNS packets have valid DNS wire-format
queries and answers; the other HTTP payloads are generated lab messages.

These files are for regression and exploratory evaluation. They do not replace
testing against representative, authorized enterprise captures. Inspect the
manifest and preserve its seed when comparing detector changes.

## Baseline run with the current detector

The suite was run through `beacon-hunter.py` with default settings. These
results are useful because they include both successful detections and
failures; they are not acceptance targets for every future detector version.

| Scenario | Current result | What it exercises |
|---|---|---|
| Regular, additive-jitter, high-jitter TCP | flagged | Timing plus recurring request-size signals |
| Sparse TCP, recurring small control request with variable exchanges | flagged | Long spacing and a stable request among variable traffic |
| Variable-size TCP beacon | missed, 48% | Timing is regular, but modal-size recurrence is weak |
| Growing interval and request size | missed, 30% | Drift defeats current fixed-interval and modal-size scoring |
| Jittered UDP with variable sizes | missed, 32% | UDP is grouped, but timing and size signals are weak |
| Bursty HTTP-like traffic | not flagged | Irregular benign background example |
| Benign periodic updater | flagged | Expected false-positive case: benign periodic behavior resembles a beacon |
| Bursty DNS | flagged, 60% | False positive from repeated, similar-sized DNS queries to one resolver |
| Beacon mixed with benign traffic to the same service | missed, 39% | Current source/destination/protocol/port grouping combines the traffic |
| Composite background | beacon found; DNS also flagged | Mixed candidates expose both detection and false-positive behavior |
| Three-event capture | insufficient events | Minimum-observation behavior |

The two DNS false positives and the same-service miss are especially useful
follow-up cases: DNS needs semantic context, and the current grouping key can
merge independent applications that share a remote service. Those are observed
limitations of this implementation, not flaws in the generated PCAPs.

The analyzer now prints DNS query/response context before candidate scoring.
This is report-only: UDP/53 packets still enter the existing generic beacon
score, so the DNS false positive remains until a separate DNS-specific scoring
decision is made.
