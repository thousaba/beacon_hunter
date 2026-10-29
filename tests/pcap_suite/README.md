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
TCP reply frames reverse both Ethernet and IP endpoints so packet direction is
represented correctly in the generated captures.

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
| Bursty DNS | not scored as a generic beacon | Recognized DNS is reported separately and excluded from generic scoring |
| Beacon mixed with benign traffic to the same service | missed, 39% | Current source/destination/protocol/port grouping combines the traffic |
| Composite background | beacon found; matching HTTP Host/DNS name can be confirmed | Exercises a direct hostname match alongside unrelated names sharing the answer IP |
| Composite without beacon HTTP Host | ambiguous; `DNS_IP_TIME_MATCH` | Same DNS records and timing as scenario 14, with beacon Host headers removed |
| TLS SNI matches DNS | high; `TLS_SNI_DNS_MATCH` | SNI selects one name from multiple DNS names sharing an IP |
| TLS without SNI | ambiguous; `DNS_IP_TIME_MATCH` | Multiple DNS candidates and no SNI |
| TLS SNI without DNS | high; `TLS_SNI_ONLY` | Reports the observed SNI without inventing a DNS association |
| TLS SNI conflicts with DNS | conflict; `TLS_SNI_DNS_CONFLICT` | Reports both sources without forcing an attribution |
| DNS CNAME chain to TLS SNI | high; `TLS_SNI_DNS_MATCH` | Follows CNAME → CNAME → A and applies the shortest TTL in the chain |
| Three-event capture | insufficient events | Minimum-observation behavior |

The same-service miss remains a useful follow-up case: the current grouping key
can merge independent applications that share a remote service. DNS-specific
beacon scoring is not implemented. DNS correlation checks client, connection
start, 5-tuple, and the DNS answer's TTL; multiple names sharing an IP can still
produce an ambiguous result. These are observed limitations of this
implementation, not flaws in the generated PCAPs.

The analyzer prints DNS query/response context before candidate scoring.
Recognized DNS packets no longer enter generic beacon scoring. A/AAAA answers
are correlated with connection starts from the same client to the answer IP
during the TTL window, using the TCP 5-tuple and observed HTTP Host/TLS SNI
when available. The result is labeled by evidence strength; DNS-specific
beacon scoring remains future work.

The composite fixture includes `beacon.example.test -> 93.184.216.34` before
the beacon's HTTP requests. Their observed `Host: beacon.example.test` header
produces `CONFIRMED`. Scenario 15 preserves the same DNS answers and timing but
removes that Host header; the connection should remain `AMBIGUOUS` with
`DNS_IP_TIME_MATCH`, rather than being attributed to an arbitrary DNS name.

TLS fixtures 16–19 cover matching SNI, missing SNI, missing DNS, and conflicting
SNI/DNS. SNI is visible in the TLS ClientHello unless ECH hides it. HTTPS
`Host` headers are encrypted and are not used as direct evidence from ordinary
packet captures.

Fixture 20 covers an answer-section CNAME chain ending in an A record, matching
the queried hostname and TLS SNI to the final address using the minimum TTL.
