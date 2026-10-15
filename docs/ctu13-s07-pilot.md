# CTU-13 Scenario 7 header pilot and Network Producer v1.1.0

Date: 2026-10-15, WSL2 Ubuntu. Baseline ML `2b23a50fa79a57af20ec98bd9a8748bbd4dfa825`;
SOC `d68d0a9e0682ad69d5751d20ffddbc11dc505b7b`. **PARTIAL**: acquisition verified,
offline producer and bounded parser tested; full archive verification, dataset admission,
retraining readiness and operational inference remain **BLOCKED**.

## Acquisition and file identity

User approved exactly two GET attempts, zero automatic retries, 300 seconds hard watchdog
per file, 256 MiB combined download and 512 MiB cumulative expansion. No new capture,
privileges, external test traffic, training or inference was performed.

Pinned URLs come from [the reviewed plan](raw-acquisition-download-plan.json):

- [Header archive](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/capture20110816-2.truncated.pcap.bz2)
- [Bidirectional labels](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/capture20110816-2.binetflow)

| File | Actual bytes | SHA256 | GET time |
|---|---:|---|---:|
| capture20110816-2.truncated.pcap.bz2 | 111664996 | `246e43ea206de437c1bf32fb07f865a8971c86dda0fd95e6597985d9f9c85577` | 35.3635 s |
| capture20110816-2.binetflow | 15630512 | `df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680` | 5.7372 s |

Total 127295508 bytes, matching the approved plan. Storage:
`data/raw/acquisition/ctu13-s07-header-pilot-v1`, private directory, raw files mode 0600.
Raw data, labels and generated JSONL are ignored by Git. Both originals remain intact.

Existing `ml.raw_acquisition.storage.fetch_reviewed_file` performed HTTPS streaming,
exact content-length/body-size checks, format-prefix checks, SHA256, no redirects/retries,
fsync and atomic no-clobber link finalization. An unprivileged parent ran each helper
in its own child with `subprocess.run(timeout=300)`; no timeout or partial-file cleanup
was needed. Actual PCAP MIME was `application/x-bzip2`; label MIME was absent and
remains UNKNOWN, accepted only with the reviewed missing-type exception and CSV header
validation. The plan's prior HEAD metadata was not re-represented as a new HEAD check.
ETags were not recorded during GET. No publisher SHA256 was available: these are local
content identities, not independently authenticated publisher checksums.

Source: [CTU-13](https://www.stratosphereips.org/datasets-ctu13),
[dataset overview / attribution](https://www.stratosphereips.org/datasets-overview).
The previous source review recorded CC-BY attribution; cite García et al. (2014),
“An empirical comparison of botnet detection methods.” Raw traffic is not redistributed.
No other dataset, botnet-only capture or executable was downloaded.

## Archive and format findings

The file has a bzip2 stream containing **PCAPNG**, despite its `.pcap.bz2` name.
The initial classic-only parser rejected it. A subsequent format-only prefix inspection
confirmed magic `0a0d0d0a`; the tested reader now supports classic PCAP and PCAPNG.
No files were extracted. Bzip2 has no member paths, symlinks, central directory or ZIP
member list; those checks are N/A. Existing ZIP safety tests still run.

Two 65536-byte preflight decompressions consumed 131072 bytes. The main inspection
therefore received only 536739840 bytes of remaining expansion budget. It stopped with
`ARCHIVE_EXPANSION_LIMIT`; only 536733893 decoded bytes were delivered to its reader.
The full uncompressed size, final bzip2 CRC/trailing-stream integrity, compression ratio
and full-session packet counts are UNKNOWN. Full archive integrity is **BLOCKED**.

**Boundary defect found:** the original bzip2 limiter decoded one rejected lookahead
byte to detect expansion overflow. Cumulative decoder output could therefore reach
536870913 bytes, one byte above the strict 512 MiB authorization. That byte was neither
yielded to the parser nor written. This strict decoder-total check is **FAILED for the
original execution**, not PASS. The limiter now stops before any over-budget decode;
a counting-decoder regression verifies that a 100-byte cap decodes exactly 100 bytes.
The corrected limiter has not been rerun on this corpus: no additional expansion was
performed or silently authorized. A fresh bounded verification needs a new byte budget.
The historical private receipt is preserved rather than rewritten.

## Actual partial-PCAP observations

All counts below describe the bounded **prefix**, not the complete Scenario 7 capture.
Inspection time: 172.2167 seconds. Recorded epoch interval:
`1313495484049047000` through `1313496536598790000` ns.
PCAPNG recorded timestamps are not a new live kernel timestamp attestation.

| Measurement | Observed |
|---|---:|
| Raw packet records | 6330279 |
| Parsed TCP/UDP packets | 6323107 |
| Captured length below original wire length | 6330225 |
| TCP / UDP | 4621747 / 1701360 |
| IPv4 / IPv6 parsed | 6323107 / 0 |
| Unsupported transport / fragments excluded | 7160 / 12 |
| Reconstructed flow segments | 152401 |
| Incomplete/resource-excluded flow segments | 142032 |
| Resource evictions / packet-limit closures | 139213 / 904 |
| Active / idle timeout closures | 323 / 10046 |
| Incomplete-at-limit closures | 1915 |

PCAPNG: little endian, Ethernet, microsecond timestamps, interface snaplen 262144.
The parser bounds block lengths/interfaces/snaplen, verifies repeated block lengths,
section byte order and interface identity, and rejects unsupported clock encodings,
unknown interface references, fragments and missing transport metadata. Payload
truncation is allowed only when all Network14 inputs remain observable. IP total length
is read from headers; it is not captured length and is not padded payload. IPv6 parsing
passed byte-fixture tests but is **not observed in the inspected real prefix**.

Flow keys are bidirectional endpoint pairs plus TCP/UDP, with source-file digest as
capture-session identity. First observed direction is not host inbound/outbound or
Argus initiator direction. Idle boundary is >=30 seconds, active >=120 seconds,
4096 packets/segment, 20000 active flows and 100000 buffered packets. Memory pressure
explicitly excludes flows, rather than calling them complete. Late packets are rejected.
Capture drops and pre-capture gaps remain UNKNOWN. Retransmissions are not deduplicated
merely because bytes match; record-index-bound event IDs distinguish packet observations.
The high eviction rate is a material limitation of this bounded pilot, not packet loss 0.

## Labels and binding

The actual ASCII CSV has 15 fields: StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr,
Dport, State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label. There are 114077 **flow-level**
records, not packet labels. Start times span 2011/08/16 13:51:24.049047 to 14:12:41.499668.

| Label inspection | Rows |
|---|---:|
| Supported From-Normal-V48 | 1668 |
| Supported From-Botnet-V48 | 63 |
| Background / other UNKNOWN | 110369 |
| Unsupported protocol | 1941 |
| Invalid TCP/UDP row | 36 |
| Duplicate parsed rows | 0 |

Anchored publisher labels are used; Background and To-Normal/To-Botnet do not become
binary benign/malicious truth. “From-Botnet” is dataset provenance, not proof that every
associated packet constitutes an attack. Invalid addresses/ports/durations are excluded.
The reader never uses model output or new feature values as labels.

The explicit UTC+02:00 CEST **hypothesis** is recorded, not optimized for match rate.
PCAP epochs and label wall-clock values are consistent with it, but independent Argus
clock configuration was not acquired within the two-file approval. Clock verification
therefore remains false. No offset tuning or time-overlap-only label assignment occurs.
Binding requires the same capture session, exact bidirectional five-tuple and complete
packet interval containment in exactly one external label interval. No widened tolerance
is added to compensate for rounded durations. Reversed tuples are allowed explicitly;
collisions and duplicates are ambiguous and excluded.

| Flow binding result | Prefix segments |
|---|---:|
| Unverified-clock unique NORMAL candidates | 237 |
| Unknown-label matches | 9813 |
| Unmatched | 319 |
| Ambiguous observed | 0 |
| Incomplete segments excluded before binding | 142032 |
| Independently verified matches / admitted samples | 0 / 0 |

Verified matched ratio = **0%**. Diagnostic candidate ratio = approximately **0.1555%**
(237/152401); it is not a training-admission rate. No BOTNET candidate was retained.
No flow is admitted for training. Correct clock provenance alone would not cure the
partial archive, high resource exclusions, direction/segmentation differences or holdout.

## Producer v1.1.0 and references

`ml.verified_producers.network_v1_1` adds a separate 1.1.0 producer;
v1.0.0 source and pinned golden evidence remain unchanged. Origins are explicitly
OFFLINE_PCAP, NATIVE_AF_PACKET and FIXTURE. Source-file/capture identity, origin,
ordered packet identities and quality bind the source and feature digests.
Declarations do not independently authenticate a native capture.

The Network14 mathematical contract remains version **1.0.0**, independently of the
producer version: duration, directional counts/IP bytes, IP-length min/max/mean/population
std, SYN/FIN/RST counts and consecutive IAT mean/max. Arithmetic uses binary64 with one
final float32 conversion; scaling NONE. Missing required inputs and known gaps are
rejected. Singleton IAT zero and UDP flag zero are definitions, not missing-value padding.

- Producer configuration SHA256: `7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7`
- Feature contract SHA256: `84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`

Three evidence classes stay separate:

1. **Synthetic arithmetic reference:** three explicit fixture packets, hand-derived
   population variance, compared with v1.0.0 and v1.1.0. This is not training parity.
2. **Actual PCAP-derived reference:** five observed packets, sanitized to relative
   times, IP lengths, forward/reverse and TCP flags. A separate 60-digit Decimal
   reference calculates all 14 features, including population variance/sqrt; final
   float32 values exactly agree. Source/feature hashes and expected values appear in
   [the sanitized evidence summary](ctu13-s07-evidence.json). This verifies arithmetic
   on observed metadata, not independent header parsing, full capture integrity or labels.
3. **Training-to-operational parity:** **BLOCKED**. No original legacy producer,
   independent matched operational pair or newly trained compatible model was established.

Reference tests reject altered feature order/values, configuration, origin, producer
version and source identity. Origins remain digest-bound, never promoted to authority.

## Pilot dataset and reproducibility

`pilot-candidates.jsonl` in the private raw acquisition directory has 237 diagnostic
rows, all NORMAL under the unverified clock. Every row carries
`training_admitted: false`, source/feature digests, external label reference and the
whole-capture split group. No raw addresses or payloads are exported into the report.
Its SHA256 is `89b789959772bca6548a4483aefc3adc5f82bcc2b138d9c7f1b01f1a11e2cc9d`.
The local `pilot-summary.json` original receipt is preserved; the committed sanitized
summary adds the independent reference and the boundary-defect disclosure.

**Dataset Admission BLOCKED; READY_FOR_RETRAINING BLOCKED.** No train/validation/test
split was fabricated from a single capture, and there is no independent holdout.
No model was trained, loaded for new inference or replaced. Old Network Quality,
Network Edge and DNS gates remain NOT_INFERABLE / BLOCKED / DIAGNOSTIC_ONLY / WRITE_DENIED.

Code entry point for a separately authorized fresh budget and fresh no-clobber output:

```bash
PYTHONPATH=src python -m ml.ctu13.pilot --root <private-approved-directory> \
  --expansion-budget-bytes <remaining-approved-bytes>
```

This is not permission to re-expand this archive under the already consumed budget.
Offline tests use tiny byte fixtures, never the ignored corpus or network. A rerun
against the current directory rejects existing derived output instead of overwriting.

## Security, tests and remaining work

No SOC source or runtime lock/governance boundary changes are needed. Existing Artifact
and v1.0.0 hashes are checked for preservation. New tests cover classic endian/resolution,
PCAPNG block tampering, unknown interfaces/clocks, IPv4/IPv6, TCP/UDP, truncation, fragments,
flow direction/timeouts/resource bounds, label collision/UNKNOWN/session mismatch,
source/config/reference forgery and the exact expansion boundary. Existing acquisition
regression covers redirect denial, no retry, timeout, SHA/size, archive traversal,
symlink, manifest tampering and split leakage. See final execution ledger below.

Next steps require new decisions: establish publisher/Argus clock and producer config;
obtain a separately approved expansion/streaming budget (full archive size remains unknown);
use bounded streaming aggregates after a reviewed producer-contract decision to avoid
buffer eviction; obtain independently labeled additional capture sessions and an external
holdout. Do not increase limits, infer Background truth, tune thresholds on this prefix
or claim legacy Top40/operational model compatibility. Physical Linux validation remains future work.

## Final execution ledger

Results are separate invocations and **must not be added together**:

| Invocation | Result |
|---|---|
| ML new CTU + existing acquisition/producer tests (working tree) | 199 passed; includes 67 CTU tests |
| ML broad producer/acquisition/scripts/three existing packages (working tree) | 395 passed, 6.49 s |
| ML broad regression from HEAD + only the 10 selected ML files | 395 passed, 4.19 s |
| SOC capture/monitor/operational/external/runtime/GUI/approval/execution/queue (working tree) | 768 passed, 291.95 s |
| Same SOC regression from clean HEAD export without user changes or Replay | 768 passed, 266.16 s |
| SOC Ruff check / whole-tree format check | PASS / 882 files already formatted |
| ML Ruff check src tests / selected Python files format check | PASS / 8 files already formatted |
| ML whole-tree format check | Existing debt: 24 files need formatting; unchanged and excluded |
| Both git diff --check | PASS |

The SOC test guard blocked one intentional test socket attempt per invocation;
no new native capture or test traffic was generated. Live LLM was disabled.
No tests require the downloaded archive. The actual-corpus results above are a separate,
partial, bounded inspection; fixture passes do not cure its failed decoder-total check,
missing EOF/clock provenance or independent holdout.

Independent exports use each baseline HEAD plus only selected task files, excluding
uncommitted Reliability Replay, the eight SOC user-modified files and the untracked
legacy DNS package. ML tests use existing ML dependencies and the existing SOC pytest
installation; source imports resolve from the exported src/packages directories.
No dependencies or environments were installed or changed. Export tests neither download
nor decompress actual raw data. All 1031 pre-existing SOC files and 464 unmodified ML
files matched the baseline SHA inventory; only the selected existing ML storage helper
changed. Seven legacy artifact/feature/label identities match their prior reviewed hashes.

Selected paths:

- ML: `src/ml/ctu13/{__init__,pcap,labels,flows,pilot}.py`
- ML: `src/ml/verified_producers/network_v1_1.py`
- ML: `src/ml/raw_acquisition/storage.py`
- ML: `tests/ctu13/test_offline.py`
- ML: `docs/ctu13-s07-pilot.md`, `docs/ctu13-s07-evidence.json`
- SOC: `docs/linux-soc-v1/ctu13-s07-operational-readiness.md`

No original PCAP/labels, generated dataset, model binary, Replay code or unrelated user
change belongs to these commits. Successful commit/export checks certify the tested
code and the accuracy of this partial report, not dataset admission or operational AI
readiness. The original one-byte decoder overrun is explicitly retained as a failed
sub-check; full real-corpus validation needs fresh authorization.
