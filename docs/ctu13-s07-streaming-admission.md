# CTU-13 streaming flow optimization and label admission

Date: 2026-10-15. Environment: WSL2 Ubuntu. ML baseline
`8567c623b61fd29b16627cc101e457b1a7b12f06`; SOC baseline
`ad2a56bd9e8cc43e3b4cebacd41eb1a994fdda17`. **PARTIAL**:
fixture memory reduction and contract preservation verified; actual-corpus
performance, full archive integrity, label-clock verification and admission blocked.
No training, new dataset acquisition, live capture or operational gate change occurred.

## Baseline and ownership

Prior [pilot report](ctu13-s07-pilot.md) and immutable
[evidence summary](ctu13-s07-evidence.json) were read as historical evidence.
Their old test counts are not new tests. Five pre-existing ML modifications are
preserved and excluded: `ctu13/{labels,pcap,pilot}.py`, `raw_acquisition/storage.py`,
`tests/ctu13/test_offline.py`. The untracked legacy DNS package is excluded.
Eight SOC user-modified tracked files and all existing untracked Replay/user files
are preserved. No producer or model artifact is modified.

## Historical real-prefix exclusions, separated

These are prior measured observations, not a newly decoded corpus or performance run:

| Historical closure | Segments | Interpretation |
|---|---:|---|
| RESOURCE_EVICTION | 139213 | State capacity forced closure; not a measured NIC drop |
| PACKET_LIMIT | 904 | Reached 4096-packet segment cap; not idle expiry |
| INCOMPLETE_CAPTURE | 1915 | Active state when bounded prefix ended |
| ACTIVE_TIMEOUT | 323 | Configured 120-second segment boundary |
| IDLE_TIMEOUT | 10046 | Configured 30-second idle boundary |
| Total | 152401 | Segments, not necessarily unique original Argus conversations |

The first three categories sum to 142032; they must not be interpreted as one cause.
The old RESOURCE_EVICTION counter did **not** record whether the active-flow count or
100000-packet buffer cap fired. That historical sub-breakdown is UNKNOWN; it cannot be
recovered from the aggregate or inferred by changing limits. Complete Packet objects
retain repeated endpoint/session metadata, and packet-count pressure remains possible
regardless of compact storage. No reduction in real-corpus evictions is claimed.

## Streaming implementation

Existing `Flows.add/finish` call sites and returned `Flow.packets/closure` are retained.
`_PacketState` stores one endpoint/session template per flow plus event IDs and an
integer array of timestamp, IP length and flags/direction. Flush reconstructs exactly
the original validated Packet records; the unchanged v1.1.0 producer computes features.
No online approximation of mean/std, packet length, IAT, direction or source digest is
introduced. Even the ninth TCP flag bit is preserved separately from direction.

Bounds remain: 20000 active flows, 100000 buffered packets, 4096 packets/segment,
idle >=30 seconds and active >=120 seconds. An additional default 64 MiB retained-state
charge budget is enforced. Charges cover retained templates/IDs/containers with a
conservative per-entry allowance; they are **not** an operating-system RSS limit.
Python allocator/interpreter overhead and transient Packet reconstruction are separate.
`finish()` still materializes a tuple of closed flows; its transient reconstruction
cost limits the measured memory gain and is a remaining optimization candidate.

Eviction remains deterministic: oldest last-observed flow first, stable insertion
ordering for equal times. `Flow.reason` separates MAX_ACTIVE_FLOWS,
MAX_BUFFERED_PACKETS and STATE_BYTE_BUDGET while preserving the existing
RESOURCE_EVICTION closure understood by the pilot. No silent deletion occurs.
Known gaps close active segments as CAPTURE_GAP; subsequent packets cannot bridge them.
Partial termination yields INCOMPLETE_CAPTURE. Capture identity is checked even after
idle expiry or a gap, late packets are refused, and duplicate IDs in an active flow
are refused before mutation. The stable flow digest permits existing consumer receipt
sets to detect duplicate delivery; the table itself is not a durable global receipt store.

The existing user-modified pilot was not edited or re-executed. Its normal Flows import
will select the new storage after merge, but a fresh real-corpus run remains blocked by
the exhausted expansion authorization. No new collector, queue or SOC framework exists.

## Fresh matched-condition fixture benchmark

Command (no raw files or sockets):

```bash
PYTHONPATH=src python benchmarks/ctu13_flow_benchmark.py
```

Baseline is the byte-pinned original `Flows` source from ML `8567c62`, retained only
as `benchmarks/fixtures/flows_8567c62.py`. Each variant runs in a fresh unprivileged
child with a 180-second timeout. Input is a lazily generated, deterministic FIXTURE:
500 bidirectional keys, 160 observations/key, 80000 packets. Both use the same 20000
active / 100000 packet budgets, timestamps, evaluation and producer. The candidate's
additional state charge bound is not hit. Baseline does not implement byte accounting.
No packet-drop or network-capture behavior is represented by this fixture.

| Measurement | Baseline | Candidate |
|---|---:|---:|
| Packets processed | 80000 | 80000 |
| Flow created / closed | 500 / 500 | 500 / 500 |
| Lifecycle-completed segments | 500 | 500 |
| Evicted / incomplete / excluded | 0 / 0 / 0 | 0 / 0 / 0 |
| Peak buffered packets | 80000 | 80000 |
| Peak RSS bytes (fresh process ru_maxrss) | 56811520 | 50499584 |
| Peak retained-state charge bytes | UNKNOWN (not implemented) | 26194072 |
| Processing seconds | 2.187857 | 3.214735 |
| Packets/second | 36565.46 | 24885.41 |
| Closed segments/second | 228.53 | 155.53 |

Peak RSS decreased **11.11%** in this run; elapsed time increased **46.94%**.
This is a memory/CPU tradeoff, not a throughput improvement or regression-gate PASS.
Packet reconstruction and validation are additional candidate work; exact CPU attribution
was not profiled. Both variants include the same input hashing and producer evaluation.
No operational strategy/model is promoted from these measurements. The offline flow
implementation uses compact storage; production SOC runtime/gates are untouched.

Input SHA256 (both): `abb379ae2b6770531da84afdb108e65c5056de82da1c1113d3599b8b466f25c6`.
Output/closure/Feature digest (both):
`ecd6e76eccc79229a0f5cfb92d26e3630f6c37389fee92368145228de3e1e6e7`.
Python 3.12.14, Linux x86_64, same host. One sequential run/variant is not a confidence
interval; scheduling/cache/CPU affinity were not controlled. No same-budget real-PCAP
comparison was possible, and no real traffic loss reduction is asserted.

## PCAPNG and expansion accounting

New raw downloads: **0**. New actual raw decompression: **0 bytes**. Existing approval
was already exhausted, including the historical rejected lookahead-byte defect. No new
allowance is inferred from this task. The two compressed/original file hashes were
rechecked with ordinary reads, without invoking bzip2, PCAP inspection or capture.

- PCAP archive: `246e43ea206de437c1bf32fb07f865a8971c86dda0fd95e6597985d9f9c85577`
- Labels: `df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680`

PCAPNG clock tests use only newly constructed tiny synthetic blocks (both endiannesses,
micro/nanosecond resolution), alongside existing truncation/interface/block regressions.
Whole-stream EOF/CRC, full packet totals, capture drop and gap remain UNKNOWN.
No FULL_STREAM_VERIFIED flag is issued. Current parser buffers a bounded block, capped
at 1 MiB, with at most a bounded header retained per Record; it does not retain payload.
The uncommitted parser rejects multiple interfaces; baseline HEAD lacks that additional
user fix. These changes are excluded rather than silently included. Multi-interface
source attestation remains outside this commit's validated readiness claim.

## Independent timezone and direction investigation

Primary documentation was read in this task; no raw dataset was downloaded:

- [Scenario 7 README](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/README.html)
  identifies the Aug 16 capture timeline in CEST and recommends bidirectional labels.
  It also contains an older Aug 10 narrative; those sections are not merged as one timeline.
- [Published ra.conf](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/ra.conf)
  declares microsecond formatted wall-clock output but has no RA_TZ setting.
- [Argus rarc manual](https://qosient.com/argus/man/man5/rarc.5.pdf) explains that TZ
  environment, RA_TZ and command overrides affect formatting. Capture CEST does not
  establish the label exporter's actual environment or command.
- [Published argus.conf](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/argus.conf)
  declares bidirectional classic five-tuples, a 3600-second flow status interval and
  bidirectional timestamps. Commented timeout defaults do not prove executed settings.

Conclusion: Capture timeline CEST is documented; **label export TIMEZONE_UNVERIFIED**.
UTC+02:00 remains the prior explicit hypothesis, not a best-match search result. DST
behavior is not inferred from the analyst's current local timezone. The published config
is documentation, not proof of an exact binary revision/argv used for these saved labels.

Argus direction and first-observed PCAP direction are separate concepts. Published
client documentation supports direction corrections; the initiator cannot be recovered
merely by sorting a five-tuple. No feature direction or label rule is changed. Background
and To-Normal/To-Botnet remain UNKNOWN rather than binary truth.

## Saved binding and admission recheck

`admission.inspect_saved` checks the committed summary digest, both original file hashes,
the saved JSONL digest, feature/source-origin/configuration identities and each external
label-row reference. Actual label file schema/counts are re-read; source data is not
rewritten. It revalidated **237 saved candidate rows**, all prior NORMAL candidates.
They lack the original per-flow endpoint/packet snapshot needed for a new independent
raw binding replay. This is candidate preservation validation, not a new tuple match.

The new read-only binding review reuses the existing matcher, validates exact flow
membership/producer inputs, and reports CANDIDATE_MATCH / AMBIGUOUS / UNMATCHED /
EXCLUDED. VERIFIED_MATCH is reserved and cannot be obtained from a caller's legacy
`clock_verified=True` declaration. Incomplete/gapped flows and unsupported directions
are excluded; duplicate/conflicting intervals remain ambiguous. No fake clock evidence
or human approval flag is introduced to manufacture admission.

| Admission condition | Current evidence |
|---|---|
| Original file identity | SHA256 matches; full archive decode integrity unknown |
| Label provenance | External file and row references checked |
| Label timezone verified | BLOCKED |
| New raw-flow binding verified | BLOCKED; saved candidates only |
| Producer contract | v1.0.0 and v1.1.0 unchanged; fixture equivalence passes |
| Capture quality | UNKNOWN / partial input |
| Group/session split | One capture session |
| Independent holdout feasible with current data | BLOCKED |

Candidate matches **237**; VERIFIED_MATCH **0**; admitted samples **0**.
Pilot Admission **BLOCKED**. No dataset is READY_FOR_RETRAINING. No operational model
inference, model artifact replacement, automatic promotion or response WRITE occurs.
The checked data and fresh measurements are in
[ctu13-s07-streaming-evidence.json](ctu13-s07-streaming-evidence.json).

## Recovery and next decision

A test terminates only its owned unprivileged fixture child before output, then replays
the immutable fixture in fresh children. Stable flow receipts match across restart.
No half-built state is called complete or persisted as a verified dataset. This proves
replay determinism and consumer duplicate-key usability, not durable in-memory state
recovery, exactly-once capture or resumption of a bzip2 stream. Real-corpus restart and
fresh validation need a new explicit expansion budget plus source-bound packet metadata.

Next decisions: review the CPU cost before wider use; consider a streaming consumer
flush API without changing feature arithmetic; collect an authoritative label-export
TZ/argv/revision record; authorize a new bounded corpus pass only with explicit accounting;
obtain independently labeled sessions/holdout. Do not tune timezones or silently increase
packet capacity to improve apparent match rates. Physical Linux validation is future work.

## Fresh verification ledger and selected scope

Each row is a separate execution; counts overlap and must not be added together.
No historical tests are substituted for these runs.

| Verification | Result |
|---|---|
| New streaming/binding/PCAPNG/admission/crash cases | 34 tests included in final suites |
| ML full related working-tree suite | 436 passed, 5.01 s |
| ML HEAD + selected files, independent export | 429 passed, 4.88 s |
| SOC runtime/capture/queue/GUI/governance/security suite | 768 passed, 307.15 s |
| Same SOC suite from independent HEAD export | 768 passed, 303.12 s |
| Independent export benchmark CLI | Same input/output digests, budgets, packets and closures |
| Final Ruff src tests, both repositories | PASS |
| ML independent export Ruff src tests benchmarks | PASS |
| SOC whole-tree format check | PASS, 884 files formatted |
| ML selected Python format check | PASS, 5 files formatted |
| ML whole-tree format check | 24 pre-existing files require formatting; excluded |
| Working/staged Git diff whitespace checks | PASS |

Seven extra ML working-tree tests come from the preserved user-modified test_offline.py;
they are excluded from this commit. Both baseline and selected export pass without
uncommitted parser/label/pilot/download fixes, legacy DNS sources or Reliability Replay.
The SOC guard blocked one intentional test socket per suite; no capture/traffic occurred.
Live LLM calls were disabled. No dependencies were installed.

The benchmark CLI was also executed from the independent export. That separate run used
56770560 / 50388992 peak RSS bytes and 1.957861 / 3.214428 seconds for baseline/candidate.
Its semantic digests match the primary run; timings are not averaged or represented as
identical. Tests include only owned fixture-child crash/exit and immutable replay, not
new privileged probes or real-corpus decompression.

Existing model/feature/label artifacts (seven reviewed hashes), both Producer source
versions and raw/candidate identities are unchanged. labels.py received an external
pairwise/import adjustment during this task; it was retained and excluded. Other
pre-existing user files were not overwritten. No index items predated this task.

Selected files for independent export and commit:

- ML src/ml/ctu13/flows.py
- ML src/ml/ctu13/admission.py
- ML benchmarks/ctu13_flow_benchmark.py
- ML benchmarks/fixtures/flows_8567c62.py (byte-pinned original baseline only)
- ML tests/ctu13/test_streaming.py
- ML docs/ctu13-s07-streaming-admission.md
- ML docs/ctu13-s07-streaming-evidence.json
- SOC docs/linux-soc-v1/ctu13-streaming-admission.md

Raw PCAP/labels and generated data are excluded. Successful source/test commits certify
fixture behavior and this BLOCKED admission assessment; they do not certify full-stream
integrity, label timezones, operational performance, producer parity or a new model.
