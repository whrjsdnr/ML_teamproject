# IoT-23 TCP binding recovery and holdout decision

2026-10-15, WSL2 Ubuntu. ML baseline `52a01ae6de0d6433d2e0825c69ec58fed1ffc3f7`;
SOC `d07a796b2923f4e7b83bd56568feba04e965cd0f`.

**Overall PARTIAL. Binding recovery verified for a narrow offline subset;
Network Quality and Network Edge retraining admission remain BLOCKED.**
No new raw download/capture, model training/inference, artifact replacement, Feature14
contract change, OS response or operational gate unlock occurred.
Analysis was bounded to the three existing files, one fixed recovery policy and two
metadata-only additional candidates. No parameter sweep, timezone search or open-ended
candidate exploration occurred. Historical reports and prior receipts remain intact.

## 1. Ownership and raw integrity

Both HEADs matched the supplied commits; indexes were empty. Every existing user/Replay
file was inventoried before changes. This task adds files only: no tracked source,
Producer v1.0/v1.1, collector, runtime, model/scaler or existing test was edited.

All six acquired PCAP/Zeek files were SHA256 rechecked against
[iot23-network-admission-evidence.json](iot23-network-admission-evidence.json).
Their total remains137251065 bytes; original local identities/sizes are repeated in
[iot23-binding-recovery-evidence.json](iot23-binding-recovery-evidence.json).
Local SHA is not a newly obtained publisher checksum. No archive expansion or raw payload
copy occurred. Seven reviewed legacy artifact/scaler/feature SHAs also remain unchanged.

## 2. Label distribution versus Flow results

| Capture | Zeek connections | Benign labels | Malicious labels | Existing Flow segments | Current VERIFIED | CANDIDATE | AMBIGUOUS | UNMATCHED | EXCLUDED |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8-1 | 10403 | 2181 | 8222 | 4237 | 4218 | 0 | 0 | 0 | 19 |
| 20-1 | 3209 | 3193 | 16 | 3921 | 2304 | 32 | 0 | 1 | 1584 |
| 34-1 | 23145 | 1923 | 21222 | 7848 | 4295 | 2336 | 0 | 4 | 1213 |

Unknown Zeek labels **0** in all three actual files; the raw malicious labels exist.
Therefore the original zero malicious verified train/validation rows was predominantly
an **association/segmentation problem**, not absence of source labels. Low validation
support remains a separate dataset-composition concern: its original label file has
only16 malicious connections. These counts are analyst labels, not model predictions
or independently observed proof of a completed attack.

| Session / fixed role | Before strict Benign / Malicious | After Benign / Malicious | Newly verified |
|---|---:|---:|---:|
| 8-1 / train |2162 /0|2162 /2056|2056|
| 20-1 / validation |2300 /0|2300 /4|4|
| 34-1 / sealed regression only |964 /902|981 /3314|2429|

10,817 Flow windows now have verified offline associations; **admitted training samples0**.
A Flow window is not one Zeek connection. After-result counts sum to the same 4237/3921/7848
original Flow populations. No existing VERIFIED_MATCH was demoted, changed to another
class or silently relabeled. Before counts were freshly reproduced on identical bytes,
code baseline, timeout policy and budgets, not copied as new test evidence.

## 3. Failure taxonomy and corrected TCP diagnosis

The previous `ZEEK_DURATION_DOES_NOT_CONTAIN_ALL_PACKETS` reason describes a failed
interval predicate, not a proven final-ACK cause. Raw byte inspection now shows:

- **8-1:** all 2056 malicious candidate windows had unequal Zeek/Flow counters.
  A typical unchanged six-packet Flow contains the same SYN sequence at offsets
  0,1.071384,3.151458,7.231378,15.791510,32.431525 seconds. Its external labels
  describe **four** connections: first3 SYNs (180 IP bytes), then three separately
  recorded singleton SYNs (60 IP bytes each). The original Flow totals6/360bytes.
  Matching only its first label as one connection necessarily fails.
- **20-1:** four SYN-only windows are recovered. One remaining malicious candidate
  fails the narrow rule;707 malicious segments remain excluded for external missed-byte
  capture-quality failures (706 active-timeout segments plus one end segment).
  Benign exclusions877 missing-duration windows and31 partial-counter candidates remain.
  No quality flag or counter error is discarded to obtain the fourth positive.
- **34-1:** the frozen rule is applied only after source/policy lock, as regression.
  No test result was used to revise the rule or select a model/split/threshold.

[Zeek's connection contract](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)
explains first-packet time and directional IP counters. Its TCP duration can omit trailing
nonproductive packets. [Current TCP timer definitions](https://docs.zeek.org/en/current/scripts/base/init-bare.zeek.html#id-tcp_attempt_delay)
include a SYN attempt timeout. The historical build/config is UNKNOWN; **no current
default timeout is assumed to be the captured export's configuration**. Actual recovery
uses the external records and exact byte counters, not a guessed timeout value.

## 4. Fixed recovery policy and cardinality

Existing `zeek.bind`, `Flows`, `PcapReader`, Producer and default `inspect` remain
unchanged. The explicit offline `ml.iot23.binding_audit` runner records strict baseline
and candidate side by side; it does not silently replace the existing admission path.

`iot23-exact-syn-partition:v1` accepts a new association only when:

1. The original Flow is complete under existing lifecycle rules; no gap/resource/packet
   eviction is promoted. Source SHA/session, ordering and unique packet IDs are verified.
2. A separate byte decoder confirms every original packet's timestamp, endpoint/transport,
   IP size and flags. Every packet is complete, flags exactly SYN, ACK number0, no TCP
   payload, one orientation and one unchanged sequence number. Sequence change/reuse,
   ACK-only, FIN/RST, SYN+ACK, payload or truncation cannot pass this recovery rule.
3. Every packet belongs to exactly one external tuple/session/time record. For an actual
   missing duration, **only a singleton at exactly its ts**, with exact one-packet/byte
   counters, is considered; no duration0/end time is synthesized. Non-singleton intervals
   require exact start and final packet time, with zero tolerance/clock shift.
4. Each record's orig/resp packet counts and IP byte totals agree exactly; missed_bytes0,
   distinct references/UIDs, known label and concordant detailed labels are required.
5. The partition is disjoint and exhaustive: no dropped packet, duplicated reference,
   unknown member or conflicting class. Multiple labels are retained explicitly as
   `N_ZEEK_CONNECTIONS_TO_1_UNCHANGED_PRODUCER_FLOW`, never reported as 1:1.
6. Cross-Flow reuse of a verified external label or packet reference fails the audit.

No retransmission is removed or deduplicated from Feature14. No ambiguity is resolved
by choosing the attack label. SYN sequence/payload repetition is a byte-level observation,
not proof of sender intent or a completed C&C exchange. Zeek UID remains an external
row reference; it is never claimed observed/reconstructed directly in PCAP.

Policy digest `304e76f801004bc4a5b372cb3dc088d3dc090ab1da3ebede8b2915dfdbaad893`.
Source/policy lock `cf6cba6aa1af76b5fafe8d2d6ee3d8d80e29b3286b9528d99f9e947640a17f7c`, created before the sealed run, records
three owned-module SHAs and the train/validation audit digest. Sealed CLI refuses a
missing/altered lock or changed code. This is a local reproducibility lock, not signed
human authorization or a new security permission.

## 5. Independent references and representative samples

`wire_reference.py` independently reads classic-PCAP framing, IP/TCP/UDP fields,
sequence/ACK, flags and payload length/hash; it does **not** call the production packet
parser, Flow builder, producer or binding function. Full stream SHA matches the same
approved source. No payload content or absolute TCP sequence number is stored in reports.
A second **row-first counter table** works from decoded wire records, independently of
the production-Packet grouping; overlapping/missing coverage or unequal counters fails.

The six-packet actual8-1 reference independently yields per-label counters
`[3,180,0,0]`, `[1,60,0,0]`, `[1,60,0,0]`, `[1,60,0,0]`, identical to the external rows.
A five-packet20-1 reference yields `[3,180,0,0]`, `[1,60,0,0]`, `[1,60,0,0]`.
All raw packet indices, relative times, lengths, flags, reference hashes, counter tables
and proof digests are retained in the sanitized evidence.

| Requested reference category | Actual evidence scope |
|---|---|
| Normal TCP / UDP | Present in existing train/validation captures; strict bindings preserved |
| Malicious TCP | Source-labeled SYN-only associations with exact independent partitions |
| ACK-only / FIN / RST | Present in20-1, also sealed regression; no new SYN-rule promotion |
| Retransmission | Same directional sequence/flags/payload hash repeats observed; retained in counts |
| Sequence-changing connection reuse | Not observed inside these replayed Flow windows; explicit fixture coverage only |
| Ambiguous overlapping labels | Actual count0; explicit conflicting/overlap fixtures only |

Same binding run twice is used only for determinism, **not independent proof**.
Neither separate parsing nor this narrow partition proves historical Zeek configuration,
full TCP reassembly, packet delivery completeness or general operational Producer parity.

## 6. Holdout redesign decision

The fixed train8-1 /validation20-1 /test34-1 roles are unchanged. Test34-1 remains
sealed for regression only; it is never moved into training or used for model/policy
selection, feature selection or threshold fitting. No model was trained at all.

Train/validation class-presence gates now both PASS, but4 validation positives are only
SYN-attempt windows from one capture/family. No arbitrary minimum sample threshold is
invented as a substitute for statistical support. They do not establish reliability
on Torii application traffic or a broad independent evaluation population.

Fresh official metadata reports validation `RPi-01`, test `RPi02`; train8-1 has no unique
physical device ID in its README. Different private IPs/family names are not proof of
independent hardware or campaigns. Original observation includes one train/validation
origin-address hash overlap; it is retained, not normalized away.
Capture drop/gap metadata remains UNKNOWN; label missed_bytes0 is not an assurance of
all loss-free observations. Thus Holdout Independence and Capture Quality do not PASS.

Admission: raw/local integrity PASS; label provenance documented; verified association
PASS for the stated subset; unchanged Producer/Golden arithmetic contracts PASS;
Train/Validation class presence PASS; manifest integrity PASS;
**Holdout Independence UNVERIFIED, Capture Quality UNKNOWN, Admission BLOCKED**.
Both models remain BLOCKED; diagnostic verified windows are not admitted training samples.

## 7. Additional capture candidates (metadata only, no acquisition)

The search is limited to **two** candidates from the
[official IoT-23 catalog](https://www.stratosphereips.org/datasets-iot23).
Only directory metadata, four HEAD responses and two bounded README bodies were read;
three existing-capture READMEs were also checked. **New PCAP/label body bytes0**.
Exact URLs, HTTP200, Content-Length, ETags, modification dates and README hashes are in
the evidence. No `test.pcap`, malware archive, mirror or additional source was fetched.

| Candidate | Publisher labels (not verified samples) | HEAD sizes | Decision |
|---|---|---:|---|
| 3-1, Muhstik |Benign4536; Attack5962; C&C8; scan145597|PCAP57919772 +labels24383537 = **82303309bytes (~78.49MiB)**|Preferred future acquisition candidate, **not ADMITTED** |
| 60-1, Gafgyt (catalog spells Gagfyt) |Benign2476; heartbeat95; DDoS3578457|PCAP22028429274 +labels467559811 = **22495989085bytes (~20.95GiB)**|BLOCKED for next bounded stage |

3-1 exact files: `2018-05-21_capture.pcap` and `bro/conn.log.labeled` under
[its official directory](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/).
The README mentions an RPi and a distinct reported malware sample; physical identity
is still unknown. Actual link/clock/schema/quality and feature compatibility remain
unverified until separately approved acquisition. 156103 reported label rows and
24.4MB label size fit current row/file bounds, but that is not a format/binding PASS.
Its May2018 capture predates current training: a later redesign must account for
chronology (e.g. training expansion), not call it an independent later validation day.
The listed small `test.pcap` is not a substitute for the publisher's original PCAP.

60-1 reports `RPi-02`, a potential alias of test34-1's `RPi02`; conservatively group
these until independent device evidence says otherwise. Its PCAP exceeds current8GiB
transport/256MiB reference bounds and labels exceed32MiB/250k-row bounds.
It needs a different expressly reviewed storage/streaming/resource plan and does not
solve independence merely by having many malicious rows. No limits are increased here.
Older per-capture authorization wording/current dataset-level terms remain subject to
the prior documented licensing review; download approval would not grant publisher rights.

No new split is admitted or executed, and no new download approval is requested as a
prerequisite to finishing this bounded audit. A later acquisition stage needs a separate
explicit request for the pinned files/bytes; existing six-file approval is not reused.

## 8. Producer, security and regression

Network v1.1.0 remains OFFLINE_PCAP /14 ordered float32 features; identical original
packet sequences yield identical source/feature digests and values. Neither30s idle,
120s active,4096-packet cap nor Feature14 meaning/order/dtype/config changed.
Existing synthetic/actual arithmetic pairs are reused; native/offline parity remains
NOT_VERIFIED, not inferred from offline association recovery.
No old Top40/Edge/DNS artifact is connected to Network14 or overwritten.
`NOT_INFERABLE`, inference/Finding promotion BLOCKED, DIAGNOSTIC_ONLY and WRITE_DENIED
remain. Syntheticv2, OperationalProvenancev3, Policy/Approval/Execution are unchanged.

Fresh focused IoT23 tests: **100 passed** (includes43 new recovery tests, not summed).
ML broad working regression: **578 passed** (7.36s). Independent baseline+owned-files
Export: **571 passed** (6.18s); seven existing user CTU tests account for the difference.
The full saved-byte train/validation and sealed audits from the independent Export are
**exactly identical**, including policy locks, counts and proof/record/manifest digests.
No uncommitted Replay/user code or raw files copied into the export were required.
SOC fresh working regression: **768 passed** (271.88s); independent SOC Export:
**768 passed** (267.75s). Each guarded run blocked one intentional fixture socket
attempt; no new capture/test traffic was generated.

New tests cover exact cardinality, independent byte/reference counters, malicious labels,
missing duration points, SYN/ACK/FIN/RST/data rejection, sequence changes, retransmission
counts, timestamp +/-1ns, direction/source mismatch, overlapping/conflicting labels,
UID/reference duplicates, gaps/limits, sealed-source locks, test leakage and fail-closed
admission. Actual absence of reuse/ambiguity is not concealed with fixture claims.

Ruff src/tests PASS, owned Python formatting PASS; whole ML format has24 pre-existing
violations, untouched. Git diff/stage checks and tested/export/staged SHAs are verified.

## 9. Reproduction and next decision

With the existing ignored six-file root, ordinary user privileges only:

```bash
PYTHONPATH=src .venv/bin/python -m ml.iot23.binding_audit \
  --root data/raw/acquisition/iot23-network14-3sessions-v1 \
  --output data/raw/acquisition/iot23-network14-3sessions-v1/new-trainval-audit.json

PYTHONPATH=src .venv/bin/python -m ml.iot23.binding_audit \
  --root data/raw/acquisition/iot23-network14-3sessions-v1 \
  --sealed-test --policy-lock docs/iot23-binding-recovery-policy-lock.json \
  --output data/raw/acquisition/iot23-network14-3sessions-v1/new-sealed-regression.json
```

Outputs are no-clobber sanitized summaries; neither command opens a network socket,
fits a model, modifies evidence, issues response authority or unlocks admission.
Source/policy lock is [iot23-binding-recovery-policy-lock.json](iot23-binding-recovery-policy-lock.json).

Next decision: stop further timer/tolerance experiments. Seek independently reviewed
host/campaign/capture-quality metadata and, if additional data is approved, prioritize
3-1's exact original PCAP+labels for bounded provenance/compatibility checks. Then define
a new explicit whole-session chronology/class/group plan while keeping34-1 sealed.
No READY claim or retraining is justified by this recovery alone.

## Changed files

- `src/ml/iot23/wire_reference.py`
- `src/ml/iot23/recovery.py`
- `src/ml/iot23/binding_audit.py`
- `tests/iot23/test_recovery.py`
- `docs/iot23-binding-recovery.md`
- `docs/iot23-binding-recovery-evidence.json`
- `docs/iot23-binding-recovery-policy-lock.json`

SOC change: `docs/linux-soc-v1/iot23-holdout-readiness.md` only.
