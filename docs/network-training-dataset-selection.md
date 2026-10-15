# Final Network training dataset selection

2026-10-15, WSL2 Ubuntu. ML baseline `309d4836580682b8cb6589264ab3fc227965f0fb`;
SOC `37bff82a18b3f5aa0b1b15649df38467fce9768f`.

**Final acquisition selection: IoT-23, individual captures 8-1 / 20-1 / 34-1 —
ACQUISITION_READY. Network Quality and Network Edge retraining readiness: BLOCKED.**
This selects the next source dataset; it does not admit unacquired bytes or promise
that downloading them will satisfy the training gate. No model was trained and
no operational inference gate is changed.

Machine-readable plan, exact URLs, HEAD sizes, ETags, terms and pending split:
[network-training-download-plan.json](network-training-download-plan.json).
Its manifest digest binds the reviewed proposal, not download or training authority.

## 1. CTU-13 S07 final decision

The existing pilot, streaming report, label schema, official README and published
ra.conf findings were reviewed. There is no new independent label-export TZ/argv
record. No new S07 web investigation loop, raw acquisition or PCAP expansion was run.
The saved 237 diagnostic rows were read without decompression; their file SHA matches
`89b789959772bca6548a4483aefc3adc5f82bcc2b138d9c7f1b01f1a11e2cc9d`.
The old tuple matches are not counted as newly reproduced/verified matches.

```text
CTU13_S07:
  capture_timeline: CEST documented
  label_timezone: TIMEZONE_UNVERIFIED
  verified_matches: 0
  training_admission: BLOCKED
  role: PRODUCER_DIAGNOSTIC_ONLY
```

Capture CEST does not prove Argus export time or DST environment. Original session
identity and full-archive integrity remain separate checks; the prior bounded decode
was incomplete. Argus flow direction is not first-observed PCAP direction, labels are
flow-level, and Background / inbound-to labels are not automatically benign/malicious.
The source remains useful for arithmetic/parser diagnostics, not training admission.

## 2. Search order and final three-candidate comparison

Screening followed CTU-13 other captures, CIC-IDS2017, UNSW-NB15, then alternatives.
A bounded additional CTU sample (Scenario 1 / Capture-Botnet-42 published ra.conf)
has no RA_TZ. This is not an exhaustive claim about all CTU scenarios; no independent
export clock evidence was obtained, so other CTU captures were not shortlisted for
another same-problem acquisition cycle.

| Final shortlist | Raw / independent labels | Sessions and scope | Access / size / terms | Decision |
|---|---|---|---|---|
| CIC-IDS2017 | Publisher PCAPs plus tuple/time/protocol/attack CSV labels; actual binding not checked | Five capture days; normal and multiple attack types | Current official download leads to a registration form reporting server error; exact file bytes UNKNOWN. Publisher research/citation terms. Advertised daily sizes about 7.8–13 GB are not HEAD sizes. | BLOCKED |
| UNSW-NB15 | Publisher describes PCAP, GT.csv and LIST_EVENTS.csv; actual binding unverified | Current individual capture catalog and class distribution UNKNOWN; nine attack types reported | Official SharePoint requires Microsoft login. Reported 100 GB corpus is not an exact per-file size. Academic use/citation; commercial agreement required by publisher. | BLOCKED |
| IoT-23 | Paired original PCAP and analyst/Flaber-labeled Zeek conn.log.labeled, per source documentation | 23 captures reported; selected 3 distinct sessions/families. Actual class counts UNKNOWN until acquisition. | Six exact direct files HEAD 200, total 137251065 bytes. Dataset CC-BY-4.0; current publisher FAQ permits attributed reuse. Legacy per-capture notice retained below. | ACQUISITION_READY |

Sources: [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html),
[current CIC download form](https://cicresearch.ca/CICDataset/CIC-IDS-2017/),
[UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset),
[IoT-23](https://www.stratosphereips.org/datasets-iot23).
No registration details were submitted, authentication bypassed, mirror substituted,
malware binary fetched or raw packet/log body downloaded.

IoT-23 offers independent analyst labels and a documented raw/log association, unlike
trying to reconstruct an undocumented Argus wall-clock exporter. It is an IoT laboratory
domain, not representative proof for all Linux-server traffic. New Network14 models
will require separate identity and evaluation; these data do not validate legacy Top40.

## 3. Exact acquisition proposal

Official root:
`https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/`

| Session | Role / filename | Expected bytes from HEAD |
|---|---|---:|
| 8-1 | 2018-07-31-15-15-09-192.168.100.113.pcap | 2098362 |
| 8-1 | bro/conn.log.labeled | 1431000 |
| 20-1 | 2018-10-02-13-12-30-192.168.100.103.pcap | 4057401 |
| 20-1 | bro/conn.log.labeled | 419604 |
| 34-1 | 2018-12-21-15-50-14-192.168.1.195.pcap | 126317980 |
| 34-1 | bro/conn.log.labeled | 2926718 |
| Total | Six files, no full tar or additional capture | **137251065 (~130.89 MiB)** |

Each URL is exactly root + `CTU-IoT-Malware-Capture-<session>/` + listed relative
filename. All six URLs, not just concatenation guidance, are explicitly pinned in JSON.
HEAD requests read no bodies. PCAP MIME was application/vnd.tcpdump.pcap; label MIME
was absent and remains UNKNOWN. ETags are remote identity metadata, not SHA256.
Actual and publisher per-file SHA256 remain UNKNOWN until acquisition/independent proof.
The full Zenodo archive MD5 must not be reused as an individual-file checksum.

The small Capture 42-1 was screened but not selected: the publisher lists only six
non-benign flows. Capture 34-1 provides a less sparse test candidate. This decision used
public summaries before downloading or model fitting, not held-out model performance.

Proposed limits, **not yet authorized**:

- Exact six files above; total download budget **256 MiB (268435456 bytes)**.
- File hard watchdog **300 seconds**, **0 retries**, redirects denied pending review.
- Storage `data/raw/acquisition/iot23-network14-3sessions-v1/<capture>/...` in ML;
  directory not created. Separate paths preserve three identically named label files.
- No overwrite; private 0700 directories / 0600 files, existing symlink/path checks,
  temporary streaming files, cumulative byte counter, fsync and atomic no-clobber finalization.
- No archive is selected: **archive expansion budget 0**. A compressed or unexpected
  response must fail, not be transparently extracted. SHA256 computed on exact body bytes.
- Recheck size/ETag/type at execution; changed metadata is not silently accepted even
  when inside the global budget. No new dataset/file beyond this list is covered.
- No raw redistribution, packet replay, network capture, model training or inference.

**Transport compatibility gap:** current DownloadSpec/format-prefix validation can handle
reviewed classic PCAP but rejects `.log.labeled` and assumes Argus CSV for other label
suffixes. Tests explicitly preserve that denial. Before approved acquisition, add/test
only the narrow Zeek filename/header acceptance using the same bounded I/O. Do not rename
Zeek logs as `.binetflow`, skip prefixes or weaken the current source allowlist. Actual
PCAP magic/link type must also be checked; MIME alone cannot establish format support.
This task adds no network downloader and no format workaround.

## 4. Source, release and usage conditions

[Official IoT-23 page](https://www.stratosphereips.org/datasets-iot23) links individual
capture folders and describes manual analysis plus Flaber rules producing labels from
the paired PCAP's Zeek flows. [Zenodo record 4743746](https://zenodo.org/records/4743746),
API and JSON export identify dataset v1.0.0, open access and CC-BY-4.0.
[Publisher FAQ](https://www.stratosphereips.org/datasets-faq) states attributed reuse
does not require a separate permission request. Cite García, Parmisano & Erquiaga (2020),
IoT-23 v1.0.0, DOI 10.5281/zenodo.4743746.

Older individual READMEs still carry an authorization notice. That wording is retained
in the plan alongside the current dataset license/FAQ; it is not erased or interpreted
as a secret access credential. No contact message was sent. This proposal uses the
publisher's public dataset release/reuse basis and does not license raw redistribution.
If an institutional review needs clarification of the older notice, keep downstream
use blocked until resolved; user download approval does not manufacture publisher rights.

Individual files are mutable snapshots, not proven byte-identical to the frozen Zenodo
package. Capture 34-1 labels have Last-Modified 2023-12-11 while the published package
and summary are older. Version this proposal as `official-individual-HEAD-2026-10-15`;
retain ETags and hash every acquired file. Published class summaries must not be claimed
as measured distribution of the current objects. Metadata GET receipts/hashes in the plan
are metadata identities, never original PCAP SHA256s.

## 5. Producer v1.1.0 compatibility

The producer, Feature14 meaning/order/float32, first-observed direction, 30/120-second
segmentation, IP length, TCP flags, UNKNOWN capture quality and all digests remain intact.
Producer config digest:
`7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7`;
Feature contract:
`84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`.

Raw Ethernet IPv4/IPv6 TCP/UDP PCAP is structurally suitable for the observable inputs;
actual link type, header completeness, timestamp order, gaps/drops, unsupported packets
and segmentation remain **BLOCKED until bytes are checked**. Missing values are excluded,
not padded with zero. IP length is not captured frame length or Zeek application bytes.
No existing neural-model/scaler artifact is loaded or replaced for this selection.

[Zeek conn.log documentation](https://docs.zeek.org/en/current/reference/logs/conn.html)
and [TSV schema documentation](https://docs.zeek.org/en/current/tutorial/logs.html)
define epoch timestamps, original/responder endpoints, duration and per-direction
packet/IP counts. That avoids a wall-clock/DST search at the contract level, but actual
older/custom IoT-23 header fields/#types and label columns are not downloaded yet.
Do not assume fields added in modern Zeek exist in these old logs.

Proposed binding, not implemented/verified on new data in this step:

1. Pin capture ID + PCAP SHA + label SHA + original row/UID reference.
2. Read schema-delimited endpoint/protocol/epoch/duration fields exactly; convert decimal
   seconds to integer nanoseconds without choosing a timezone to improve match rate.
3. Match exact bidirectional tuple and the entire producer segment interval to one label
   interval in the same capture; record whether first observation is orig or resp.
4. Reject tuple/interval collisions, contradictory labels, missing duration, unsupported
   protocol, truncation or known gap. Use declared precision, not a tuned wide tolerance.
5. Use analyst labels only. Neither model output, detector finding, host infection alone
   nor the absence of a malicious match can generate the independent target label.
6. Keep every subsegment from one Zeek conversation/session in one group. No change in
   the Feature14 direction/timeout contract is made to imitate Zeek segmentation.

The old CTU Argus label parser/binder is not a Zeek parser. Implementing a narrowly
reviewed Zeek binding path after schema inspection is a prerequisite, not a claim that
all existing adapters already support this source. New raw-derived independent golden
pairs and admission remain NOT_RUN/BLOCKED; fixture arithmetic tests are separate.

## 6. Fixed proposed holdout before training

| Proposed partition | Entire session | Reported family | Public summary labels (not measured counts) |
|---|---|---|---|
| Train | CTU-IoT-Malware-Capture-8-1 | Hakai | Benign 2181, C&C 8222 |
| Validation | CTU-IoT-Malware-Capture-20-1 | Torii | Benign 3193, C&C-Torii 16 |
| Sealed Test | CTU-IoT-Malware-Capture-34-1 | Mirai | Benign 1923, C&C 6706, DDoS 14394, scan 122 |

This fixes intended groups before any fit or test-result inspection. Actual capture
start/end epochs and session identity must be verified from bytes, not filename/README
year strings. Device/host identities and campaign/sample relationships must be audited:
private IP differences do not prove independent hardware, and shared devices/campaigns
or duplicate raw records may force group merging. If that invalidates independent
partitions, remain BLOCKED and request a specific additional capture, not random-row split.

Checks after acquisition: session/day/campaign/host connected groups across partitions,
duplicate raw packets/flows/features, same conversation fragments, class coverage,
label leakage, and timestamps/UID/IP/session IDs excluded from model features. Fit any
scaler or class weighting on train only; use validation for thresholds; test only once
after fixing model choices. Sixteen reported validation positives imply substantial
uncertainty; report interval/group-aware limitations instead of claiming strong recall.
No separate external-source holdout is acquired, and IoT-to-Linux-server domain shift
remains unvalidated. No current split digest or independent holdout PASS is fabricated.

## 7. Gate and next action

| Gate | Current state |
|---|---|
| Exact official file endpoints / size / source documentation | Verified metadata, six HEAD 200 |
| Raw files / per-file SHA / archive or PCAP integrity | Not acquired / UNKNOWN |
| Label provenance / tuple+time binding | Documented mechanism; actual bytes NOT_VERIFIED |
| Timestamp / direction / capture quality | Specification reviewed; actual data BLOCKED |
| Producer / independent raw golden pair | Contract stable / NOT_RUN |
| Independent split / manifest admission | Proposed only / NOT_ADMITTED |
| Network Quality retraining | **BLOCKED** |
| Network Edge retraining | **BLOCKED** |
| Operational input / response | NOT_INFERABLE / WRITE_DENIED |

A small pure `raw_acquisition.selection.verify_selection_plan` validates the pending
metadata, reviewed file/budget identities and unchanged v1.1.0 contract. It refuses
rehashed declarations of approval, admission, acquired digests, trained-model readiness
or verified split claims. Existing v1.0.0 pending manifests are not widened. The function
opens no network/file output and grants no capability. It is not a new dataset platform.

Next action: obtain explicit user approval for the exact six-file/137251065-byte proposal
with 256 MiB cap, 300 seconds/file, zero retries and zero expansion. After safe transport
format support, acquire once, verify schema/identity/labels and construct golden pairs
using unchanged Producer v1.1.0. Only after dataset admission and holdout gates pass should
a separate training authorization be considered. New model IDs/artifacts and separate
Quality/Edge compute, latency/memory and accuracy evaluations will be planned then;
legacy Top40 accuracy cannot be compared as if the inputs/data were identical.

Full-stream S07 re-expansion, model training, artifact generation, operational inference,
privilege changes and OS/security responses are outside this step and were not performed.

## Fresh verification and selected commit scope

Results are separate invocations with overlapping tests; do not sum counts:

| Execution | Result |
|---|---|
| New pending dataset-selection tests | 42 passed |
| ML selection + CTU13 + raw acquisition + producer + scripts + three package suites | 478 passed, 4.99 s |
| Same ML suite from baseline HEAD + only selected files | 471 passed, 5.33 s |
| SOC capture/source/queue/runtime/provenance/external/GUI/approval/execution security suite | 768 passed, 244.48 s |
| Same SOC suite from independent baseline HEAD export | 768 passed, 226.94 s |
| Ruff src tests, both working trees and ML export | PASS |
| SOC whole-tree format | PASS, 885 files already formatted |
| ML selected Python format | PASS, 2 files already formatted |
| ML whole-tree format | Existing 24 files require formatting; not changed |
| Git diff whitespace and selected stage checks | PASS |

Seven ML working-tree tests come from the existing user-modified test_offline.py and
are excluded from this commit. Independent exports exclude the five existing ML user
source/test modifications, untracked legacy DNS package, eight SOC user-modified files
and all uncommitted Reliability Replay files. Imports/tests use exported source plus
existing local dependencies/pytest; no new dependency is installed. All 1033 pre-existing
SOC files and 480 pre-existing ML files matched their initial SHA inventory. Seven
legacy artifact/feature/label hashes match the earlier reviewed identities.

The SOC guard blocked one intentional test socket attempt per invocation. No new
capture, test traffic, live LLM, original-data decompression or raw dataset GET occurred.
Tiny fixture and mock-transport tests are distinct from unacquired IoT-23 bytes.

New tests check immutable-plan integrity, rehashed admission/approval/promotion denial,
source/file/path/size identities, timeout/retry budgets, explicit unsupported Zeek label
transport, whole-session split leakage, unchanged producer and fixture epoch/direction
arithmetic. Existing suites cover actual binding primitives, label conflicts/UNKNOWN,
archive/download safety, golden tampering, flow/time/gap/restart and security contracts.
They do not verify a new IoT-23 Raw-to-Label pair, golden pair, actual schema or holdout.
Those remain NOT_RUN/BLOCKED, not fixture PASS promoted to dataset evidence.

Selected files only:

- ML docs/network-training-dataset-selection.md
- ML docs/network-training-download-plan.json
- ML src/ml/raw_acquisition/selection.py
- ML tests/dataset_selection/test_network_selection.py
- SOC docs/linux-soc-v1/network-training-readiness.md

No raw packet/log/label file, large generated dataset, model artifact or unrelated user
change belongs to these commits. Source/stage SHA identities and independent exports
are checked before commit. Commit/push covers this selection/readiness assessment only;
it does not approve the proposed download or authorize later model training.
