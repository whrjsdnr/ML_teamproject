# IoT-23 Capture 3-1 validation admission

2026-10-15, WSL2 Ubuntu. ML baseline `484f9ac62b6d597113ebf44016410100a81a2f76`;
SOC baseline `78e1f8798fa3573f0623add902441691d235c006`.

**Overall PARTIAL. Download PASS; raw/label binding PARTIAL (verified subset);
Producer compatibility PASS; Independent Validation BLOCKED;
Network Quality BLOCKED; Network Edge BLOCKED. Admitted training samples: 0.**

No model training, existing artifact replacement, native model inference, OS capture,
OS security response or operational gate unlock was performed. Binding, Feature14 and
all pre-existing tracked/untracked files are unchanged; this task adds files only.

## 1. Approved download and exact identities

The two original URLs were taken from the previous committed metadata, confirmed by
fresh HEAD and the [official file index](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/).
The separate small `test.pcap` is not the original and was not downloaded.
The fixed [download plan](iot23-capture3-download-plan.json) pins both URLs, filenames,
sizes and private destination `data/raw/acquisition/iot23-capture-3-1-muhstik-v1/`.
Its digest is `6864df68808a1d8e5891dff64d7ef606f849548783261b3e4fe142170097dc1b`.

Exactly two GET transfers completed, **82303309 bytes** total, within the256MiB cap.
Each used the existing bounded transfer, HTTPS, redirect denial, exact Content-Length,
stream SHA256, no-clobber atomic publication, partial cleanup, <=10s socket timeout
and <=300s parent watchdog including process startup. Automatic retries0; expansion0.
No original file was overwritten, no mirror/extra capture/archive was fetched.
Both HTTP statuses200; MIME PCAP `application/vnd.tcpdump.pcap`, label absent/UNKNOWN
explicitly allowed with the existing strict Zeek prefix check.

| File | Expected = actual bytes | Local SHA256 | Transfer seconds |
|---|---:|---|---:|
| 2018-05-21_capture.pcap | 57919772 | `c674dc0c8d584fa66e6f00c60df973c5fbacad551c850a76d75ec9952641d00b` | 21.757 |
| conn.log.labeled | 24383537 | `9851009bbca03e15089fa1a356dd4b5eee4a98161a51703626058a0b507f50d0` | 5.493 |

Per-file URLs and acquisition timestamps are in
[iot23-capture3-validation-evidence.json](iot23-capture3-validation-evidence.json).
Publisher per-file SHA256 is UNKNOWN: these are computed local integrity values,
not signed publisher hashes. A second body request/retry was not used for verification.
Raw files have0600 modes under private0700 directories and remain Git-ignored.
The acquisition receipt is inside that private root; no credential or packet payload
is copied into repository documentation.

## 2. Actual raw PCAP

Full **classic PCAP2.4, little-endian, Ethernet link1, microsecond resolution,
snaplen262144** stream; entire57919772bytes hashed during parsing equals the receipt.
**496959 raw packets**, **489567 parsed IPv4 TCP/UDP packets**:
TCP488060 /UDP1507. Actual IPv6 observed0. Other link protocols5658 and unsupported
transport1734 are excluded by the existing parser. No missing protocol fields are invented.
Observed snaplen truncation0; this is not proof of original loss-free collection.

The unchanged Flow builder yields **86378 segments**: idle-timeout86372,
active-timeout1, capture-end5, resource eviction0, packet-limit0, marked-gap0.
A capture-end closure does not prove the original network connection is complete;
strict label counters/intervals still determine association. Original capture drop/gap
provenance remains **UNKNOWN**, not zero.

Actual PCAP and label epoch ranges agree:
**2018-05-19 18:57:19.958006 UTC through2018-05-21 07:04:47.960915 UTC**.
The filename's May21 date is not treated as the entire capture period.
No timezone/DST shift or time-tolerance sweep occurred.

## 3. Actual Zeek schema and label provenance

The unchanged parser validates the observed23-column extended Zeek TSV:
original columns through `tunnel_parents`, then triple-space `label` /`detailed-label`.
`#types` declares `ts=time`, `duration=interval`, IP addresses/ports, directional
packet/IP-byte counts and string labels. UID is an external connection reference;
no UID is claimed independently observed/reconstructed from PCAP.

**156103 label connections**: Benign4536, Malicious151567, Unknown0.
Detailed malicious labels: horizontal scan145597, Attack5962, C&C8.
Protocol rows: TCP154158 /UDP738 /ICMP1207. All-label counts include ICMP; only TCP/UDP
are eligible for the current Network14 input. Label connections and producer Flow
segments are different units and are never summed or treated as one-to-one.

An independent full-row/UID-set scan of all protocols found duplicate full rows0 and
duplicate UIDs0. Unset/empty duration, orig_bytes and resp_bytes each occur73944 times;
service150195, history1207, local_orig/local_resp/tunnel_parents156103 each.
`detailed-label=-` on4536 benign records is not a missing benign class label.
Dashes are not converted into normal class, zero duration, zero bytes or missing features.
The row-quality counts are explicitly raw inspection diagnostics, separate from binding.

[Publisher provenance](https://www.stratosphereips.org/datasets-iot23) describes
analyst/Flaber annotations on Zeek logs generated from the original PCAP.
Those external labels are independent of the future model and the new producer,
but are not claimed infallible attack ground truth or observed completed attacks.
Attribution: García, Parmisano, Erquiaga (2020), IoT-23v1.0.0,
DOI10.5281/zenodo.4743746. Existing dataset-level/legacy per-capture terms review is
retained; raw data are not redistributed and download permission is not a new license.

## 4. Frozen binding recovery, without tuning

The prior policy lock was checked before applying Capture3:
`cf6cba6aa1af76b5fafe8d2d6ee3d8d80e29b3286b9528d99f9e947640a17f7c`.
The bytes of `recovery.py`, `wire_reference.py`, `binding_audit.py` remain identical.
Policy digest `304e76f801004bc4a5b372cb3dc088d3dc090ab1da3ebede8b2915dfdbaad893`.
No changes were made to the PCAP/Zeek parser or Flow/Producer contracts.

The exact SYN-only partition rule is reused: independent byte decoder agrees with
production metadata, same sequence/orientation, zero ACK/payload, complete packets,
exact clock/counters, disjoint exhaustive external row partitions, concordant labels,
unique references. Missing duration is only an exact independently counted singleton;
no end time is imputed. ACK-only/FIN/RST/data, sequence reuse, ambiguity, quality/counter
mismatch do not gain a new promotion path. Retransmissions remain counted in features.

| Status / Flow unit | Baseline strict | Frozen recovery |
|---|---:|---:|
| VERIFIED_MATCH |3386|76320|
| CANDIDATE_MATCH |82210|10044|
| AMBIGUOUS |0|0|
| UNMATCHED |1|1|
| EXCLUDED |781|13|
| Total |86378|86378|

All 3386 old verified associations are preserved. Newly verified **72934** are malicious
source-label associations. Exact two-Zeek-records-to-one-unchanged-Flow mappings72166;
exact singleton-record mappings768. All reference IDs and proof/cardinality are retained;
many-to-one is never reported as one-to-one. No packet or retransmission is removed.
Cross-Flow reuse of a verified label/packet reference fails the unchanged audit.

## 5. Class distribution and remaining exclusions

| Reconstructed Flow classification | Count |
|---|---:|
| Verified Benign |**2927**|
| Verified Malicious |**73393**|
| Candidate Benign |539|
| Candidate Malicious |**9505**|
| Ambiguous Malicious |**0**|
| Excluded Benign |13|
| Excluded Malicious |**0**|
| Unmatched / unknown association |1|

These exclusion counts are Flow-state counts, **not** a claim that no malicious packet
was excluded by the parser or that every source connection was recovered.
Malicious candidates:3533 partial/counter mismatches and5972 duration non-containment;
benign candidates470 /69 for the same two categories. Thirteen benign missing-duration
windows remain excluded by the existing rule. No additional tolerance or label guess
was introduced to increase coverage.

Class coverage exists, but verified candidates are about96% malicious, mostly scanning
SYN windows; train8-1's class proportions/traffic differ. This laboratory distribution
is not an operating Linux-server base rate. No precision/recall/F1 or superiority over
legacy models is claimed; no model or threshold was fitted.

## 6. Producer compatibility and new reference samples

Existing Network Producer **v1.1.0**,14 ordered IEEE754 float32 values,
**OFFLINE_PCAP**,30s idle/120s active/4096-packet window contract unchanged.
**76320 actual feature vectors** were produced and checked for exact names/order,
finite values, representable float32, Source/Config/Feature digests. No imputation,
scaler fitting, feature selection or mapping into legacy Top40 models occurred.

Config digest `7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7`;
feature contract digest `84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`.
Source Origin is never relabeled NATIVE_AF_PACKET or FIXTURE.

Golden evidence is distinguished:

1. Existing synthetic and earlier actual arithmetic Golden Pairs remain unchanged.
2. **New actual Capture3 reference pairs:** a9-packet Benign flow and4-packet Malicious
   source-labeled flow, compared with separate two-pass mean/population-standard-deviation
   and counter arithmetic, final float32 (rel1e-6/abs1e-7). Raw/source/feature/config
   digests and numeric reference vectors are in evidence. The four-SYN sample independently
   yields240 forward IP bytes, four SYNs and zero reverse packets/bytes.
3. Training-to-native operational parity is **NOT_VERIFIED**. No new AF_PACKET capture
   or existing model inference was run; future model artifact binding is NONE.

The measured full validation run took157.23s, peak RSS1055632KiB (~1030.9MiB) under a
3GiB virtual-address-space bound applied only to its owned analysis process.
This is resource observation, not a baseline/candidate performance benchmark.

## 7. Independent validation and holdout admission

Fixed roles remain **train8-1, validation candidate3-1, diagnostic20-1,
test34-1 SEALED**. No reassignment or random row split occurs.

- Fresh train8/diagnostic20 audit exactly reproduces the previous frozen audit digest
  `bd5795f81a50e86035f2f43de0bee3e824dac74897ab6ca338ffb212533185cd`. Train classes2162 Benign /2056 Malicious.
- Train8 and candidate3 have **zero exact raw-flow fingerprint intersections** and
  **zero observed origin-address hash intersections** in fresh comparisons.
  Fingerprints include absolute epoch/endpoints; these checks cannot rule out retimed
  copies, reused physical hosts or common malware infrastructure.
- Time intervals do not overlap. However **candidate May19–21 predates train July31–Aug1**.
  The existing forward-time split contract therefore fails for this proposed ordering.
  Retrospective cross-campaign validation is a different protocol; it is not silently
  substituted for the established chronological gate.
- Unique physical device identity is unresolved for both3-1 and8-1. Different private
  addresses/capture names do not prove independent hardware. Different Muhstik/Hakai
  family annotations do not establish independent campaigns. Source-group leakage
  remains UNVERIFIED despite the zero exact/address intersections.
- Absolute timestamps, addresses, labels, UID and session identifiers are metadata,
  not any of the14 model values; direct feature-column label leakage is absent.
  This does not establish all source/campaign independence.
- Capture loss/drop/gap provenance is UNKNOWN. Exact label counter agreement cannot
  prove packets that were never captured. Class presence alone cannot override it.

Raw/local integrity PASS; published label provenance documented; binding PASS for the
verified subset; Producer contract/reference arithmetic PASS; class presence train/val
PASS; manifest integrity PASS. **Holdout Independence UNVERIFIED, forward chronology
FAIL, Capture Quality UNKNOWN. Independent Validation BLOCKED.**
Network Quality and Network Edge each remain **BLOCKED**, admitted samples **0**.
No new model artifact/runtime performance approval is implied by shared data compatibility.

## 8. Test34 preservation and SOC boundaries

Existing six raw files are byte-hash verified unchanged. Test34 was **not parsed again**
by this validation runner, included in model/rule selection or moved into training.
Only train8 and diagnostic20 are freshly re-audited; test metadata/source bytes are
checked without changing the previous sealed result or policy lock.

No SOC source, collector, queue, Source Store, GUI or inference framework is changed.
Network Quality/Edge/DNS keep **NOT_INFERABLE / inference and Finding promotion BLOCKED /
DIAGNOSTIC_ONLY / WRITE_DENIED**. No legacy model accepts Network14 merely because
features/binding were verified. Seven reviewed artifact/scaler/feature SHA identities
were rechecked unchanged. Syntheticv2, OperationalProvenancev3 and Policy/Approval/
Execution contracts remain intact. No physical Linux-server validation is claimed.

## 9. Tests, independent Export and quality

Fresh focused IoT23 tests **119 passed**, including19 new Capture3 tests (not added to
broad totals). ML working regression **597 passed** (9.02s); independent baseline+owned
files Export **590 passed** (7.87s). The difference is seven pre-existing user CTU tests,
deliberately excluded from this commit. Both are complete separate runs, not a summed count.

The independent Export excludes all user/Replay/legacy-untracked package code. Its
full saved-byte validation uses only the approved external raw directories (no raw data
copied into Git/Export) and reproduces **identical complete Manifest, source/feature,
reference and binding digests**, including the old train/diagnostic audit.
Validation Manifest `4b35479d6d16959566347eca5f04e19e5d43b0180d807bab988bd4aeab539e70`.

SOC working regression: **768 passed** (289.61s); independent SOC Export:
**768 passed** (276.31s). Each guarded run blocked one intentional fixture socket
attempt and created no native capture/test traffic. Tests include existing
capture/source/provenance/runtime/gate, approval/execution and GUI safety regressions,
with live LLM disabled and new AF_PACKET/IPv4/IPv6 sockets denied by the test guard.
New tests cover pinned URLs/bytes, budgets/timeout/no retry/no clobber, rehashed scope/
path/receipt forgery, fixed Test role, class/chronology/group uncertainty and fail-closed
admission. Existing download/parser/label/feature/tamper tests were also rerun.

Ruff src/tests PASS; owned Python Format PASS. ML whole Format remains 24 pre-existing
violations, not modified. Diff/staged checks and tested/export/staged SHA comparisons
precede commit. Existing user/Replay files, artifacts and all raw sources are preserved.

## 10. Reproduction and next decision

Do not rerun acquisition: its CLI refuses a previously started destination. The exact
approved two-file plan/receipt is a historical download authorization, not training permission.
Read-only revalidation with a new output name:

```bash
PYTHONPATH=src .venv/bin/python -m ml.iot23.capture3_validate \
  --output data/raw/acquisition/iot23-capture-3-1-muhstik-v1/new-validation.json
```

`--raw-root` and `--prior-root` permit explicit read-only access to the same approved
saved directories from an independent source Export. No network request or model call
occurs on that path. Existing output names fail rather than overwrite evidence.
The small full-row duplicate/unset diagnostics were separately computed with existing
`columns`, SHA256 row sets and UID sets across all label rows; source SHA binds that scan.
No raw records are copied into the summary.

Next decision: obtain independently reviewable physical-device/campaign and capture
quality evidence, and explicitly review a chronological split redesign or a documented
retrospective evaluation protocol. Do not move3-1 to Test or34-1 to Train to obtain a
favorable score. No source-producer change, new download or training is required/authorized
as an automatic consequence of this report. A separate training approval still follows
only a verified dataset/holdout admission.

## Changed files

- `src/ml/iot23/capture3_acquire.py`
- `src/ml/iot23/capture3_validate.py`
- `tests/iot23/test_capture3.py`
- `docs/iot23-capture3-download-plan.json`
- `docs/iot23-capture3-validation-evidence.json`
- `docs/iot23-capture3-validation.md`

SOC change: `docs/linux-soc-v1/iot23-independent-validation.md` only.
