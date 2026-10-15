# IoT-23 Network acquisition and admission

2026-10-15, WSL2 Ubuntu. ML baseline `48205646bacbca67eaa39d04b597c34551942a18`;
SOC `e2c2acaf1736a9db43fd3754451227bb01ede0fc`.

**Overall PARTIAL. Acquisition and offline reference validation completed;
Network Quality: BLOCKED; Network Edge: BLOCKED. Training admission: BLOCKED.**
No model training, native model inference, new capture, privilege change, OS security
response, model artifact replacement or operational gate unlock occurred.

## 1. Approved download and local integrity

Exactly the six URLs in [the fixed plan](network-training-download-plan.json) were
requested once, without redirects or retry. The previous pending plan remains intact
as a historical proposal. The user's new instruction is separate approval to acquire,
not permission to train. New code adds only the exact `conn.log.labeled` filename
and Zeek prefix check to existing bounded transport; it does not disguise Zeek as Argus.

Storage: `data/raw/acquisition/iot23-network14-3sessions-v1/`, private session directories,
0600 raw files, no overwrite, atomic no-clobber publication, stream SHA256, identity
encoding, strict HTTP 200 / Content-Length / expected format. Parent process watchdog:
300 seconds per file, terminates only its owned transfer child; socket timeout <=10s,
no retry. Total actual downloaded **137251065 bytes**, cap 268435456 bytes.
Archive expansion **0 bytes**. No PCAP, raw label or generated large flow dataset is in Git.

| Capture | File | Actual = expected bytes | Local SHA256 | Seconds |
|---|---|---:|---|---:|
| 8-1 | 2018-07-31-15-15-09-192.168.100.113.pcap | 2098362 | `80dcc2602519479ddcde889fa902fee19a76696630811452f8df38888af894f2` | 2.927 |
| 8-1 | conn.log.labeled | 1431000 | `4877ca8f0f01902fbd18d28b7d06cb3d0be082355b7f2c8862c9deef1782eb8a` | 2.202 |
| 20-1 | 2018-10-02-13-12-30-192.168.100.103.pcap | 4057401 | `4d0a00c33a4bf11228158baddd47c38f702731ea8d75ef1201061fc8bbd878b9` | 8.154 |
| 20-1 | conn.log.labeled | 419604 | `ef48ad72f65efd13d517223e61e4d877ba53a082ddb8159324b18d3f310d0711` | 1.961 |
| 34-1 | 2018-12-21-15-50-14-192.168.1.195.pcap | 126317980 | `92ec7e2f6658ee4b007d0b816986c46cc0338bc5e2bec6ceaaca566c695e4699` | 16.754 |
| 34-1 | conn.log.labeled | 2926718 | `d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e` | 2.662 |

All six HTTP status codes were 200. Label Content-Type was absent (UNKNOWN), allowed
explicitly with independent format validation; PCAP was `application/vnd.tcpdump.pcap`.
Acquisition timestamps and exact source URLs are in the sanitized receipt below.
Publisher per-file SHA256 is unavailable; **local computed SHA is not a publisher checksum**.
TLS/source URL, exact size and local repeat-read integrity are established; no signed
publisher digest or external immutable per-file authenticity proof is invented.

Receipt and aggregate evidence:
[iot23-network-admission-evidence.json](iot23-network-admission-evidence.json).
No payload, raw label row, original IP address or Zeek UID is included in that evidence.
Capture filenames retain publisher identities, not newly collected host data.

## 2. Raw PCAP and actual Zeek schema

All three files are **classic PCAP 2.4, little-endian, Ethernet link type 1,
1 microsecond resolution, snaplen 262144**. Full uncompressed file streams were parsed;
stream byte counts and SHA equal the acquired files. No archive/decompression was used.
Only IPv4 TCP/UDP were parsed in these actual captures; IPv6 is covered by existing
explicit fixtures, not claimed observed here. No snaplen-truncated records were observed.

Non-TCP/UDP exclusions: link protocol unsupported: 8-1 **6946**, 20-1 **8949**,
34-1 **5396**; 34-1 also has **57489 fragmented IP packets**, excluded by the existing
parser without reassembly. No missing fragments or features are imputed as zero.
Capture packet/drop metadata and gap-free collection provenance are **UNKNOWN**.
Successful full-file parsing does not prove the original capture observed every packet.

Actual label schemas have 23 columns. 8-1 / 20-1 use tab-delimited original Zeek fields
with a triple-space-separated `tunnel_parents / label / detailed-label` suffix.
34-1 is tab-delimited with the actual final name **`det_label`**, explicitly mapped as
the documented local alias. `#types`: `ts=time`, `duration=interval`, address/port/enum,
packet/byte `count`; label strings. Unexpected headers, widths or types fail closed.
Both actual suffix forms have separate schema digests and tests; no arbitrary whitespace
split, inferred missing field or generic CSV parser is used.

Fields retained for checks: `ts`, `uid`, `id.orig_h/p`, `id.resp_h/p`, `proto`, `duration`,
`missed_bytes`, `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes`, label and detail.
Background, unknown, missing labels or duration never become benign/zero.
Source identity = exact PCAP SHA + session; each external label reference binds the
label file SHA and original row number. Zeek UID is linked by the label reference,
**not reconstructed or matched independently from PCAP**.

## 3. Timestamp and direction evidence

No timezone/DST search or shift was performed. PCAP epoch microseconds and decimal
Zeek `ts` match at first-packet precision; all three full-capture first/last epoch
ranges coincide with the corresponding label ranges (see evidence). 8-1 starts
2018-07-31 13:15 UTC, 20-1 2018-10-02 11:12 UTC, 34-1 2018-12-21 14:50 UTC.
Filename local-looking times are not used to correct packet timestamps.

[Zeek's connection contract](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)
defines first-packet time, originator/responder counters and IP-header byte lengths.
Its TCP duration may omit trailing nonproductive packets, such as a final ACK.
Thus Zeek duration is **not assumed to equal all-packet Flow duration**. This current
reference explains the observed mismatch; the precise historical Zeek build/config
for these individual snapshots remains UNKNOWN.

Producer direction remains first observed endpoint pair. Binding compares counters in
Zeek orig/resp orientation, recording ORIG/RESP independently; it never substitutes
inbound/outbound host direction. No new flow lifecycle or Producer semantics are introduced.

## 4. Flow reconstruction and conservative binding

Existing `PcapReader`, packet parser and bounded `Flows` are reused. Idle timeout 30s,
active 120s, <=4096 packets per segment, deterministic resource handling remain unchanged.
Flow counts below are **producer segments, not Zeek connection counts**.

A VERIFIED_MATCH requires a unique session/protocol/bidirectional 5-tuple, exact first
epoch, full flow within the recorded interval, zero reported missed bytes, exact
originator/responder packet counts and IP byte totals. Duplicate or conflicting intervals
are AMBIGUOUS. Multiple segments associated with one label cannot silently become 1:1;
strictly matched rows would be demoted if shared. Incomplete/resource/packet-limited
segments are excluded. No label is inferred for unmatched traffic.

Same start+tuple with missing duration is EXCLUDED; with non-containing TCP duration is
CANDIDATE_MATCH only. Counter mismatch/partial connections are also candidates. These
are explanatory categories, **not training truth**; no end-time tolerance was tuned.

| Capture | Raw packets | Parsed | Flow segments | Label rows | VERIFIED | CANDIDATE | AMBIGUOUS | UNMATCHED | EXCLUDED |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8-1 | 23623 | 16677 | 4237 | 10403 | 2162 | 2056 | 0 | 0 | 19 |
| 20-1 | 50156 | 41207 | 3921 | 3209 | 2300 | 36 | 0 | 1 | 1584 |
| 34-1 | 233865 | 170980 | 7848 | 23145 | 1866 | 4755 | 0 | 4 | 1223 |

Binding statuses sum to reconstructed segments within each capture. Per-reason counts
and closure counts are retained separately in evidence, rather than combining parser,
quality, timeout and unknown-label exclusions into one claimed improvement.
No resource eviction occurred. 20-1 has **706 active-timeout** segments; 34-1 has
**26 packet-limit** segments (excluded) and **2 active-timeout** segments.

## 5. Class coverage: raw labels are not admitted samples

| Capture / tentative split | Publisher label rows Benign / Malicious | Strictly VERIFIED Benign / Malicious | Admitted |
|---|---:|---:|---:|
| 8-1 / train | 2181 / 8222 | 2162 / **0** | 0 |
| 20-1 / validation | 3193 / 16 | 2300 / **0** | 0 |
| 34-1 / sealed test | 1923 / 21222 | 964 / 902 | 0 |

6328 strict Flow matches exist, with diagnostic feature vectors, but dataset admission
is not granted. In 8-1, 2056 segments are candidates because the Zeek duration does not
contain all packets; 19 have a matching start with missing duration. Raw malicious
labels are present, but cannot be promoted by relaxing binding to manufacture class coverage.
20-1 also has missing durations, partial long connections and missed-byte quality failures.

## 6. Producer v1.1.0, reference pairs and integrity

The unchanged producer produces the existing **14 float32 features** from ordered IP
metadata, source origin **OFFLINE_PCAP**, explicit source/feature digests and UNKNOWN
capture quality for diagnostic-only output. No Top40/legacy model compatibility is implied.

- Producer configuration digest: `7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7`.
- Feature contract digest: `84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`.
- Duration, packet/byte counts, IP length population statistics, SYN/FIN/RST and IAT
  retain their meanings/order; no scaler, imputation or feature selection was fitted.

Golden evidence is distinguished:

1. Existing synthetic arithmetic pairs: fixtures, not raw acquisition proof.
2. **Three actual PCAP-derived two-packet reference pairs**: separate `statistics.mean`
   / `pstdev`, integer counter sums and final float32 conversion agree with Producer.
   Reference method, metadata/source digest, numeric packet lengths/flags/time offsets,
   feature names/values and config/contract digests are committed without raw addresses.
   Tolerance rel=1e-6 / abs=1e-7; test fixtures additionally assert manual exact values.
3. **Training-to-operational parity pair: NOT_VERIFIED**. Equal arithmetic on declared
   origins is not independent AF_PACKET capture validation. No new privileged capture
   or native model inference was run. Future model artifact binding: NONE (not trained).

Raw bytes, labels, vectors, feature order/config and manifest mutations are tested.
SHA manifests are tamper-evident local receipts, not signed identity/authorization.

## 7. Tentative holdout and admission

The pre-download split is retained: train8-1 / validation20-1 / test34-1, no random row
split or moving test samples to repair missing training classes. Test data were used only
for this pre-training schema/binding/admission inspection, not model selection or tuning.
No model was fitted and no test labels influenced fitted preprocessing/thresholds.

Distinct capture/day epoch ranges do not overlap. Exact raw-flow fingerprint intersections
are 0 across all pairs. However **one observed origin address hash overlaps train/validation**;
private IP reuse does not establish physical device identity or independence. Device/malware
sample/campaign separation remains unverified despite different published family names.

Network14 numeric-vector coincidences across pairs are **92 / 80 / 79**. Small generic
packet shapes can yield identical features; they are reported separately and are not
misclassified automatically as duplicate raw flows or proof of independence.
Raw-flow fingerprints include absolute times and endpoints; they cannot exclude all
replayed/retimed/shared-campaign source data. Leakage audit is therefore not PASS.

Admission gates: raw/local integrity PASS, label/local integrity PASS, binding PASS **for
strict subset only**, producer PASS, actual offline arithmetic reference PASS, manifest
PASS, external analyst label provenance documented. **Holdout class coverage BLOCKED,
source-host/campaign leakage UNVERIFIED, capture quality UNKNOWN.** Both network model
readiness values and training admission remain BLOCKED. Admitted sample count **0**.

Manifest digest: `e833b021a361d35e968962ab5b3b1c626ca313523d89ef75f5496e5ffae909d6`.
No READY status can be obtained just by rehashing a changed admission field; gate and
observed class/quality/independence consistency are revalidated.

## 8. SOC integration readiness and preserved boundaries

Existing future connection is:
`AF_PACKET → existing Flow metadata → versioned producer → future new model → external
advisory context → Finding → READ-only investigation → Policy/Human Approval`.
No existing Network Quality/Edge/DNS artifact accepts Network14 just because its schema
is known. Source/provenance/model binding must be independently established.
`NOT_INFERABLE`, inference/Finding promotion BLOCKED, DIAGNOSTIC_ONLY, WRITE_DENIED
remain unchanged. Existing 7 reviewed artifact/scaler/feature identities were SHA-rechecked.
No new collector, queue, GUI, source store or response framework was added.

## 9. Tests, reproducibility and ownership

Fresh ML working-tree regression: **535 passed** (5.12s); includes IoT23, dataset
selection, raw acquisition, CTU13, producers, scripts and the three package test suites.
Independent ML Git Export: **528 passed** (5.11s); the difference is 7 pre-existing user
CTU tests deliberately excluded from this commit. Counts are separate runs, not summed.

Independent export = committed baseline plus only this task's files. It excludes user
changes to CTU labels/PCAP/pilot/tests and excludes the pre-existing storage preflight
hunk. Reprocessing all three already acquired PCAPs from that export produced an
**identical full inspection Manifest and flow-record SHA256s**. No second download occurred.
Only owned Zeek filename/prefix transport hunks are included, not the user's storage hunk.

New IoT23 tests: **57 passed** in a separate focused run (not added to the broader counts).
New coverage: strict observed schema variants, exact/reversed direction, missing/unknown
labels/durations, ambiguous/conflicting labels, digest/source/path forgery, raw byte
PCAP E2E fixture, independent arithmetic reference tampering, hard watchdog/no retry,
redirect/MIME/length/budget/partial cleanup/no-clobber/symlink, and admission bypass checks.
Runtime/collector/security coverage is reported separately in the SOC report.

Ruff src/tests PASS; owned Python formatting PASS. Whole ML formatting remains
**24 pre-existing violations**, untouched. Git diff/check and staged/export identities
are checked before commit. Raw datasets and every pre-existing user/Replay file are preserved.

## 10. Reproduction and next retraining decision

Acquisition was explicitly invoked once. Do not rerun or delete receipts to bypass
no-retry/no-overwrite protection. The command refuses a previously started destination.

Saved-byte inspection, unprivileged and with a new output directory:

```bash
PYTHONPATH=src .venv/bin/python -m ml.iot23.inspect \
  --root data/raw/acquisition/iot23-network14-3sessions-v1 \
  --output data/raw/acquisition/iot23-network14-3sessions-v1/new-review
```

Raw files and per-flow diagnostic JSONL stay in the ignored acquisition directory.
The source, fixtures and sanitized summary are independently reproducible without
shipping raw traffic in Git; testing actual bytes requires the separately acquired files.

Next action: independently review a **connection-aware TCP label association** policy
that handles documented trailing nonproductive packets and Zeek/producer segmentation
with exact counts and unique references. Do not broaden time windows merely to increase
matches or change the Producer's 14 feature semantics. If reliable malicious train/val
binding cannot be established, request specifically reviewed additional labeled captures
or packet-level reference metadata; no additional download is authorized here.
Device/campaign grouping, drop/gap evidence and independent native parity still need work.
Only after a new explicit admission decision may a separately authorized training plan
be executed. No physical Linux server or production reliability/accuracy claim is made.

## Sources and usage

[IoT-23 publisher](https://www.stratosphereips.org/datasets-iot23),
[Zenodo v1.0.0](https://zenodo.org/records/4743746),
[current publisher FAQ](https://www.stratosphereips.org/datasets-faq).
Attribution: García, Parmisano, Erquiaga (2020), IoT-23 v1.0.0,
DOI10.5281/zenodo.4743746. Dataset-level CC-BY-4.0/current reuse FAQ and the older
per-capture authorization notices are both retained from prior terms review. No raw
redistribution occurred; approval to download does not override publisher restrictions.
Individual 34-1 labels were modified in 2023; identity with the frozen 2020 Zenodo tar
is not claimed. The exact downloaded snapshots are bound by the local SHAs above.

## Changed files

- `docs/iot23-network-admission-evidence.json`
- `docs/iot23-network-admission.md`
- `src/ml/iot23/__init__.py`
- `src/ml/iot23/acquire.py`
- `src/ml/iot23/inspect.py`
- `src/ml/iot23/integrity.py`
- `src/ml/iot23/zeek.py`
- `src/ml/raw_acquisition/storage.py`
- `tests/dataset_selection/test_network_selection.py`
- `tests/iot23/test_acquisition.py`
- `tests/iot23/test_binding.py`
- `tests/iot23/test_inspection.py`

SOC change: `docs/linux-soc-v1/iot23-network-readiness.md` (documentation only).
