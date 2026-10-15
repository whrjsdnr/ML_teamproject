# Raw dataset acquisition and retraining readiness

2026-10-15 / WSL2 Ubuntu. Baselines: ML
`e564499ffc8cb7682e03876fde82892db89a1305`, SOC
`5ed566987d6d03dd6ae8c60d3cf2521da0734990`.

**Readiness: BLOCKED for all three models.** Public metadata acquisition and the
bounded I/O / binding / pending-manifest contracts are implemented. **No raw
corpus was downloaded, no dataset is ADMITTED, no model was trained.** A download
approval question for the exact Network pilot is pending; silence is not approval.
The result advances to concrete files, sizes and decisions rather than repeating
the previous local-data search.

Machine-readable evidence: [five pending manifests](raw-dataset-manifests.json).
[Network pilot download plan](raw-acquisition-download-plan.json).
All raw/label SHA256s, actual sample/class/exclusion counts and dataset/split digests
remain `UNKNOWN`. Remote metadata hashes are not raw-data hashes.

## 1. Existing datasets first

### CSE-CIC-IDS2018 — ACQUISITION_READY, not ADMITTED

The [official source](https://www.unb.ca/cic/datasets/ids-2018.html) links the public
S3 bucket and documents source/time/protocol-based flow labeling and attribution
conditions. Its live HTTPS [bucket listing](https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/?list-type=2&delimiter=%2F&max-keys=40)
and ten bounded date listings were fetched, not just the introduction page.
Each date listing is complete (`IsTruncated=false`). Observed packet archives:

| Capture date | Archive | Exact compressed bytes from S3 |
|---|---|---:|
| 2018-02-14 | pcap.zip | 39,913,353,098 |
| 2018-02-15 | pcap.zip | 41,283,382,768 |
| 2018-02-16 | pcap.zip | 38,535,667,707 |
| 2018-02-20 | pcap.rar | 44,391,980,380 |
| 2018-02-21 | pcap.zip | 53,462,820,707 |
| 2018-02-22 | pcap.zip | 50,240,938,251 |
| 2018-02-23 | pcap.zip | 59,093,922,810 |
| 2018-02-28 | pcap.zip | 53,251,694,487 |
| 2018-03-01 | pcap.zip | 52,358,069,106 |
| 2018-03-02 | pcap.zip | 44,789,835,888 |

Full object URLs, exact log ZIP sizes, ETags and modification timestamps are in
the catalog. These are downloadable object identities, **not downloaded bytes or
SHA256s**. Multipart ETags are not SHA256 checksums. Archive member lists and
expanded sizes are UNKNOWN; RAR is unsupported by the new inspection helper and
would require separate review. No unrar dependency or archive data was fetched.

Locally preserved TrafficForML CSVs are potential historical label references,
not new Producer input. Nine lack complete endpoint keys; timestamps, NAT/host
identity, timezone and original flow boundaries require review. A new 30s/120s
segment cannot blindly inherit every label from an old longer/differently closed
flow. Use reviewed tuple + containing time interval + session mappings; exclude
unmatched, multiply matched, conflicting and boundary-straddling windows. Official
schedules are context, not permission to label all traffic during an attack malicious
or everything else normal. Raw↔Label matching has **not** been verified.

### CIC-Bell-DNS-EXF-2021 — INSUFFICIENT_EVIDENCE

The [official source](https://www.unb.ca/cic/datasets/dns-exf-2021.html) describes
PCAP/query capture and timestamp labeling, with dataset/paper attribution terms.
Its actual [download link](https://cicresearch.ca/CICDataset/CICBellEXFDNS2021/)
returns an identity-registration form displaying a server error; the public
browse link returns the same form. No personal details were submitted or fabricated,
and no access boundary was bypassed. No verified file list, downloadable raw FQDN
file, file size or SHA is available from this route. The related CIC-Bell-DNS2021
link behaves similarly. Historical guessed aliases redirect to a generic dataset
index and were rejected as file evidence. Local stateless CSV references remain
absent. Advertised corpus sizes are not HEAD-verified download sizes.

## 2. Fallback selection: at most three shortlisted alternatives

| Candidate | Verified availability / terms | Producer fit / label limitation | Decision |
|---|---|---|---|
| CTU-13 Scenario 7 | HTTPS PCAP and labeled-flow objects HEAD 200; CC-BY / attribution | Header-only full-session capture; Argus bidirectional labels. Background/To-Botnet are not binary truth. Network v1 rejects OFFLINE_PCAP. | ACQUISITION_READY; selected bounded Network binding pilot |
| DomainRadar 2024, Zenodo 13330074 v1 | Record export lists individual files, MD5, CC-BY-4.0; selected files HEAD 200 | Raw domain strings plus source/time fields and per-file category, not exfiltration labels. DNS7 lexical fit is reported, not yet checked on bytes. | ACQUISITION_READY; selected DNS acquisition candidate |
| UMUDGA v1 | Official repository and dataset record, MIT; raw lists reported | Generated DGA family lists differ from observed DNS exfiltration. Individual raw-file list/size not verified. | INSUFFICIENT_EVIDENCE; not selected for download |

[CTU official overview](https://www.stratosphereips.org/datasets-overview) distinguishes
normal, botnet and unknown background and states CC-BY attribution.
[Scenario 7 file listing](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/)
and [bidirectional labels](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/)
were actually retrieved. The original full payload capture is private; the extended
truncated capture includes normal/background/botnet packet headers. The small
botnet-only PCAP cannot supply a negative class. The listed malware executable was
not downloaded. Its README SHA describes that executable, **not a PCAP hash**.
The documentation also contains historical timeline text, so label clocks/session
mapping must be checked against bytes rather than copied without review.

[DomainRadar record](https://zenodo.org/records/13330074), its
[metadata export](https://zenodo.org/records/13330074/export/json) and file HEADs
were checked. Selected `malware.json`: **1,081,784,233 bytes**;
`benign_umbrella.json`: **6,075,400,719 bytes**, total **7,157,184,952 bytes**.
Other listed files: `phishing.json` 2,247,046,745 and `benign_cesnet.json`
6,437,047,412 bytes. Publisher MD5s are retained separately from UNKNOWN local
SHA256. Initial record/API fetches failed, but the official export and direct HEAD
requests succeeded; no failed route is claimed as acquisition.

The publisher schema reports `domain_name`, `source`, `sourced_on` and
`evaluated_on`; per-file categories originate from its external collection/review,
not SOC findings. These fields must be parsed and checked before admission.
The task would become **malicious-domain advisory classification**, not evidence
of DNS tunneling/exfiltration or a verified DNS query event. Source filters and
curation may leave label noise. A popular-domain list alone is not independent
proof of benignness. Enrichment fields may contain WHOIS/contact data; none were
acquired or committed, and they must not be retained as training features.

[UMUDGA dataset record](https://data.mendeley.com/datasets/y8ph45msv8/1) reports
raw FQDN lists and an MIT license; its
[author repository](https://github.com/Cyberdefence-Lab-Murcia/UMUDGA) confirms code.
That does not verify downloadable raw files. Probe API routes returned 404, without
proving the dataset itself unavailable. No generated domains were executed or
substituted for an operational corpus.

Screened but outside the final three: [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
has useful label documentation but its current download link leads to the same
registration/server-error flow; [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
documents raw PCAP and ground-truth files, but its official SharePoint link redirects
to authentication. Their individual raw-file availability was not verified. No
mirrors of uncertain license/identity were silently substituted.

## 3. Exact bounded storage / download decision

The Network pilot plan selects **two** Scenario 7 files:

- `capture20110816-2.truncated.pcap.bz2`: 111,664,996 bytes; HEAD type `application/x-bzip2`.
- `detailed-bidirectional-flow-labels/capture20110816-2.binetflow`: 15,630,512 bytes; HEAD type UNKNOWN.

Total: **127,295,508 bytes (~121.4 MiB)**. Destination, once approved:
`data/raw/acquisition/ctu13-s07-header-pilot-v1`, ignored by Git, newly created,
private 0700 with raw files 0600. No existing datasets will be overwritten.
Free space observed before acquisition was 951,335,133,184 bytes; this is a point
observation, not a space reservation. Download cap 256 MiB / two files, expansion
cap 512 MiB, zero automatic retries, per-file 300s watchdog required in the caller.
No raw file transfer was started because explicit approval has not arrived.

The DNS pair would require a separate approval for 7,157,184,952 bytes, storage
reservation and a bounded streaming importer. Do not fetch all 15.8GB or retain
WHOIS/RDAP/TLS/GeoIP enrichments by default. No DNS download is approved by the
Network pilot question. Suggested separate storage:
`data/raw/acquisition/domainradar-2024-v1`. No directory/data was created there.

`storage.py:DownloadSpec,fetch_reviewed_file,save_response` validates HTTPS source
host, exact URL, no redirects/credentials, approved filename/type, declared length,
byte bound, format prefix, SHA256 and a body deadline. No automatic retries.
Missing MIME is UNKNOWN and rejected unless explicitly reviewed; an Argus CSV
header must still match the expected schema. Publisher SHA is checked when known;
without one the receipt reports no publisher-digest verification. TLS/origin and
local SHA cannot manufacture independently authenticated label provenance.
Publication uses a private temporary file and atomic no-clobber link. Only its
own temporary file is cleaned on failure; original user files are preserved.
The transfer helper is not a hard process watchdog: blocking socket reads have
10s timeouts, so a reviewed caller must enforce the plan's total 300s process bound
before actual use. No batch auto-downloader or hidden approval flag was added.

ZIP inspection validates member paths, symlinks, special/encrypted/executable files,
member count and 512MiB aggregate expanded bytes, reads/hashes bounded content and
extracts nothing. Bzip2 decoding similarly enforces expanded bytes and rejects
truncation, extra data and concatenated streams. Tests use owned temporary archives.
Before ZIP parsing, central-directory metadata is capped at 64KiB and compressed input at 256MiB; ZIP64/multidisk or larger metadata are rejected. Bzip2 input has the same 256MiB compressed cap. No external archive was extracted. New raw files and sensitive payloads are never
staged; only sanitized metadata, manifests, code and tests are eligible.

## 4. Producer compatibility — discovered hard blocker

**Producer v1.0.0 was not changed.** Network accepts source origins only
`NATIVE_AF_PACKET` / `EXPLICIT_PACKET_FIXTURE`. Public offline PCAP is neither.
Calling it Fixture or pretending AF_PACKET provenance would be false. The new
binding helper requires an explicit source origin and rejects `OFFLINE_PCAP`
through the existing Producer. There is no validator bypass or synthetic relabel.

Proposed separate change (not implemented/authorized): Network v1.1.0 with an
`OFFLINE_PCAP` origin, authenticated source-file/session linkage and explicit
header-only capture-quality semantics, preserving 14 numerical feature definitions
unless a further reviewed incompatibility is found. It needs separate golden,
source/config digests and model compatibility review. No approval was inferred
from the data-acquisition task. The current pending catalog cannot grant this.

CTU TCP/UDP snapshots are truncated to headers. Existing SOC packet parsing expects
complete frame/IP lengths and cannot simply accept them or pad missing payload.
A reviewed offline reader would need original/captured length validation and
sufficient IP/transport bytes, preserve wire timestamps and exclude fragments,
unsupported headers/transports and missing fields. Flow direction is first observed;
PCAP file/session identity substitutes only for a reviewed offline interface
identity, never a real live NIC claim. No offline importer was implemented yet.

DNS v1.0.0 can consume `RAW_LABELED_FQDN`; its 7-feature lexical contract excludes
query type and does not require DNS wire metadata. Actual file rows, ASCII/name
validity, duplicates and category binding still need verification. No raw DNS
queries or response times are invented from domain lists. Both producers retain
ordered features, final float32 conversion and source/config/feature digests.
Existing hand Golden fixtures still pass; they are not a dataset-specific Golden
Pair nor an independent operational holdout.

## 5. Raw / label binding and admission boundary

`binding.py:bind_network` validates one reviewed external label interval containing
the entire same-session bidirectional five-tuple window. Missing/multiple/unknown
matches are excluded; nothing defaults to normal. Labels stay external row
references, not values predicted from producer outputs. CTU mapping must retain
From-Botnet vs To-Botnet/Background distinctions and verify capture clock offsets.
This pure predicate is tested with synthetic records only; it is not a verified
PCAP-to-Argus importer or automatic external-label attestation.

`bind_dns` applies exactly the existing lowercase/one-terminal-dot lexical policy,
then requires one explicit source/label row. Normalized duplicates and conflicting
labels are rejected. Invalid, Unicode or digest-only names cannot be converted
into plausible raw names. Future import must record row identities and exclude
counts; actual counts remain UNKNOWN without bytes.

`manifest.py:pending_manifest,verify_manifest` distinguishes ACQUISITION_READY from
ADMITTED and always BLOCKED from READY_FOR_RETRAINING. Tampered or even rehashed
pending manifests cannot assert acquired SHA/counts, training or WRITE authority.
A future acquired-data admission record needs separate verified byte/label/import/
split evidence; this helper intentionally cannot mint one from booleans.
`verify_local_file` rechecks actual local bytes before reuse. The old
`verified_producers.dataset_manifest` remains declarations-only, not evidence of
admission. No positive admission implementation is certified by these tests.

## 6. Freeze splits and independently review holdout

Before training, freeze dataset version, raw/label SHA, importer/producer revision,
configuration, exclusions and label-mapping policy. Network groups must cover
capture session, source, host/incident and the entire flow; verify timezone and
exclude windows crossing collection/split boundaries. **One CTU session cannot
provide independent train/validation/test captures.** Additional sessions and
class support must be separately acquired/reviewed. CSE can later be an external
source only if its raw labeling is independently verified.

DNS requires a pinned Public Suffix List / registered-domain mapping, plus source,
campaign and collection-time groups. Do not guess registered domain from the last
two labels. Domain lists are not a temporal stream of DNS queries; `sourced_on`
and `evaluated_on` have different meanings. Preserve that distinction, review
cross-source/campaign dependence and exclude normalized duplicates/conflicts.
PSL identity and split identity are UNKNOWN; no operational holdout exists.

`validate_split` checks explicit raw/bound-feature digests, group overlap, both
classes in three splits and strict nonoverlapping chronological periods, returning
a stable split digest. Caller-supplied grouping cannot prove genuine source
independence. It does not discover dishonest group assignments, compare all
numeric feature-value collisions or certify label authority. Synthetic tests
exercise duplicate/group/boundary failures only. No actual split has passed.
Do not use test/holdout data for feature selection, threshold tuning or candidate
selection. Record source/time/base-rate differences; older botnet traffic and
curated malicious domains cannot prove host detection accuracy in 2026.

## 7. Retraining readiness / next approved training plan

| Model | Dataset admitted | Compatibility | Actual leakage / Golden / manifest | Readiness |
|---|---|---|---|---|
| Network Quality | NO | BLOCKED: OFFLINE_PCAP origin/header-only importer | NOT RUN | BLOCKED |
| Network Edge | NO | same producer blocker, separate future artifact review | NOT RUN | BLOCKED |
| DNS Security | NO | REPORTED_ONLY lexical fields | NOT RUN | BLOCKED |

After download approval: verify received size/magic/checksums and write immutable
receipts; implement/review the importer with exact external label joins; approve
any new Producer version separately; freeze independent groups/time holdout and
validate real raw↔feature reference cases. Only then request a **separate training
approval** with resource budget, seeds, libraries, hyperparameters, training-only
preprocessing, independent PR-AUC/F1/FPR/FNR, latency/RSS measurements and versioned
artifact paths. A fallback DNS task change needs explicit acceptance; do not call
malicious-domain results exfiltration accuracy. No training/model packaging,
automatic policy change or operational gate release occurs in this task.

## 8. Validation and ownership

New tests exercise fake bounded responses, MIME/magic/size/hash/deadline/no-retry,
archive safety, local source tampering, explicit origin, label ambiguity/conflict,
group/time leakage, manifest tampering and rehashed promotion attempts. These
are local synthetic tests, not downloaded corpora or live capture. Existing
Producer/package/SOC regression is reused. Final per-run results are appended below;
repeated test counts are not summed. Existing ML global format failures are
reported separately; only new files are formatted.

SOC receives byte-identical metadata/plan snapshots and closed-gate tests. No
runtime/source-store/GUI/approval behavior changes. Existing user changes, Replay,
legacy DNS package, v1 Producer source/config/Golden identities and all model
artifacts are preserved. No new dependencies, privilege escalation, packet capture,
traffic generation, domain resolution to dataset entries, LLM call or model
training is performed. Physical Linux validation remains future work.

CSE-CIC-IDS2018 retains priority as the existing Network training-data source.
The CTU selection is a smaller optional raw/label-binding pilot rather than a
wholesale training-corpus switch. CSE's verified availability is preserved in the
catalog; no claim of impossibility or full fallback adoption is made. Actual
bindings, independent capture groups and user budget/task decisions must precede
choosing the training corpus.

### Final executed validation ledger

| Execution | Result |
|---|---|
| Working ML final acquisition + Producer + legacy packages/benchmark tests | 328 passed, 0 failed (22.01s) |
| Independent ML HEAD export + selected changes, acquisition + Producer tests | 132 passed, 0 failed (0.21s) |
| Working SOC related regression | 768 passed, 0 failed (295.59s) |
| SOC new acquisition snapshot/gate tests | 6 passed, 0 failed (0.31s), included in broader runs |

Counts are per run, not added across repeated development/export executions.
Earlier smaller runs preceded the final archive-allocation guard. No failed test
was skipped or weakened. The new file transport tests use fake responses; public
metadata/HEAD probes are separately recorded in JSON, not described as raw downloads.
SOC's test guard blocks actual network sockets and live LLM tests are disabled.

ML Ruff `src tests`, new-file Format (7 Python files), export Ruff/Format and Git
whitespace checks pass. Global ML Format has **24 preexisting failures**, confirmed
against the initial hashes. An intermediate new-file formatting finding was fixed;
no old Notebook/source was automatically rewritten. SOC global Ruff/Format passes.
Existing ML `.venv` lacks pytest, so test runs borrow the already-installed pytest
module via a process-local path while the ML interpreter and source dependencies
remain unchanged. No install or environment rebuild occurred.

Selected ML files (10):

- `src/ml/raw_acquisition/__init__.py`
- `src/ml/raw_acquisition/storage.py`
- `src/ml/raw_acquisition/binding.py`
- `src/ml/raw_acquisition/manifest.py`
- `tests/raw_acquisition/test_storage.py`
- `tests/raw_acquisition/test_binding.py`
- `tests/raw_acquisition/test_manifest.py`
- `docs/raw-dataset-acquisition.md`
- `docs/raw-dataset-manifests.json`
- `docs/raw-acquisition-download-plan.json`

The independent export contains HEAD and these files only; it needs no uncommitted
Replay, legacy DNS raw artifacts or user changes for its 132 tests. SOC selects
only three documentation snapshots/reports and one boundary test. All 455 existing
ML and 1,027 SOC inventoried files are SHA-identical, and the seven legacy model/
scaler/resource hashes separately match. New Producer v1.0.0 and its old evidence
SHA/Golden manifest remain untouched. Large old corpora were not fully hashed.
The new acquisition directories were not created. Public metadata/manifests have
no secrets, authentication logs, domain row dumps, packet payloads or trained artifacts.

Final independent SOC export: **768 passed, 0 failed (373.88s)**; Ruff/Format pass
and the guard blocks one attempted socket creation without native capture.
Documentation ledger updates after tests change no executable source or evidence
snapshot. Selected source/test/metadata SHA values match their independent exports.
Both indexes are checked before selective staging. The requested preparation
commits do not contain downloaded data or imply download/training approval.
