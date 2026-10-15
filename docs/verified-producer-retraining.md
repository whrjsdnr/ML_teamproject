# Verified producer preparation and retraining feasibility

Date: 2026-10-15. Environment: WSL2 Ubuntu, Python 3.12.14.
ML baseline: `1800bd013edefd448671c97a8b7114409f639481`.
SOC baseline: `4a86db4c0beeef7d6d7d81c1a0f7d543b27183b4`.

**Overall: BLOCKED for real model retraining and independent evaluation.**
Network Quality, Network Edge and DNS Security are independently BLOCKED.
New versioned arithmetic producers and synthetic hand-checked reference tests are
implemented (PARTIAL preparation). No new model has been trained, packaged,
benchmarked or promoted. Existing models/scalers and the untracked legacy DNS
package remain untouched.

Machine-readable evidence: [evidence](verified-producer-evidence.json).
Portable specifications: [contracts](verified-producer-contracts.json).
Those specifications are offline preparation, not executable runtime authorization.

## 1. Raw dataset availability

A fresh local file inventory examined `data`, `notebooks`, `scripts`, `src` and
`packages`, excluding virtual environments, caches and distribution directories.
It found **0 PCAP/PCAPNG/CAP files**. Headers of all ten files under
`data/raw/cse_cic_ids2018` were read: 6,886,649,507 bytes in total,
nine 80-column CSVs and one 84-column CSV. These are previously computed
CICFlowMeter features with a `Label` column, not packet records for the new
producer. Extra Flow ID/IP columns in the 84-column file do not reconstruct
individual lengths, timestamps or packet/label correspondence.

`reports/CIC-Bell-DNS-EXF-2021_DNS_Security_ML.ipynb` cells 2 and 5 read
`data/Benign/stateless_features-benign_1.pcap.csv` and
`data/Attack_heavy_Benign/Attacks/stateless_features-heavy_text.pcap.csv`, then
select nine precomputed columns. Those referenced files are absent. The EDA
notebook likewise reads stateless-feature CSVs. Neither is a raw FQDN producer.
No independently labeled raw FQDN training corpus was found. Existing Parquet
splits remain old feature datasets and are excluded from new-producer training.
The scan checked filenames and headers, not the full content of every data row;
it cannot rule out undisclosed data outside the inspected repository.

| Admissible dataset | Network | DNS |
|---|---|---|
| Raw input + independent linked labels | MISSING | MISSING |
| Attack and normal source groups | MISSING | MISSING |
| Time/session/domain-separated holdout | MISSING | MISSING |
| Training samples admitted this run | 0 | 0 |
| Dataset generation / model training | BLOCKED | BLOCKED |

The stored user-executed loopback session has 32 packet observations, four
observed endpoint groups and no DNS events. It has no independent class labels.
It is diagnostic evidence only; owned test traffic is not automatically a
verified negative class, and a detection result is not a training label.

### Required acquisition

Request original per-host PCAPs, capture/session identity, checksums and reviewed
label mappings keyed by endpoint/protocol/time interval. Ambiguous many-to-many
joins must be excluded and counted. For DNS, request raw query names (or DNS
PCAP), independent label documentation, source family and collection identity;
query type is optional for this FQDN-only contract.

The [official CSE-CIC-IDS2018 page](https://www.unb.ca/cic/datasets/ids-2018.html)
describes raw PCAP/log downloads separately from generated flow CSVs.
The [official CIC-Bell-DNS-EXF-2021 page](https://www.unb.ca/cic/datasets/dns-exf-2021.html)
is the acquisition reference for the DNS corpus and its labeling context.
These are acquisition candidates, not locally verified inputs. No datasets were
downloaded and no capture, traffic generation or dependency installation occurred.

## 2. Network producer v1

Implementation: `src/ml/verified_producers/network.py:Packet,network_features`.
Identity: `linux-observable-network`, semantic version `1.0.0`.
This is a new **14-feature** experimental contract, not Top40.

Input is an ordered tuple of 1..4096 validated packet metadata records from one
interface, capture session and bidirectional endpoint/protocol pair. A reference
ID, interface identity, session, integer nanosecond timestamp, canonical addresses,
ports, TCP/UDP, IP length and TCP flags are required. Protocol minimum lengths,
address family, bounds and ambiguous identical endpoints are checked. No packet
payload is needed. Source origin/quality are declared metadata, not attestations.

Feature order is fixed in `contracts.py:NETWORK_NAMES`:

1. duration_seconds
2. forward_packet_count
3. backward_packet_count
4. forward_ip_bytes
5. backward_ip_bytes
6. ip_length_min
7. ip_length_max
8. ip_length_mean
9. ip_length_population_std
10. tcp_syn_packet_count
11. tcp_fin_packet_count
12. tcp_rst_packet_count
13. iat_mean_seconds
14. iat_max_seconds

Forward means the first observed endpoint pair, independent of host IN/OUT or
historical training direction. Bytes/statistics use **full IP length**, not frame
length or payload bytes. Standard deviation uses the population denominator N.
IAT uses consecutive observations in input order; equal timestamps are allowed,
negative intervals are rejected. A singleton has duration and IAT zero by explicit
contract. Rates and Active/Idle features are omitted; no undefined rate is imputed.

Caller must segment observations first. An interval >=30 seconds or span >=120
seconds is rejected; this function neither captures packets nor reconstructs TCP
streams. Explicit gaps/drops are rejected. UNKNOWN quality permits experimental
arithmetic only and never establishes capture completeness. Repeated event IDs
are rejected. Different record IDs with identical frames remain observations;
loopback IN/OUT copies are not claimed to be unique wire packets. Session IDs and
interface digests cannot establish authenticity without source/provenance checks.

## 3. DNS producer v1

Implementation: `src/ml/verified_producers/dns.py:dns_features`.
Identity: `linux-observable-dns`, semantic version `1.0.0`.
This is a new **7-feature** FQDN-only contract, not DNS9.

Input: ASCII text, max 254 characters including an optional root dot. Remove
exactly one trailing dot and lowercase ASCII, without whitespace trimming. Labels
contain 1..63 ASCII letters/digits/hyphens/underscores; normalized name <=253
characters. Root-only, empty labels, Unicode and malformed text are rejected.
Punycode is accepted literally, without decoding or an implicit IDNA conversion.
These are explicitly limited lexical inputs, not support for every legal DNS
wire label. Public-suffix/subdomain classification is omitted.

Order: `fqdn_length_no_root`, `label_count`, `max_label_length`,
`mean_label_length`, `ascii_digit_ratio`, `ascii_special_ratio`,
`character_entropy_bits`.

Length includes internal dots. Character ratios and Shannon log2 entropy use
concatenated lowercase labels, excluding dots. Special characters are hyphen and
underscore; digit means ASCII 0..9. Query type, TTL and response fields are
excluded. DoH/DoT and retained-name digests cannot provide raw lexical inputs.
Raw spelling is preserved only inside the source digest input; normalized variants
can share feature values but have different source/feature digests. The pure
producer stores nothing; any future raw-domain retention needs a privacy policy.

## 4. Contract, precision and identity

`contracts.py:contract,FeatureVector` binds producer ID/version, ordered names,
source schema, normalization, timeout/direction/missing policy and configuration
SHA256. Arithmetic is binary64 with one final IEEE754 binary32 conversion using
`struct`. The return value is an immutable tuple of Python floats representing
float32 values, not a NumPy array. Missing input, NaN and infinity are rejected.
No scaling is fitted. Future learned preprocessing must be trained only on the
training split and separately bound to the model artifact.

Source digest binds input records, declared origin and quality; feature digest
also binds ordered names, configuration, values, version, origin and quality.
Canonical JSON uses sorted keys and rejects nonfinite numbers. An unsigned digest
is integrity linkage, not authenticated provenance. Implementation file SHA256s
are pinned in the evidence JSON; production binding must include a reviewed
revision plus configuration and artifact identities. Version/config/order changes
never imply compatibility with an existing model.

## 5. Golden pairs and independent reference

`tests/verified_producers/fixtures/golden.json` is explicitly
`SYNTHETIC_HAND_CHECKED_NOT_TRAINING_GROUND_TRUTH`: **one Network and two DNS cases**.

Network hand example: times 0,1,3 seconds; IP lengths 40,80,40; directions F,B,F;
SYN,SYN+ACK,FIN. Duration=3; counts=2/1; bytes=80/80; mean=160/3;
population variance=3200/9; IAT mean=1.5 and max=2. A separate sum-of-squares
reference calculation checks the deviation, rather than rerunning the producer.
DNS `Aa.11.` -> `aa11`: digit ratio=1/2 and entropy=1 bit.
`A-._1.` -> four distinct characters: special ratio=1/2, entropy=2 bits.
These expectations were written independently, not generated by producer output.
The fixture file SHA is pinned in tests; tolerance is absolute/relative 1e-6.
This small arithmetic check is not a raw training corpus or broad operational
parity verification. No old training Producer Golden Pair is claimed.

## 6. Dataset admission preparation

`dataset.py:Sample,dataset_manifest` rejects feature-only/synthetic declarations,
missing/derived labels, invalid source digests, duplicate raw IDs, duplicate sample
IDs, cross-split source groups, absent splits and absent classes. It produces
stable declaration/label digests and per-split counts. **It does not load raw
bytes, verify label authority, join labels, detect dishonest group assignments or
prove time-disjoint holdout independence.** Its result explicitly says
`DECLARATIONS_ONLY_NOT_TRAINING_AUTHORITY`; raw/label/time verification is false.

No feature dataset or train/validation/test files were generated. A full dataset
builder/training pipeline is deferred until raw admission can be tested. Future
Network splits must isolate capture session/incident/source and overlapping time
windows. DNS splits require independently assigned domain/source-family groups,
not random row splits or a guessed public suffix. Freeze holdout before candidate
selection, fit all transforms on training only, exclude ambiguous labels, and
record excluded counts and digests. This work does not certify leakage-free data.

## 7. Retraining, holdout and packaging

| Model | Producer preparation | Retraining | Independent evaluation | New artifact |
|---|---|---|---|---|
| Network Quality | 14-feature arithmetic PARTIAL | BLOCKED | BLOCKED | NONE |
| Network Edge | same new contract PARTIAL | BLOCKED | BLOCKED | NONE |
| DNS Security | 7-feature arithmetic PARTIAL | BLOCKED | BLOCKED | NONE |

No random seed/hyperparameters were used for training, no training duration was
measured, and no new library/model format was selected by benchmark. Precision,
recall, F1, PR-AUC, confusion matrix, FPR/FNR, inference latency and model RSS are
**N/A (not evaluated)**, not zero. There is no model loading/timeout test for a
nonexistent new artifact. Old package regression tests concern old models and
mocked backends, not new-model suitability.

Keep existing artifacts as archival baselines. Different input contracts and
missing shared raw holdout prohibit ranking old and new models. Future independent
evaluation must report class/source/time breakdowns, group leakage review,
precision-recall behavior under rare attacks, and false-positive impact at likely
host base rates. Lab dataset ratios cannot establish production attack frequency.
Only after this evaluation should a separate versioned bundle include model,
producer/source revision, preprocessing config, dataset/label/split digests,
metrics, runtime compatibility and per-file SHA manifest. No such bundle exists.

## 8. Actual saved WSL observations and SOC readiness

This run read the existing user-executed saved session with SQLite `mode=ro`.
Stored event digests and PacketObservation schemas/kernel timestamps were checked.
The new producer computed four metadata observation-group vectors from 32 packets;
DNS count was zero. Original session files were SHA256-identical before/after.
No new capture, privileged command, native AI inference or traffic was run.
There are zero independent labels. Capture quality remains UNKNOWN with the
preexisting gap. See the evidence JSON for sanitized digest/value summaries.
This diagnostic computation does not verify Source Store recovery anew or certify
operational completeness. Prior capture audit/recovery evidence remains separate.

SOC receives a byte-identical offline contract snapshot plus closed-gate tests.
Current synthetic v2 and operational v3 accept no new live model feature authority.
Future integration needs an explicit adapter from verified packet/source records,
privacy-approved raw FQDN availability, a new validated model binding and reviewed
operational provenance support. The current GUI/collector/native model settings
are unchanged. `NOT_INFERABLE`, finding promotion BLOCKED and `WRITE_DENIED` remain.
No auto-promotion, runtime policy change or actual OS security response occurred.

## 9. Tests and reproducibility

Final executed results are appended below after independent exports. Test fixture
labels are only admission-test declarations; they are not a six-row training set.
The ML environment has no pytest; tests reuse already installed SOC pytest through
a process-local import path. No environment files or dependencies were changed.
The initial SOC-interpreter collection lacked pandas. A second run in the demo
environment had 259 passes and one installed-package isolation failure because
its sys.path contains the SOC repository. Re-running under the ML interpreter
resolves that environment mismatch; no test was skipped or weakened.

Standalone producer tests can run with an existing pytest interpreter:

```bash
PYTHONPATH=src /path/to/python-with-pytest -m pytest --import-mode=importlib -q tests/verified_producers
```

Source has only standard-library dependencies. Original ML pyproject/lockfile and
legacy packages are unchanged. Full training/evaluation/runtime promotion remain
blocked pending raw data and independent labels. Physical Linux validation is
future work after offline model evidence, not part of this WSL result.

### Executed validation ledger

| Execution | Result |
|---|---|
| Final working tree, producer/admission + legacy packages + memory benchmark tests | 262 passed, 0 failed (4.05s) |
| Independent HEAD export + selected files, producer/admission tests | 66 passed, 0 failed (0.07s) |
| Independent export with ML interpreter `-I -B`, no SOC import/path | 3 hand-reference smoke cases passed |
| SOC working related regression (includes six new readiness tests) | 762 passed, 0 failed (240.97s) |

These are separate runs, not additive. The earlier standalone producer runs
(58/64 tests), and earlier corrected 260-test run preceded the final source/spec
identity tests. SOC export results are recorded after completion below.

ML `ruff check src tests`, seven new Python files' Ruff/Format, and `git diff
--check` pass. **Repository-wide `ruff format --check .` fails on 24 preexisting
files**: notebooks, old docs/scripts/report helpers and untracked legacy DNS source.
All were present in the initial SHA inventory and were preserved. The global
failure is not hidden by the passing scoped check. SOC full Ruff/Format and
export checks pass. No broad automatic formatting was applied to either repo.

Selected ML files (11):

- `src/ml/verified_producers/__init__.py`
- `src/ml/verified_producers/contracts.py`
- `src/ml/verified_producers/network.py`
- `src/ml/verified_producers/dns.py`
- `src/ml/verified_producers/dataset.py`
- `tests/verified_producers/test_producers.py`
- `tests/verified_producers/test_dataset.py`
- `tests/verified_producers/fixtures/golden.json`
- `docs/verified-producer-contracts.json`
- `docs/verified-producer-evidence.json`
- `docs/verified-producer-retraining.md`

The independent ML export contains only HEAD plus these files. Producers run with
the standard library and no SOC package or native model dependency. Existing ML
tracked/untracked files (444 inventoried) and seven separately hashed legacy
artifact/resource files are unchanged. Models are not copied to the new package,
and `packages/dns_security_package/` remains untracked/excluded. Large datasets
were not fully checksummed. SOC's uncommitted Replay/user changes are excluded
from both exports and commits. The deliverable is a tested preparation increment,
not a completed retraining pipeline or deployment-ready model bundle.

Independent SOC export final result: **762 passed, 0 failed (228.04s)**, with
Ruff/Format passing and one socket attempt blocked by its test guard. No new
capture occurred. The export excludes Replay and user modifications. Tested source,
fixture and specification hashes are preserved for selective staging. Documentation
ledgers were finalized after tests; no executable source changed afterward.
