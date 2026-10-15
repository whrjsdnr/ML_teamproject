# Network research training and offline evaluation

2026-10-15, WSL2 Ubuntu. ML baseline `8c6da5fa613e3053bf2cb4d73addfd248595c1d1`; SOC baseline `23767a0394d5f74384463c3be33fdfcf7c4c8865`.

## Decision

**RESEARCH_EVALUATED**: five real CPU models trained, two selected on validation, then one final test pass. This is the explicitly authorized retrospective, cross-session research protocol. Previous operational dataset admission remains **BLOCKED**; neither chronology, physical device independence nor campaign independence is newly certified. No deployment readiness claim.

## Research dataset and label/binding provenance

No download, new capture or decompression. All eight existing PCAP/Zeek SHA256 identities were verified against the existing fixed acquisition plans. Frozen recovery policy `304e76f801004bc4a5b372cb3dc088d3dc090ab1da3ebede8b2915dfdbaad893`; original source/policy lock preserved. Producer **1.1.0**, OFFLINE_PCAP, ordered **14 float32** features, no Top40 compatibility claim. Each sample is one verified Producer Flow. Many concordant Zeek connections remain references to one sample. Conflicts, reference reuse and packet reuse fail closed; CANDIDATE/AMBIGUOUS/UNMATCHED/EXCLUDED never enter fitting or evaluation.

| Role | Session | Flow samples | Benign | Malicious |
|---|---|---:|---:|---:|
|train|8-1|4218|2162|2056|
|validation|3-1|76320|2927|73393|
|diagnostic|20-1|2304|2300|4|
|test|34-1|4295|981|3314|

Per-session raw SHA, label SHA, row digest, feature/configuration digests, original reconstructed populations, binding exclusions and class/reference checks are in `network-research-training-evidence.json`. No raw rows, payloads, IPs, Zeek UIDs or generated dataset are committed. Existing arithmetic Golden Pairs plus actual per-class independent mean/pstdev/counter references were checked while building each split. This is not native AF_PACKET parity.

## Leakage and split limitations

Train8, validation3, diagnostic20 and test34 have zero observed cross-split Flow ID, raw fingerprint, original label-reference, source-bound feature-digest and session identity overlap. These are concrete checks, not proof that hosts/campaigns are independent. Fourteen feature inputs contain no IP, UID, label, session ID or absolute epoch. Source/destination hashes are inspection metadata only.

Train8/validation3 have **1 shared distinct feature-value vector**, **2 shared endpoint hashes** and **2 shared address hashes** (both directions checked). Matching numeric feature values from distinct packet/label sources are reported as collisions, not automatically relabeled as copied raw flows or independent evidence. They are retained under the frozen policy; no test-driven feature filter is tuned. Within-session repeated feature values remain distinct, verified raw flows, so highly repetitive scan traffic can dominate metrics. Train/test have **80** shared distinct feature-value vectors; validation/test **4**. The final receipt additionally reports metrics for **3,927** test flows with feature values unseen in train+validation, calculated from the same one-pass predictions.

Observed capture time windows do not overlap. Validation3 predates Train8: this research experiment is **not future-time forecasting**. Physical devices and campaigns remain UNVERIFIED; shared remote services can cross sessions. Session separation is the only established split unit. Test34 was already inspected for label distribution and binding during prior development; it is **not a blind holdout**. Capture drop/gap quality is UNKNOWN, not zero. Label verification selects a restricted, non-random subset of original traffic. Validation is 96% malicious and scan-heavy; no operating base-rate inference.

## Preprocessing and reproducibility

Train-only StandardScaler + balanced LogisticRegression; tree models require no scaling. No imputer, feature selection, resampling or SMOTE. Missing/NaN/Inf and non-float32 inputs are rejected. Balanced class weights use Train only. LogisticRegression scaler fit count is **4,218**, not the validation/test size. Seed **20261015**, one CPU thread (OMP/BLAS/MKL), fixed finite configurations, no unbounded search. Both HGB candidates have early stopping disabled, preventing an implicit random validation split.

Libraries: Python 3.12.14, scikit-learn 1.9.1, numpy 2.5.3, joblib 1.6.0. Existing installations were reused; nothing installed or reconfigured.

## Quality and Edge candidate comparison

Quality ranks by validation average precision (AP), F1, recall, lower FPR and lower Brier. Edge selects minimum measured single-row CPU median among validation recall >=0.8 and FPR <=0.1; a documented limited fallback exists if no candidate qualifies. Threshold is maximum validation F1, then recall, lower FPR and proximity to0.5 on the fixed grid0.05..0.95. These rules existed before test access. Diagnostic20 never selects a model/threshold.

| Candidate | Val AP | Recall | FPR | F1 | Threshold | Model bytes | CPU p50 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
|quality_rf|0.999984|99.9796%|3.1431%|0.999271|0.35|117241|4.1702|
|quality_hgb|0.997599|98.7751%|4.8514%|0.992871|0.5|58416|0.5648|
|edge_lr|0.999437|98.7478%|1.8449%|0.993332|0.8|1773|0.2195|
|edge_rf|0.999992|99.9796%|1.4008%|0.999619|0.45|50681|1.0635|
|edge_hgb|0.997979|98.7751%|4.8514%|0.992871|0.5|28544|0.2592|

Selected **Quality: RandomForest (128 trees, max_depth12, min_leaf3), threshold0.35**. Selected **Edge: StandardScaler + LogisticRegression (C1, balanced, max_iter2000), threshold0.8**. Final repeated Train-only fits reproduced all five model binary SHA256s, validation prediction digests, metrics and thresholds before the locked Test evaluation.

## Validation and locked Test metrics

| Role / split | Precision | Recall | F1 | AP (PR-AUC summary) | ROC-AUC | FPR | FNR | TN / FP / FN / TP |
|---|---:|---:|---:|---:|---:|---:|---:|---|
|quality/validation|0.998748|0.999796|0.999271|0.999984|0.999601|3.1431%|0.0204%|2835 / 92 / 15 / 73378|
|quality/test|0.951796|0.887749|0.918657|0.984635|0.952715|15.1886%|11.2251%|832 / 149 / 372 / 2942|
|edge/validation|0.999255|0.987478|0.993332|0.999437|0.991921|1.8449%|1.2522%|2873 / 54 / 919 / 72474|
|edge/test|0.995458|0.727520|0.840656|0.912923|0.720760|1.1213%|27.2480%|970 / 11 / 903 / 2411|

PR-AUC is explicitly **average precision**, not trapezoidal PR interpolation. Calibration is assessed using Brier and10-bin ECE/reliability summaries, without fitting a calibration transform on validation/test. Model output is a class score, not actual attack probability.

| Selected model | Validation Brier / ECE | Test Brier / ECE |
|---|---:|---:|
|quality|0.027987 / 0.155811|0.108069 / 0.197099|
|edge|0.014120 / 0.047984|0.219843 / 0.237790|

Test performance deteriorates: Quality FPR15.19%, Edge misses27.25% of malicious verified flows. **No threshold adjustment, retraining or candidate change followed this test.** These are unsuitable as evidence of operating safety. Diagnostic20 has only4 malicious flows; Quality precision2.27% and Edge precision80%, illustrating base-rate sensitivity. Diagnostic AP1.0 for both is not robust operational evidence.

## Test lock and one-pass semantics

Pre-test lock digest: `1c2aedc3c3c5ccbb24fc09a6a7ac047acde379cc064c5c1734fcf9dd13c727b3`.
Final result digest: `a57a284cbf7e91d8cc4abfed2aad41774428bb0720e18bb10f03f4aadbcd4eec`.

Lock binds selected binary SHA/threshold/preprocessor, all fit/validation/diagnostic dataset digests, evaluation code SHA, runtime versions and test raw/label SHA. An exclusive reservation is persisted before reading Test packets. Any crash consumes the attempt and leaves UNKNOWN until a result receipt exists; there is no automatic retry. One final model-prediction pass per selected model, no test benchmarking loops. Test remains evaluation-only. Atomic create also rejects duplicate final evaluations. JSON digests detect mutation; they are not digital signatures or external attestations.

## CPU, memory and latency

Measured host: x86_64, Intel Core i5-12400, 12 logical CPUs; Linux 6.18.33.2-microsoft-standard-WSL2. Fit/inference threads pinned to1; the WSL host was shared with regression tasks, not an isolated performance lab.

Each candidate fit ran in an isolated CPU child process with a180s timeout and3GiB address-space limit. Wall and CPU process time measured separately. Single-row latency: one warmup +100 measured calls; batch throughput uses76,320 validation rows already in RAM and excludes collection/feature-generation/I/O. It is not streaming runtime throughput.

| Candidate | Fit wall s | Fit CPU s | Peak process RSS KiB | Single-row wall p50 ms | Batch flows/s |
|---|---:|---:|---:|---:|---:|
|quality_rf|0.1873|0.1873|653240|4.1730|1319690.0|
|quality_hgb|0.2055|0.2055|653336|0.5660|497413.7|
|edge_lr|0.0125|0.0125|653228|0.2203|19239180.2|
|edge_rf|0.0380|0.0380|653344|1.0658|6839163.2|
|edge_hgb|0.1304|0.1304|653348|0.2600|1498814.2|

**RSS scope is the whole candidate process including dataset JSON loading, training and validation**, not pure model memory. Model sizes and RSS must not be equated. Latencies vary with this WSL CPU and process scheduling; no physical-server benchmark.

## Research Artifact identities and loading

Local-only binary package: `models/network-research-v1-final/` (Git-ignored under existing policy). `research-package.json` binds chosen models, fitted scaler, feature/producer contract, splits, hyperparameters, versions, validation and locked-test receipts. Binary redistribution/license review remains unresolved, so model binaries and datasets are not committed. The committed artifact manifest and evidence contain SHA/digests and reproduction code.

| Model | Bytes | SHA256 |
|---|---:|---|
|linux-network14-research-v1-quality_rf|117241|`53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603`|
|linux-network14-research-v1-edge_lr|1773|`661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882`|

Loader accepts RESEARCH_ONLY purpose only; explicit trusted manifest digest is required from a reviewed local receipt. Private owner-controlled root, no symlink components/final file, regular file/size/ownership checks, same library version, matching producer and feature contract. Model bytes are hashed **before** joblib deserialization. Hashing does not make untrusted pickle safe: never load outsider models or accept their hash/manifest as its own trust anchor. No generic executable model path comes from events/LLM.

## Independent Git Export

Baseline HEAD + only the8 new Python source/test files and this task metadata were exported separately. Train/validation/diagnostic **rows and manifests reproduced exactly**. Test **feature and label rows reproduced exactly** without another model prediction pass. Five models and validation predictions/metrics/thresholds reproduced identically in the Export. Original test confusion-derived precision/recall/F1/FPR/FNR were independently recalculated from the frozen receipt; AP/ROC and calibration are the original one-pass results, not a second test evaluation. Timing/RSS fields are measurements and are not required byte-identical.

Important source-identity distinction: existing uncommitted `src/ml/ctu13/pcap.py` adds only a PCAPNG second-interface guard. Original Lock correctly records that working-file SHA, while committed Export has HEAD version. Original Lock validation against Export therefore correctly returns TEST_LOCK_MISMATCH. The Lock was **not rewritten** or passed as identical. All four raw inputs are Classic PCAP, outside that changed branch; exact regeneration of all four datasets and models establishes no functional dependency for this experiment. Both source hashes and the reviewed scope are recorded. No existing user change is staged. This is bounded source equivalence, not global parser equivalence.

## SOC advisory readiness

No runtime registration or adapter implementation. Current SOC binding accepts Network Top40/DNS9 observation contracts and fixed legacy native backends, not this Network14 research artifact. The fitted scaler+LR and RF require separately reviewed versioned binding/backend support, explicit artifact trust, producer/source/provenance validation, bounded inference and advisory-only projection. None is automatically granted by research success. No Findings or investigations are generated from these scores. Existing NOT_INFERABLE, BLOCKED inference/Finding promotion, DIAGNOSTIC_ONLY and WRITE_DENIED remain unchanged. Syntheticv2 / Operational Provenancev3 semantics unchanged. Seven legacy artifact/scaler/feature identities verified unchanged.

## Commands

Use existing ML Python; start with new empty data/artifact paths. No download is performed. The recorded run used the fixed roles and final paths below.

```bash
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1
.venv/bin/python -m ml.network_research prepare --data data/processed/NEW-RESEARCH-RUN --artifacts models/NEW-RESEARCH-RUN
.venv/bin/python -m ml.network_research train --data data/processed/NEW-RESEARCH-RUN --artifacts models/NEW-RESEARCH-RUN
.venv/bin/python -m ml.network_research lock --data data/processed/NEW-RESEARCH-RUN --artifacts models/NEW-RESEARCH-RUN
# Review lock BEFORE final-test. This task already consumed its test pass.
# Do not re-run final-test for this task or tune against34-1.
.venv/bin/python -m ml.network_research final-test --data data/processed/NEW-RESEARCH-RUN --artifacts models/NEW-RESEARCH-RUN --trusted-lock-digest REVIEWED_DIGEST
```

## Tests and quality

Final executions (overlapping suites, do not sum):

| Execution | Result |
|---|---|
| Focused new research tests |35 passed|
| ML working broad |630 passed (3.17s)|
| ML independent Export broad |623 passed (4.77s)|
| SOC working configured broad |769 passed, 1 deselected in 603.48s (0:10:03)|
| SOC independent Export configured broad |759 passed, 1 deselected in 602.21s (0:10:02)|
| SOC AF_INET identity assertion, separate unbound socket only |1 passed (0.45s)|

The ML difference7 is pre-existing user CTU tests excluded from Export. The SOC difference10 is pre-existing untracked operational producer-parity tests excluded from Export. The AF_INET assertion is deselected only in the no-network guarded broad run and passed separately: open/unbound/close only, no bind/connect/send. The broad guard denied AF_PACKET/IPv4/IPv6 capture/traffic and records its prevented attempts. RUN_LIVE_LLM_TESTS=0; existing native regressions use verified legacy feature fixtures and the existing persistent `.security-ai-demo` backend, not operational raw inference or these research artifacts.

Initial failures were investigated and retained, not counted as passes:

- ML/SOC Python initially used for ML isolated-package import:511 passed,1 failed; corrected ML interpreter plus missing source paths:568 passed,1 failed; full explicit package paths produced the final630 passes. ML `.venv` lacks pytest/Ruff; existing SOC test/tool dependencies were reused without installation; model training and ML broad tests use ML Python.
- SOC first guarded invocation omitted repository root from spawned-child import path:734 passed,35 failed,1 skipped. Relative-root correction:760 passed,9 failed,1 skipped; independent Export:750 passed,9 failed,1 skipped. Remaining failures were8 obsolete `/tmp` native environment defaults and1 intentional AF_INET identity assertion blocked by the no-network guard.
- Absolute roots with AF_INET deselected: working760 passed,8 failed,1 skipped,1 deselected; Export750 passed,8 failed,1 skipped,1 deselected. Native paths then configured from READ-only verified persistent environment, producing the final passing executions above. No source/security control was changed to hide failures.

Ruff `check src tests`:PASS in both repositories, using the existing SOC Ruff executable from each respective repository cwd/config. SOC whole format:PASS. ML owned8 Python files format:PASS. ML whole format:24 pre-existing violations, preserved (not reported as a full-format pass). `git diff --check` and selected staged checks:PASS.

New tests cover manifest and feature tampering, source/label reference and group leakage, concordant/conflicting labels, float32/order/missing/NaN/Inf, train-only scaler, invalid output, trusted digest-before-deserialize, symlink/ownership, purpose/promotion denial, threshold/model source lock changes, duplicate final test and crash-after-reservation. All unit test data are synthetic; those test executions do not reopen actual34-1 model inference.


## Remaining blockers and next stage

No production qualification. Next stage needs a new independent evaluation source/protocol after the now-consumed34-1 result; verified host/campaign grouping and capture quality; lower observed FP/FN; calibration/base-rate analysis; native/offline producer parity; physical Linux CPU/memory validation; explicit artifact distribution and adapter review. No download, capture, model promotion, operating threshold/model replacement or OS security action was authorized or performed here.

## Changed files

New package files: `src/ml/network_research/{__init__,__main__,dataset,evaluation,artifacts,training,locked_test}.py`; new `tests/network_research/test_research.py`; this report; `network-research-training-evidence.json`; `network-research-artifact-manifest.json`; `network-research-test-lock.json`. Existing producers, binding sources, models, dependencies and user files unchanged.

Primary references: [scikit-learn persistence](https://scikit-learn.org/stable/model_persistence.html), [HistGradientBoosting](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.HistGradientBoostingClassifier.html), [LogisticRegression](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html).
