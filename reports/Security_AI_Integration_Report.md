# Security AI Integration Report

이 보고서의 본문은 통합 구현 단계의 검증 기록입니다. 후속 artifact 배포와 Git 반영 상태는
[배포 보고서](Security_AI_Artifact_Distribution_Report.md) 및
[artifact 설치 가이드](../docs/security_ai/artifact_installation.md)에 별도로 기록합니다.

검토일: 2026-10-12. 작업 저장소: `/home/geonug/kdt-linux/ML`.
모델 재학습, hyperparameter/threshold tuning, 기존 Test 재평가, commit/push는 수행하지 않았습니다.
SOC는 interface 참고 목적으로만 읽었으며 소스/환경을 수정하지 않았습니다.

## Executive Summary

**B안: Network/DNS 독립 패키지 + 상위 통합 패키지**를 구현했습니다.
기존 `network-security-ai` source/API/feature 계약은 그대로 보존합니다.
새 `dns-security-ai`가 공급된 INT8 DNN과 fitted scaler의 추론을 담당하고,
`security-ai`가 공통 predict Protocol 및 typed EvidenceEnvelope를 제공합니다.
Fusion, ensemble, SOC tool/policy/approval/execution은 구현하지 않았습니다.

실제 artifact로 Network LightGBM, Network DNN FP32, DNS DNN INT8의 standalone smoke 및
Network→DNS 별도 입력 순차 실행이 성공했습니다. 전체 테스트 **156 passed**
(Network 76 + DNS 61 + 통합 17 + benchmark regression 2), Ruff/Format PASS,
세 패키지 wheel/sdist 6개 build PASS입니다. Isolated base wheel 환경은 **148 passed, 6 skipped**이며
skip은 optional sklearn/pandas 없는 환경의 전처리 테스트입니다.

**신뢰성 제한:** 배포 DNS DNN의 학습/변환 코드와 평가 결과가 제공되지 않았습니다.
기존 detector와 같은 LiteRT 런타임에서 합성 35개 row의 전처리/확률/label 일치는 확인했지만,
train-only scaler fit, 모델과 scaler의 동일 학습 실행 출처, DNN test 성능은 **UNVERIFIED**입니다.
성능 검증을 완료했다고 표시하거나 notebook의 다른 모델 수치를 DNN 성능으로 사용하지 않습니다.
Native TensorFlow runtime smoke도 UNVERIFIED입니다.

## 작업 전 안전 점검

| 항목 | 확인 결과 |
|---|---|
| Branch | main |
| Recent HEAD | 59c16b2 `feat: make network security AI reproducible and shareable` |
| 이전 commit | a7a81c0, 1e08049, 6072fd7, 8894a70 |
| 초기 status | `?? packages/dns_security_package/`만 존재; 기존 사용자 파일 보존 |
| 기존 Network | packages/network-security-ai, 자체 pyproject/uv.lock/resources/tests/CLI |
| 새 DNS 공급 위치 | packages/dns_security_package/dns_security_package/dns_security |
| Python / uv | CPython 3.12.14 / uv 0.12.8 |
| 기존 환경 | root .venv(실험 dependencies), Network 자체 .venv(pytest/Ruff) |
| Resource | WSL2 x86_64, RAM 약 7.6 GiB, 조사 시 available 약 1.5 GiB; 모델별 별도 프로세스로 측정 |
| Gitignore | 기존 data/, models/, parquet, build/cache 제외 유지; 공급 DNS artifact와 Zone.Identifier 제외 추가 |
| SOC 환경 경계 | ambient VIRTUAL_ENV가 SOC를 가리켜도 명시한 Python 및 /tmp env 사용; SOC sync/install 없음 |
| 보호 | reset/clean/delete/stage/commit/push 없음; 기존 모델/실험/notebook/결과 덮어쓰기 없음 |

검증 환경은 `/tmp/security-ai-validation`, `/tmp/security-ai-wheel-check`,
`/tmp/security-ai-uv-sync`에 생성했습니다. 첫 환경은 기존 dependency 디렉터리를 .pth로 재사용하며
LiteRT/build 도구만 별도 설치했습니다. 두 번째 wheel 환경은 독립 설치입니다.
Sandbox cache read-only 및 DNS resolution 실패에는 도구 승인 흐름을 사용했습니다.
대형 CSV/Parquet는 로드하지 않았고 원본 dataset을 평가에 사용하지 않았습니다.

## DNS Model Review

### 전체 조사와 파일 분류

제공 DNS 관련 원본 **23개 파일**(Zone.Identifier 포함), 모든 notebook source,
Python/README/requirements/metadata 및 두 DNS PDF를 검토했습니다.
PDF는 PyMuPDF로 텍스트를 읽었습니다. 세부 파일별 역할·dependencies·실행 상태·SHA-256은
[source_inventory.md](../docs/security_ai/source_inventory.md) 및
[dns_source_inventory.json](security_ai/dns_source_inventory.json)에 있습니다.

| 분류 | 실제 파일 / 역할 |
|---|---|
| TRAINING | reports/CIC-Bell-DNS-EXF-2021_DNS_Security_ML.ipynb: RF/XGB/LGBM/IF 실험 학습 |
| PREPROCESSING | 같은 ML notebook의 9-column 선택; legacy detector의 named scaler transform/INT8 변환 |
| INFERENCE | 제공 dns_security/detector.py, __init__.py, demo.py |
| EVALUATION | ML notebook saved metrics/plots, ML_clean.pdf; demo는 2-row 예시뿐 |
| ARTIFACT | model/dnn_int8.tflite, preprocessor/scaler.joblib |
| EXPERIMENT | DNS EDA/ML notebook; EDA는 stateful feature도 탐색하지만 배포 모델은 stateless9 |
| DOCUMENTATION | 제공 README, requirements_addon.txt, EDA/ML PDF |
| UNUSED | Windows Zone.Identifier metadata; 코드·모델 자체는 사용 불명으로 삭제하지 않음 |

검색에서 DNN training/export 코드, FP32 DNS checkpoint, calibration/encoder/imputer,
RF/XGB/LGBM/IF serialized DNS model을 발견하지 못했습니다.
`notebooks/data.ipynb`의 DNS 언급은 dataset 계획이며 DNS DNN 학습 구현이 아닙니다.
제공 패키지는 pyproject가 없고 eager import/implicit dependencies를 사용합니다.
requirements_addon은 TensorFlow 2.21.0만 명시하여 standalone 설치 사양으로 불충분합니다.
Legacy source는 비교 reference로 보존하고 신규 추론 패키지에서 import하지 않습니다.

### 배포 DNN INT8

| 항목 | 실제 확인 |
|---|---|
| Algorithm | TFLite fully connected DNN: 9→64→32→16→1, hidden ReLU, 최종 LOGISTIC(sigmoid) |
| Task | binary classification; anomaly detector/회귀 아님 |
| 모델 ID / content version | dns_cicbell_dnn_int8 / int8-sha256-28e089af363d |
| 원래 training version / optimizer/loss/epochs | UNVERIFIED: DNN 학습 코드/metadata 없음 |
| Dataset | detector와 notebook은 CIC-Bell-DNS-EXF-2021 stateless9 convention; 실제 DNN dataset pairing UNVERIFIED |
| Feature 수/순서 | 9; detector, notebook cell5, scaler.feature_names_in_에서 정확히 일치 |
| Raw input dtype | float32; 모델 입력은 INT8 [1,9] |
| Preprocessing | named float32 DataFrame → StandardScaler.transform → INT8 round/clip |
| Scaler | StandardScaler, with_mean=True, with_std=True, n_features_in_=9, n_samples_seen_=162880 |
| Scaler serialization version | sklearn 1.9.1; 현재 1.9.1 load 시 version warning 없음 |
| Missing | imputer 없음; notebook 저장 출력은 선택 feature null=0; 신규 API는 None/NaN/Inf 거부 |
| Output | INT8 [1,1] → dequantized sigmoid probability |
| Class IDs/labels | 0=NORMAL, 1=MALICIOUS; legacy/notebook convention 유지; DNN training mapping UNVERIFIED |
| predict_proba | legacy DNSDetector.predict_proba 지원; 신규 typed predict의 probability 필드로 보존 |
| Calibration | artifact/code 없음; calibrated라고 주장하지 않음 |
| Decision | probability >=0.5 → MALICIOUS; legacy default, 선정 근거 UNVERIFIED |
| Score direction | 클수록 모델이 malicious class를 높게 출력; anomaly score 아님 |
| Input quantization | scale=0.0387900173664093, zero=-40 |
| Output quantization | scale=0.00390625=1/256, zero=-128 |
| Runtime | 원래 TF2.21 요구; 실제 검증 LiteRT2.3.0, CPU num_threads=1 |
| 정확도 | UNVERIFIED; 새 smoke는 정확도 평가 아님 |

Tensor/ops 전체는 [dns_tflite_review.json](security_ai/dns_tflite_review.json), scaler 통계는
[dns_scaler_review.json](security_ai/dns_scaler_review.json)에 있습니다.
Model/scaler 두 SHA-256을 하나의 reviewed bundle로 pin했으므로 이후 혼합을 거부합니다.
다만 현재 두 파일이 같은 원래 학습 run에서 생성되었는지를 hash만으로 증명할 수 없습니다.
Scaler sample 수가 notebook train 수와 같은 것은 지지 근거이며 train-only fit 증명이 아닙니다.

### 실험 모델별 검토

다음은 ML notebook의 **저장 출력**입니다. 이번에는 모델을 fit하거나 test를 재사용하지 않았습니다.
Dataset은 Benign/stateless_features-benign_1.pcap.csv 132,499 rows와
Attack_heavy_Benign/Attacks/stateless_features-heavy_text.pcap.csv 71,102 rows,
총 203,601 rows입니다. Label은 파일별 benign=0/attack=1로 추가합니다.
162,880 train / 40,721 test, stratify=y, random_state=42, test_size=0.2입니다.
모두 같은 stateless9 raw numeric input이며 categorical encoder/scaler는 이 실험 코드에 없습니다.

| 실험 모델 | 설정/목적 | Accuracy | malicious Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|
| RandomForestClassifier | n_estimators=100, random_state42; binary classifier | 0.7162643354 | 0.5519134192 | 0.9969059841 | 0.7104841135 |
| XGBClassifier | 100 trees, depth6, lr0.1, eval_metric=logloss; binary classifier | 0.7163134501 | 0.5519402172 | 0.9971872583 | 0.7105777421 |
| LGBMClassifier | 100 trees, lr0.1; binary classifier | 0.7162397780 | 0.5518919340 | 0.9969059841 | 0.7104663109 |
| IsolationForest | 100 trees, contamination=auto; mixed train X에서 unsupervised fit | 0.5353994254 | 0.2084160874 | 0.1180648337 | 0.1507384298 |

Classifier metric은 sklearn accuracy_score/precision_score/recall_score/f1_score의 binary
positive label1 계산입니다. RF/XGB/LGBM은 해당 classifier의 predict_proba API를 제공하지만
notebook은 predict label만 평가하고 calibration은 구현하지 않습니다. Artifact가 없어
이 실험 모델의 standalone inference/backend를 새로 만들어 제공하지 않습니다.

IsolationForest는 predict의 -1=outlier/+1=inlier를 attack1/normal0으로 매핑하여
classifier metric을 계산합니다. Probability를 출력하지 않습니다. 현재 설치 sklearn 구현의
decision_function은 score_samples−offset_, 작을수록 outlier, 0 미만이 이상이며
contamination=auto의 offset은 -0.5입니다. 이는 라이브러리 의미와 notebook 설정 검토이며
저장된 fitted detector/offset/score 평가 artifact가 없으므로 실제 학습 실행 threshold metadata는
UNVERIFIED입니다. Train X에는 공격도 포함되어 있어 benign-only anomaly 학습으로 설명할 수 없습니다.

RF/XGB/LGBM은 높은 recall과 약 0.552 precision으로 False Positive 문제가 있습니다.
Benign_1와 heavy_text 대표 파일의 결과이며 다른 공격 유형/전체 DNS/운영 성능으로 일반화하지 않습니다.
이 수치를 배포 DNN의 성능으로 인용하지 않습니다.

### DNS 데이터 누수 및 평가 감사

| 검토 항목 | 상태 | 근거 / 영향 |
|---|---|---|
| train/test 분리 | VERIFIED (실험 notebook) | stratified random row split 80/20; 별도 validation 없음 |
| DNN train/validation/test | UNVERIFIED | 학습 코드 없음 |
| 동일 record 중복 처리 | 코드상 없음; 실제 overlap UNVERIFIED | dedup/hash-disjoint check 없음; DNS CSV 없음 |
| domain/entity/session overlap | UNVERIFIED | group split/audit 없음; raw domain/session feature 제외만으로 leakage를 배제할 수 없음 |
| 시간 순서 | 시간 holdout 없음 | random split, time sort/capture-disjoint split 없음; 분포 일반화 제한 |
| 직접 label 포함 | 선택 X에는 없음 | 명시 9-column 중 label/file/source/timestamp/IP 포함 안 함 |
| 간접 feature/source leakage | UNVERIFIED | 두 capture 파일로 label 생성; file/source 편향을 검증하지 않음 |
| experiment preprocessing fit | X column 선택뿐 | scaler/imputer fit 없음; 일부 EDA는 전체 비교이므로 unbiased selection 증명은 아님 |
| DNN scaler train-only fit | UNVERIFIED | 162880 sample metadata만 확인; 실제 fit 대상 코드 없음 |
| 클래스 불균형 | VERIFIED 저장 출력 | train 105999 normal /56881 attack; test26500/14221; imbalance 존재 |
| Threshold tuning | DNN 근거 UNVERIFIED | supplied 0.5 고정; notebook IF auto 설정; 새 tuning 없음 |
| Test 재사용 | 기존 실험 4개 같은 test 사용 | 모델 비교에 사용; 독립 최종 holdout 증명 아님; 이번 test 사용 없음 |
| Metric 계산 | VERIFIED notebook code/output | binary label1; IF label mapping 후 계산; saved outputs 미재실행 |
| DNN calibration/INT8 accuracy loss | UNVERIFIED | 비교 평가/변환 representative data 코드 없음 |

DNS 원본 CSV 부재로 데이터 기반 중복/분할/entity 감사를 새로 실행하는 것은 **BLOCKED**입니다.
학습 source 부재로 DNN train/inference preprocessing 전체 일치 감사는 **BLOCKED/UNVERIFIED**입니다.
문제를 재학습이나 test tuning으로 우회하지 않았습니다.

## Network Model Review

기존 package를 read-only 검토하고 현재 source의 76 tests를 다시 실행했습니다.
이전 검증 숫자를 현재 결과로 대체하지 않았습니다.

| 파일/영역 | 역할 / 검토 결과 |
|---|---|
| contracts.py | Top40 exact rank order/15-label mapping, bounded input, manifest digests, config path containment |
| preprocessing.py | training mean imputation → saved scaler transform → FP32, no fit |
| predictors.py | lazy LightGBM V4-B2 / DNN epoch13; model feature/class/epoch/scaler 검증, per-predictor lock |
| adapter.py | enabled/profile factory와 existing Protocol; public API 보존 |
| schema.py | immutable prediction, class probabilities sum/argmax/UTC validation |
| evidence.py | network-evidence-v1, typed payload, optional flow_reference; no actions/raw input |
| artifact_manifest.json/resources | 기존 model/scaler/Top40/mapping hashes; bundled CSV/JSON portable resources |
| __main__.py | 기존 standalone Network CLI; 수정 없이 유지 |
| tests/fixtures | Network 계약/loader/adapter/evidence/resource/standalone regression 76 PASS |
| pyproject.toml / uv.lock | 독립 build와 quality/edge optional extras; 변경 없음 |

LightGBM은 native missing 처리를 사용하고 scaler를 적용하지 않습니다.
DNN은 40→128(BatchNorm/ReLU/Dropout)→128(BatchNorm/ReLU/Dropout)→64(ReLU)→15,
CPU FP32 softmax이며 checkpoint epoch13/Top40를 검증합니다.
현재 `notebooks/dnn_top40_v4.ipynb`는 52 cells/86,992 bytes의 코드 notebook입니다.
TRAIN_PATH에서 100,000-row Parquet iter_batches로 StandardScaler.partial_fit하고,
동일 mean imputation/transform을 학습·validation에 사용하는 코드를 확인했습니다.
과거 보고서의 0-byte notebook 제한을 현재 상태의 사실로 재사용하지 않았습니다.

저장된 full validation metric 재확인: LightGBM MacroF1=0.8086545334668387,
DNN FP32 MacroF1=0.6986469531097897, 양쪽 rows=2390002.
새 정확도 평가가 아닙니다. Validation 중심 개발, 기존 Test V2 소비, minority class/운영
일반화와 calibration 제한은 그대로 유지합니다.

## Network / DNS Comparison

| 항목 | Network | DNS |
|---|---|---|
| 데이터 단위 | precomputed CIC Network flow | stateless DNS query/string-feature record; exact extraction aggregation UNVERIFIED |
| Input | Top40 CSV canonical rank order | named stateless9; scaler.feature_names_in_ 확인 |
| Model | LightGBM V4-B2 또는 DNN FP32 | Dense INT8 TFLite DNN binary classifier |
| Output | NetworkThreatPrediction 15-class | DNSThreatPrediction binary |
| Score | confidence=max class P; threat=1−P(Benign) | uncalibrated malicious sigmoid P; fixed threshold0.5 |
| Preprocessing | LightGBM native NaN; DNN mean impute/scaler | nonfinite reject; stored scaler→INT8 quantization |
| Artifact | 48.64 MB Booster; 398041-byte checkpoint +1543-byte scaler | 9288-byte model +1135-byte scaler |
| Evidence | existing network-evidence-v1 | new dns-evidence-v1 with UUID and artifact digests |
| Runtime | optional lightgbm OR torch/joblib/sklearn | optional LiteRT OR TF; joblib/sklearn/pandas |

하나의 input/event/score로 통합하지 않고 관측별 입력과 typed payload를 분리했습니다.

## Architecture Decision

| 기준 | A: Network 확장 | B: 독립 Network/DNS + 상위 | C: 신규 코드 병합 |
|---|---|---|---|
| 코드 중복 | 적지만 Network에 DNS 책임 결합 | 각 backend canonical 1개; re-export만 | 기존 API 보존용 wrapper/복제 위험 |
| 기존 API 호환성 | 변경 영향 주의 | existing source/object 그대로 | module 이동/중복 유지 필요 |
| 테스트 유지 | 테스트 의존성 섞임 | 기존76 그대로; DNS/상위 별도 | 재배치/fixture 이관 필요 |
| 독립 배포 | DNS 단독 배포 어려움 | Network/DNS 각 wheel 가능 | 공통 release에 결합 |
| dependency 충돌 | Network extras에 DNS runtime 추가 | heavy dependencies optional; base 둘은 numpy/pydantic만 | 환경 범위 크게 결합 |
| artifact 관리 | unrelated 계약을 Network manifest에 혼합 | 각 package manifest/typed model identity | 하나의 mixed inventory 위험 |
| Authentication 확장 | Network 이름/책임 불일치 | 세 번째 독립 package + typed envelope 확장 가능 | 거대 패키지 누적 |
| SOC 설치 | package1개지만 역할 결합 | 상위 + 두 lightweight wheel; extras 선택 | 단일 wheel 편리, API migration 비용 |

**B 선택:** Network canonical 구현의 변경 없이 independent DNS packaging과
thin integration boundary를 제공할 수 있습니다. 상위 base에는 두 schema package가 있지만
heavy runtime은 선택 extra이며 import/predict 미사용 backend는 로딩되지 않습니다.
기존 공급 DNS code는 비교용 사용자 파일로 보존되며 새 유지보수 canonical source는 아닙니다.
학습 notebook/기존 모델을 runtime으로 복제하거나 새로운 ensemble을 만들지 않았습니다.

## Final Package Structure

```text
packages/
├── network-security-ai/                 # 기존 source/API 그대로
├── dns_security_package/                # 사용자 제공 원본 보존, 새 runtime 의존성 아님
├── dns-security-ai/
│   ├── pyproject.toml, uv.lock, README.md
│   ├── src/dns_security_ai/
│   │   ├── contracts.py, feature_contract.json
│   │   ├── preprocessing.py, predictor.py
│   │   ├── artifacts.py, artifact_manifest.json
│   │   ├── evidence.py, errors.py, cli.py
│   │   └── __init__.py, __main__.py
│   ├── tests/                           # contract/loading/preprocess/evidence/security
│   └── examples/synthetic_stateless9.json
└── security-ai/
    ├── pyproject.toml, uv.lock, README.md
    ├── src/security_ai/
    │   ├── common/contracts.py, common/evidence.py
    │   ├── network/__init__.py           # existing objects 재노출
    │   ├── dns/__init__.py               # canonical DNS objects 재노출
    │   └── cli.py, __init__.py, __main__.py
    └── tests/test_integration.py
docs/security_ai/
scripts/security_ai_smoke.py
scripts/verify_dns_legacy_parity.py
reports/security_ai/                     # 이번 검증 기록, 기존 실험과 분리
```

## Feature Contracts

Network Top40는 기존 package resources/top40_features.csv의 40 ranks와 version
`cse-cic-ids2018-top40-v1`을 유지합니다. Label mapping과 원래 `Infilteration` 철자도 보존합니다.
Numeric 문자열 허용 및 None/NaN/Inf 처리 등 기존 input API는 변경하지 않았습니다.

DNS schema `cic-bell-dns-stateless9-v1`:

| Position | Name | Dtype / required | Missing / range | Units |
|---:|---|---|---|---|
| 0 | FQDN_count | float32 / yes | reject; finite >=0 | dataset의 FQDN 문자수로 EDA 설명; extractor definition UNVERIFIED |
| 1 | subdomain_length | float32 / yes | reject; finite >=0 | dataset length; 정확한 계산 규칙 UNVERIFIED |
| 2 | numeric | float32 / yes | reject; finite >=0 | dataset numeric-count convention; extractor UNVERIFIED |
| 3 | entropy | float32 / yes | reject; finite >=0 | entropy base/normalization UNVERIFIED |
| 4 | special | float32 / yes | reject; finite >=0 | special character counting rule UNVERIFIED |
| 5 | labels | float32 / yes | reject; finite >=0 | label-count convention; extractor UNVERIFIED |
| 6 | labels_max | float32 / yes | reject; finite >=0 | label maximum convention; extractor UNVERIFIED |
| 7 | labels_average | float32 / yes | reject; finite >=0 | label average convention; extractor UNVERIFIED |
| 8 | len | float32 / yes | reject; finite >=0 | exact dataset length distinction UNVERIFIED |

모든 값의 상한은 float32 표현 범위입니다. 이 범위는 inference numeric guard이며
학습 분포나 DNS protocol의 물리 상한을 임의로 주장하지 않습니다.
Bool/string/container/missing/extra keys 거부; dict order와 무관한 canonical ordering.
Scaler는 전체 names/order/type/config/stats/sample metadata 및 hash를 검증합니다.
학습의 feature selection 순서는 notebook cell5, 공급 detector, scaler에서 일치하지만
DNN training matrix의 실제 순서는 코드 부재로 별도 UNVERIFIED입니다.

Legacy parity는 stored scaler로 같은 DataFrame dtype/order를 재현하고 양자화 결과를
byte 비교합니다. 합성35 rows에서 output probability/label도 exact equality입니다.
같은 LiteRT Interpreter를 old TF import에 adapter로 연결한 결과이므로
native TF↔LiteRT runtime equivalence로 잘못 표시하지 않습니다.

## Artifact Inventory

| Artifact / 실제 위치 | Bytes | Version / 필요 preprocessing | SHA-256 |
|---|---:|---|---|
| models/network/lightgbm_top40_v4b2.txt | 48637456 | v4-b2; no scaler | eb28cc855a65d336cd1b2720ec4fcc2958874444e33fae5b78c1cae4e4c62924 |
| models/network/dnn_top40_v4_best.pt | 398041 | v4-fp32-epoch13; 다음 scaler | 85cbc702d1b0a137c4f44b23be6911691cc89d5bfef0c388cf282e9500c49160 |
| models/network/dnn_top40_v4_scaler.joblib | 1543 | Network trained scaler | 528cfa770181bb61bdcc5d30b2cae8a171dfa63399f3fd33f9a15ab5fbc67d32 |
| packages/dns_security_package/dns_security_package/dns_security/model/dnn_int8.tflite | 9288 | int8-sha256-28e089af363d; 다음 scaler | 28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33 |
| packages/dns_security_package/dns_security_package/dns_security/preprocessor/scaler.joblib | 1135 | DNS StandardScaler9, sklearn1.9.1 | 2735f7650a7d7888ee68f2df870b4e29d83666962931ae2aecb9aa339f40266a |

작은 Network Top40/mapping SHA-256, runtime dependency versions, input contract version과
배포 scope는 [artifact_inventory.json](security_ai/artifact_inventory.json)에 추가 기록했습니다.
Network 기존 manifest와 DNS 새 manifest는 각각 canonical bundle authority입니다.
상위에 두 hash set을 별도의 mutable loader manifest로 복제하지 않았습니다.

### 배포 방식 비교

| 방식 | 장점 | 현재 적용 판단 |
|---|---|---|
| 일반 Git | 작은 metadata/code 리뷰 쉬움 | manifest/feature/mapping/source만 추가; DNS10KB도 기술적으로 작지만 신뢰/정책 미확정이므로 이번에는 모델 제외 |
| Git LFS | 큰 binary를 repo 버전과 연결 | 팀 LFS 사용/용량 정책 미확정; 별도 운영 필요 |
| GitHub Release | versioned trusted bundle를 code와 분리 | 팀 공유의 간단한 후보; URL/Release 생성 미수행 |
| 별도 artifact storage | access control/immutable revision 관리 | 여러 모델·환경의 장기 운영에 적합; endpoint 미정 |

추천: reviewed bundle을 Release 또는 팀 trusted artifact storage로 별도 공유하고
model+preprocessor+manifest를 같이 버전 관리합니다. 다운로드 주소를 임의로 작성하지 않습니다.
48.6MB Network model 및 training datasets를 일반 Git에 새로 추가하지 않습니다.
Joblib은 trusted source only, Torch는 기존 weights_only=True, 모든 model load 전에 checksums.
Checksum/containment는 administrator-controlled root를 전제로 하며 공급망 서명 인증을 대신하지 않습니다.

## Evidence Schemas

| Schema | 내용 / 의미 |
|---|---|
| network-evidence-v1 | 기존 source/evidence_type/prediction/flow_reference 그대로 |
| dns-evidence-v1 | unique evidence_id, source, prediction, optional observation_ref; raw payload 없음 |
| security-ai-envelope-v1 | evidence_id/type/source/model_id/version/inference timestamp/observation_ref/typed payload |

Envelope는 confidence나 generic risk score를 추가하지 않습니다.
Network confidence/class probabilities/threat_score와 DNS probability/threshold/score_type는
각 typed payload 안에서 유지됩니다. DNS는 model/scaler/feature digests도 유지합니다.
UTC timestamp는 추론 receipt time이며 원래 observation time을 생성하지 않습니다.
참조가 없으면 null이고 UUID는 receipt tracking입니다. Network를 재감싸면 새 UUID이므로
deduplication에는 이미 만든 envelope를 저장해 재사용해야 합니다.
Frozen schemas와 nested tuples/snapshots를 사용하고 arbitrary mutable metadata/raw features는 넣지 않습니다.
Pydantic model_copy를 통한 잘못된 instance도 public conversion에서 revalidate합니다.
Evidence에 tool 실행·policy 판단·approval/action field가 없습니다.

## Test Results

최종 full run은 빌드 wheel을 `/tmp/security-ai-validation`에 설치하고
pytest `-o pythonpath=''`로 실행했습니다. Dependencies는 root/Network 환경을 재사용합니다. 별도 clean uv-sync 환경에서는 같은 154개 package tests가 모두 통과했고, 무거운 Torch가 필요한 benchmark2개는 full 환경에서만 실행했습니다. 구조화된 최종 상태는 [validation.json](security_ai/validation.json)에 있습니다.

```bash
/tmp/security-ai-validation/bin/python -m pytest -o pythonpath='' \
  -c packages/security-ai/pyproject.toml packages/security-ai/tests \
  packages/dns-security-ai/tests packages/network-security-ai/tests scripts/tests -q
```

| 검증 | 최종 결과 / 근거 |
|---|---|
| Network regression | 76 PASS, 첫 독립 실행과 최종 full run 모두 |
| DNS unit / upper integration | 61 + 17 = 78 PASS |
| 기존 benchmark regression | 2 PASS, mock data; 대형 dataset 사용 없음 |
| 전체 | 156 passed, warnings 없음; full_tests.xml |
| clean base wheel dependencies | 148 passed, 6 optional preprocessing skips; base_wheel_tests.xml |
| fresh python -I wheel import | 세 package import PASS, heavy runtimes/SOC imported 안 됨 |
| optional dependency isolation | fake import blocker, installed base-only env, lazy selected backend 검증 PASS |
| Feature/preprocess | order/scalar/missing/NaN/Inf/overflow/wrong scaler name order PASS |
| Artifact/security | missing, size/hash corruption, mixed scaler, model/tensor mismatch, symlink escape PASS |
| Output/evidence | invalid score semantics, version, provenance, metadata, immutable nested snapshots PASS |
| Failure isolation | DNS failure 후 Network 성공 및 반대 방향 PASS |
| CLI | bounded JSON, duplicate keys, malformed source, sensitive output suppression PASS |
| Ruff / Format | 기존 Network + 새 두 패키지 + 새 scripts PASS |
| Wheel/sdist | 세 패키지의6 builds PASS, package metadata 포함 및 artifact/SOC 제외 확인 |
| Lockfile | 두 신규 uv.lock 생성; offline --check PASS |
| uv sync base / selected extras | frozen/no-dev/offline base PASS; frozen network-quality + dns-litert extras PASS |
| Fresh locked team environment | 154 passed; actual Network/DNS CLI exit0; Pydantic2.14.1, Ruff0.17.0 |
| git diff --check | PASS |

초기 benchmark 수집은 Network 자체 환경에 pandas가 없어 실패했고, 별도 validation 환경에서
필요 dependency를 연결한 뒤 PASS했습니다. 전체 suite를 처음 함께 실행할 때 fixture `features`
충돌이 있어 신규 DNS fixture를 `dns_features`/`dns_scaler`로 분리했습니다.
기존 Network tests/source는 변경하지 않았으며 final run failures=0입니다.
별도 env의 -I import에는 PYTHONPATH만으로 설치를 대체할 수 없어 실제 wheel을 설치했습니다.
이 초기 setup 실패들을 모델 PASS로 간주하지 않았습니다.

최종 standard offline build output은 `/tmp/security-ai-dist-final/`; hashes/size는
[build_inventory.json](security_ai/build_inventory.json)에 있습니다. 모델 파일은 모든 wheel/sdist에 없습니다.
다른 standalone package release와 같은 이름의 신규 wheel을 기존 reports dist에 덮어쓰지 않았습니다.

## Standalone Inference Results

| 실제 backend | Artifact load | predict / schema | CLI | 근거 |
|---|---|---|---|---|
| Network LightGBM V4-B2 | PASS | NetworkThreatPrediction + NetworkSecurityEvidence + envelope | exit0 | network_quality_smoke.json / cli_network_quality.json |
| Network DNN FP32 epoch13 | PASS | 동일 typed Network schema, profile=edge | exit0 | network_edge_smoke.json / cli_network_edge.json |
| DNS INT8 LiteRT | PASS | DNSThreatPrediction + DNSSecurityEvidence + envelope | exit0 | dns_smoke.json / cli_dns.json |
| Network→DNS 순차 | PASS | 서로 다른 input과 source, DNS가 선택 전까지 unloaded | PASS | sequential_smoke.json |
| DNS native TensorFlow2.21 | UNVERIFIED | 메모리 제한 환경에서 별도 TF 설치/실행하지 않음 | UNVERIFIED | optional backend code만 제공 |
| DNS training preprocessing 일치 | UNVERIFIED | supplied inference와는35-row exact parity; training source 없음 | 해당 없음 | dns_legacy_parity.json |

입력은 Network feature별0..39, DNS supplied sample-derived numeric values 및 합성 rows입니다.
Observation/capture 정답이 없으므로 accuracy/recall PASS 판정이 아닙니다.
Legacy parity는 같은 LiteRT interpreter로 원래 detector를 실행하여 INT8 input bytes와
probability/label/threshold를 비교한 migration 검증입니다.

## Resource Measurements

환경: CPython3.12.14, WSL2 Linux6.18.33.2 x86_64, CPU.
NumPy2.5.4, pandas3.0.6, sklearn1.9.1, joblib1.6.0,
LightGBM4.7.0, Torch2.14.1, LiteRT2.3.0, Pydantic2.13.5.
각 모델은 별도 process에서 import/load하고 warmup5 calls, 각 size에10 trials를 실행합니다.
Latency는 feature/output validation과 single-record public API를 포함한 wall time median입니다.
32는 native vector batch가 아니라 **32회 순차 predict**이며 모델 architecture는 변경하지 않았습니다.
Load는 integrity checks+dependency import+model/scaler setup입니다. Peak RSS는 Linux ru_maxrss입니다.

| Backend | Model load ms | Batch1 median ms | 32 sequential median ms | Peak RSS MiB |
|---|---:|---:|---:|---:|
| LightGBM V4-B2 | 1930.795 | 5.564 | 89.430 | 281.613 |
| DNN FP32 | 4705.929 | 0.540 | 12.918 | 649.707 |
| DNS INT8 | 1587.612 | 1.154 | 55.722 | 199.637 |

실측 JSON은 `reports/security_ai/*_smoke.json`이며 first call/setup과 max latency도 기록합니다.
WSL background load/allocator/caches 영향을 받으므로 일반 성능 보장이나 기존 Network
warm backend benchmark와 직접적인 우열 비교를 하지 않습니다. ARM/NPU 결과가 아닙니다.

Direct installed distribution footprint: numpy53.776 MiB, pydantic1.806+core4.800 MiB,
lightgbm9.288 MiB, torch1091.207 MiB, LiteRT56.907 MiB,
pandas37.138 MiB, sklearn29.609 MiB, scipy106.753 MiB, joblib0.879 MiB.
[dependency_footprint.json](security_ai/dependency_footprint.json)의 file stat 합이며
transitive CUDA/runtime packages, cache, 공유 환경 중복은 제외하여 전체 설치 용량으로 해석하지 않습니다.
LiteRT만 실행할 때 Torch를 설치/로드할 필요가 없습니다.

## Remaining Issues

1. **UNVERIFIED/BLOCKED:** DNS DNN 학습/export code, original dataset/split mapping,
   train-only scaler fit, 같은 학습 실행 model/scaler pairing, training feature order/loss/optimizer.
2. **UNVERIFIED:** DNS DNN metrics, calibration, threshold0.5 선정 근거, INT8 conversion accuracy.
3. **BLOCKED:** DNS raw CSV absent; duplicates/domain/entity/session/time overlap 실제 감사 불가.
4. **UNVERIFIED:** native TensorFlow runtime and 다른 플랫폼/실제 production traffic.
5. Artifact distribution endpoint/owner/Release/LFS 정책 미확정. URL/다운로드를 만들지 않았습니다.
6. Raw feature extractor 정확한 규칙·단위 부재. SOC가 raw domain에 임의 extractor를 적용하면 안 됩니다.
7. SOC 내부 adapter/incident binding, Fusion/운영 품질 판단은 다음 단계입니다.
8. Network 기존 Validation/Test 사용 이력 및 일반화/calibration 제한 유지.

학습 코드 경로/commit을 사용자에게 비동기 요청했고, 제공되기 전에는 학습 검증을 완료로 표시하지 않습니다.
누락된 모델을 다른 알고리즘으로 대체하거나 새 threshold/ensemble을 만들지 않았습니다.

## SOC Integration Readiness

**설치·추론·evidence 소비 경계는 준비되었습니다. 운영 탐지 신뢰성과 SOC 내부 연결은 별도 검증이 필요합니다.**
Read-only SOC inspection에서 SecurityAIResult/AISignal은 incident_id 및 source_evidence_ids를
IncidentState와 검증합니다. 신규 package envelope에는 incident나 SOC evidence ID를 만들어 넣지 않습니다.
후속 application-owned adapter가 관측 linkage, incident/source references, coverage/failure,
transport authenticity와 persistence를 책임져야 합니다.

상세 설치/API/schema/score/error/artifact 및 SOC/AI 책임은
[soc_integration_contract.md](../docs/security_ai/soc_integration_contract.md)에 있습니다.
Evidence Fusion → ThreatAssessor → Investigation → Policy → Human Approval → Execution은
이번 코드 경계 밖입니다. 모델 receipt가 tool 실행이나 공격 확정/대응 승인을 수행하지 않습니다.

## Completion Checklist

| 요구 | 상태 |
|---|---|
| DNS 코드/모델 inventory 및 review | PASS; 불확실성 별도 명시 |
| DNS training↔inference preprocessing 전체 일치 | **UNVERIFIED/BLOCKED: training code 없음** |
| DNS legacy inference↔신규 preprocessing/prediction | PASS: same-runtime35-row parity |
| Network 기능/API 유지 | PASS: source 변경 없음, regression76 |
| DNS Predictor / Evidence / 공통 인터페이스 | PASS |
| Artifact manifest / distribution 문서 | PASS; 실제 endpoint 미정 |
| SOC 없이 import / Network·DNS standalone | PASS: LiteRT DNS; native TF UNVERIFIED |
| Network/DNS/integration/security tests | PASS; clean base optional preprocessing6 skips 명시 |
| Ruff / Format / wheel / sdist | PASS |
| README / integration contract / final report | PASS |
| 운영 정확도 / SOC 실제 adapter 연결 | UNVERIFIED / 다음 단계 |

## Commit File List

이번 작업에서 **stage/commit은 수행하지 않았습니다**.
정확한 신규 파일 목록은 [changed_files.json](security_ai/changed_files.json)에 기록합니다.

추가 대상:

- `.gitignore`, root `README.md`의 통합 package 안내.
- `packages/dns-security-ai/`: pyproject/lock/README, canonical source/feature+artifact manifest,
  synthetic example, unit tests.
- `packages/security-ai/`: pyproject/lock/README, Protocol/envelope/re-exports/CLI, integration tests.
- `docs/security_ai/source_inventory.md`, `docs/security_ai/soc_integration_contract.md`.
- `scripts/security_ai_smoke.py`, `scripts/verify_dns_legacy_parity.py`.
- 이 보고서 및 `reports/security_ai/`의 작은 JSON/XML 검증 기록.

제외 대상:

- 기존 사용자 미추적 `packages/dns_security_package/` 원본 전체는 이번 구현 변경 목록이 아니며
  canonical packaging에 필요하지 않습니다. 제공 source 보존/공유 여부는 팀이 결정합니다.
- 모델5개, 공급 DNS `.tflite`/`.joblib`, `models/`, DNS/Network raw/processed data,
  parquet/large CSV, Zone.Identifier.
- /tmp 검증 환경·uv cache·빌드 wheel/sdist, .venv/.pytest_cache/.ruff_cache, 기존 실험 patch/log.
- SOC checkout 및 SOC의 모든 source/config/environment.

기존 Network files/notebook/모델/실험 결과는 수정 목록이 아닙니다.
아래 파일 표는 이번 작업에서 만든 파일과 변경한 tracked 파일만 나열하며,
사용자가 제공한 미추적 원본은 별도 보존합니다.

<!-- Generated final file list follows. -->

| Status | Actual path |
|---|---|
| MODIFIED | `.gitignore` |
| MODIFIED | `README.md` |
| NEW | `docs/security_ai/soc_integration_contract.md` |
| NEW | `docs/security_ai/source_inventory.md` |
| NEW | `packages/dns-security-ai/README.md` |
| NEW | `packages/dns-security-ai/examples/synthetic_stateless9.json` |
| NEW | `packages/dns-security-ai/pyproject.toml` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/__init__.py` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/__main__.py` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/artifact_manifest.json` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/artifacts.py` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/cli.py` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/contracts.py` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/errors.py` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/evidence.py` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/feature_contract.json` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/predictor.py` |
| NEW | `packages/dns-security-ai/src/dns_security_ai/preprocessing.py` |
| NEW | `packages/dns-security-ai/tests/conftest.py` |
| NEW | `packages/dns-security-ai/tests/test_artifacts_predictor.py` |
| NEW | `packages/dns-security-ai/tests/test_contracts_evidence.py` |
| NEW | `packages/dns-security-ai/tests/test_preprocessing.py` |
| NEW | `packages/dns-security-ai/tests/test_runtime_loading.py` |
| NEW | `packages/dns-security-ai/uv.lock` |
| NEW | `packages/security-ai/README.md` |
| NEW | `packages/security-ai/pyproject.toml` |
| NEW | `packages/security-ai/src/security_ai/__init__.py` |
| NEW | `packages/security-ai/src/security_ai/__main__.py` |
| NEW | `packages/security-ai/src/security_ai/cli.py` |
| NEW | `packages/security-ai/src/security_ai/common/__init__.py` |
| NEW | `packages/security-ai/src/security_ai/common/contracts.py` |
| NEW | `packages/security-ai/src/security_ai/common/evidence.py` |
| NEW | `packages/security-ai/src/security_ai/dns/__init__.py` |
| NEW | `packages/security-ai/src/security_ai/network/__init__.py` |
| NEW | `packages/security-ai/tests/test_integration.py` |
| NEW | `packages/security-ai/uv.lock` |
| NEW | `reports/Security_AI_Integration_Report.md` |
| NEW | `reports/security_ai/artifact_inventory.json` |
| NEW | `reports/security_ai/base_wheel_tests.xml` |
| NEW | `reports/security_ai/build_inventory.json` |
| NEW | `reports/security_ai/changed_files.json` |
| NEW | `reports/security_ai/cli_dns.json` |
| NEW | `reports/security_ai/cli_network_edge.json` |
| NEW | `reports/security_ai/cli_network_quality.json` |
| NEW | `reports/security_ai/dependency_footprint.json` |
| NEW | `reports/security_ai/dns_legacy_parity.json` |
| NEW | `reports/security_ai/dns_scaler_review.json` |
| NEW | `reports/security_ai/dns_smoke.json` |
| NEW | `reports/security_ai/dns_source_inventory.json` |
| NEW | `reports/security_ai/dns_tflite_review.json` |
| NEW | `reports/security_ai/full_tests.xml` |
| NEW | `reports/security_ai/network_edge_smoke.json` |
| NEW | `reports/security_ai/network_quality_smoke.json` |
| NEW | `reports/security_ai/sequential_smoke.json` |
| NEW | `reports/security_ai/team_install_dns.json` |
| NEW | `reports/security_ai/team_install_network.json` |
| NEW | `reports/security_ai/team_install_tests.xml` |
| NEW | `reports/security_ai/validation.json` |
| NEW | `scripts/security_ai_smoke.py` |
| NEW | `scripts/verify_dns_legacy_parity.py` |
