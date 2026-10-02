# On-Device Network Threat Intelligence AI

대규모 네트워크 보안 데이터를 분석하고 공격 행동을 탐지하는 **경량 Machine Learning 기반 Security AI**를 개발하는 프로젝트입니다.

단순 IDS 분류 모델 구축을 넘어 **데이터 분석 → ML → 모델 해석 → 경량화 → On-Device Benchmark → Security AI 연동**까지 하나의 파이프라인으로 구현하는 것을 목표로 합니다.

현재 **CSE-CIC-IDS2018 기반 Network Attack Classification**에 대해 데이터 품질 분석, Security EDA, 데이터 분할 재설계, Feature Reduction, 다중 모델 비교 및 Ensemble 실험까지 완료했습니다.

---

## Project Pipeline

```text
Security Dataset
      ↓
Data Quality Analysis
      ↓
EDA & Attack Behavior Analysis
      ↓
Feature Engineering
      ↓
Duplicate / Label Conflict Analysis
      ↓
Train / Validation / Test Redesign
      ↓
ML Training
      ↓
Explainability
      ↓
Feature Reduction
      ↓
Model Comparison / Ensemble
      ↓
On-Device Benchmark
      ↓
Security AI Adapter
      ↓
Autonomous SOC Agent / Drone AI
```

---

## Dataset

### CSE-CIC-IDS2018

네트워크 Flow 기반 **Multi-Class Attack Classification**에 사용합니다.

주요 분석 대상은 Flow Duration, Packet/Byte Rate, Packet Length, IAT, TCP Flags, Active/Idle Time 등이며 정상 트래픽과 다양한 공격 유형의 행동 차이를 분석합니다.

통합 데이터 기준:

- **16,232,943 flows**
- **15 classes**
- **78 model features**
- Benign 약 **83.07%**
- 심각한 Class Imbalance 존재
- 일부 동일 Feature Vector에서 서로 다른 Label이 관측됨

주요 공격 유형:

- Bot
- Brute Force - Web / XSS
- DDoS HOIC / LOIC
- DoS Hulk / GoldenEye / SlowHTTPTest / Slowloris
- FTP-BruteForce
- SSH-Bruteforce
- Infilteration
- SQL Injection

**Current Candidate:** LightGBM Top40  
**Comparison:** XGBoost · RandomForest · HistGradientBoosting · Ensemble

---

### CIC-Bell-DNS-EXF-2021

정상 DNS와 DNS Tunneling/Data Exfiltration 등 **악성 DNS 행동 분석**에 사용할 예정입니다.

단일 요청뿐 아니라 시간 Window 기반 Query Frequency, Query Length, Interval, Domain Diversity 등의 행동 Feature를 분석합니다.

**Known Attack:** XGBoost  
**Anomaly Detection:** IsolationForest

DNS Security AI는 Network Attack Classification 이후 진행할 예정입니다.

---

## Analysis & Modeling

### 1. Data Quality

다음 항목을 중심으로 데이터 품질을 분석했습니다.

- 데이터 크기 및 Feature 구조
- 결측치 / ±Inf
- 중복 데이터
- 이상값
- Label 및 클래스 불균형
- Feature 분포
- Feature 상관관계

CSE-CIC-IDS2018 통합 데이터에서 확인한 주요 결과:

```text
Rows                : 16,232,943
Classes             : 15
NaN                 : 59,721
±Inf                 : 131,799
Generic Duplicates  : 422,815
Benign Ratio        : 83.07%
```

단순 중복 외에도 일부 공격 클래스에서 동일 Feature Pattern이 매우 높은 빈도로 반복되는 현상을 확인했습니다.

---

### 2. Security EDA

Network Traffic EDA에서는 다음 영역을 분석했습니다.

- Class Distribution
- Traffic Volume
- Flow Duration
- Packet / Byte Rate
- Packet Length
- Inter Arrival Time
- TCP Flags
- Active / Idle Behavior
- Feature Correlation
- Attack / Benign Feature Distribution

분석 결과 공격 트래픽은 하나의 단순한 임계값으로 구분되는 것이 아니라 공격 유형에 따라 서로 다른 네트워크 행동 특성을 보였습니다.

또한 다수의 높은 상관관계 Feature Pair를 확인했습니다.

대표적인 예:

```text
RST Flag Cnt ↔ ECE Flag Cnt
Flow Duration ↔ Fwd IAT Tot
Idle Mean ↔ Idle Min
Tot Bwd Pkts ↔ TotLen Bwd Pkts
Pkt Len Mean ↔ Pkt Size Avg
Flow IAT Max ↔ Fwd IAT Max
Flow Pkts/s ↔ Fwd Pkts/s
```

이 결과는 이후 Feature Reduction 실험의 근거로 활용했습니다.

---

## Duplicate & Label Conflict Analysis

초기 모델링 과정에서 단순 중복보다 중요한 문제를 확인했습니다.

**동일한 78개 Feature Vector가 서로 다른 Label을 갖는 패턴**이 존재했습니다.

```text
Conflicting Patterns      : 22,373
Affected Rows             : 423,390
Max Labels per Pattern    : 3
```

대표적인 Label Conflict:

```text
SlowHTTPTest ↔ FTP-BruteForce
Benign ↔ Infilteration
FTP-BruteForce ↔ SSH-Bruteforce
SlowHTTPTest ↔ SSH-Bruteforce
Brute Force-Web ↔ SQL Injection
```

특히 일부 클래스는 매우 높은 Conflict Ratio를 보였습니다.

```text
FTP-BruteForce       : 90.60%
SlowHTTPTest         : 55.24%
Infilteration        : 25.64%
SQL Injection        : 10.34%
```

즉 동일한 Feature Vector만으로는 일부 Sample의 Label을 완벽하게 구분할 수 없는 구조적 한계가 존재합니다.

Conflict Sample을 임의로 제거하여 성능을 높이지 않고, 해당 문제를 보존한 상태에서 평가하도록 설계했습니다.

---

## Split Redesign

### Split V1

초기 Split은 다음 Hash를 사용했습니다.

```text
hash(features + label_id)
```

이 방식은 Feature와 Label 조합의 중복은 막을 수 있지만 동일한 Feature Vector가 서로 다른 Label을 갖는 경우 서로 다른 Split으로 이동할 가능성이 있었습니다.

따라서 실제 Feature Generalization 평가에는 적합하지 않다고 판단했습니다.

---

### Feature-Only Hash Split V2

Split 기준을 다음과 같이 수정했습니다.

```text
hash(78 model features)
```

동일 Feature Vector는 Label과 관계없이 반드시 동일한 Split에 배치됩니다.

분할 결과:

```text
Train : 11,416,137
Valid :  2,390,002
Test  :  2,426,804
Total : 16,232,943
```

Feature Overlap 검증:

```text
Train ↔ Valid : 0
Train ↔ Test  : 0
Valid ↔ Test  : 0
```

따라서 동일 Feature Pattern이 Train과 Validation/Test에 동시에 존재하지 않도록 구성했습니다.

**Test V2는 최종 모델 선택 전까지 사용하지 않고 보존합니다.**

---

## Unique-Pattern V3

일부 공격 클래스에서 특정 Pattern이 수천 번 반복되는 문제를 확인했습니다.

대표적으로 Train V2에서:

```text
SlowHTTPTest
85,458 rows → 44 unique patterns

FTP-BruteForce
173,083 rows → 39 unique patterns
```

반복 빈도가 모델 평가를 과도하게 지배하지 않도록 Feature 기준 Unique Pattern Dataset을 별도로 구성했습니다.

### V3 Development Dataset

```text
Train : 702,217
Valid : 142,082
```

이 실험은 기존 데이터의 발생 빈도를 재현하는 목적이 아니라 **새로운 Feature Pattern에 대한 Generalization을 분석하는 실험**입니다.

일부 희소 클래스는 Unique Pattern 자체가 매우 적습니다.

```text
SlowHTTPTest Validation Support : 6
FTP-BruteForce Validation Support : 6
SQL Injection Validation Support : 13
```

따라서 해당 클래스의 개별 F1 Score는 높은 분산을 가질 수 있으며 결과를 과도하게 일반화하지 않습니다.

---

## Machine Learning

Network Flow Classification 구조:

```text
Network Flow
      ↓
78 Network Features
      ↓
Feature Reduction
      ↓
Top40 Features
      ↓
ML Classifier
      ↓
Attack Class + Probability
```

현재 비교한 모델:

- XGBoost
- RandomForest
- HistGradientBoosting
- LightGBM

---

## XGBoost Baseline

Full 78 Feature 기반 XGBoost V3 Validation 결과:

```text
Accuracy        : 0.945546
Macro Precision : 0.841778
Macro Recall    : 0.854829
Macro F1        : 0.846377
Weighted F1     : 0.945503
```

Feature Importance 분석 결과 상위 Feature에는 다음 항목들이 포함되었습니다.

```text
Fwd Act Data Pkts
Fwd Seg Size Min
Fwd Header Len
ECE Flag Cnt
Init Fwd Win Byts
URG Flag Cnt
RST Flag Cnt
Dst Port
Fwd PSH Flags
Fwd Pkts/s
```

이를 기반으로 Feature Reduction 실험을 진행했습니다.

---

## Feature Reduction

Feature Importance를 기준으로 Full78 → Top40 → Top20 → Top10 실험을 수행했습니다.

| Feature Set | Feature Count | Macro F1 |
|---|---:|---:|
| Full | 78 | 0.846377 |
| **Top40** | **40** | **0.859573** |
| Top20 | 20 | 0.849831 |
| Top10 | 10 | 0.808544 |

78개에서 40개로 약 **49%의 Feature를 제거했지만 Macro F1은 오히려 증가**했습니다.

반면 20개 이하에서는 성능 감소가 나타났으며 Top10에서는 감소 폭이 커졌습니다.

따라서 이후 모델 비교에서는 **Top40 Feature Set**을 공통 입력으로 사용했습니다.

---

## Model Comparison

동일한 Top40 Feature와 V3 Train/Validation Dataset을 사용하여 모델을 비교했습니다.

| Model | Accuracy | Macro F1 | Weighted F1 |
|---|---:|---:|---:|
| RandomForest Top40 | 0.942991 | 0.825171 | 0.942943 |
| HistGradientBoosting Top40 | 0.941294 | 0.844567 | 0.941231 |
| XGBoost Top40 | 0.943117 | 0.859573 | 0.943070 |
| **LightGBM Top40** | **0.945792** | **0.876563** | **0.945745** |

현재 Validation 기준 가장 높은 Macro F1은 **LightGBM Top40**에서 확인되었습니다.

### LightGBM Top40

```text
Accuracy        : 0.945792
Macro Precision : 0.871111
Macro Recall    : 0.885821
Macro F1        : 0.876563
Weighted F1     : 0.945745
```

주요 클래스 F1:

```text
Benign                  : 0.802454
Bot                     : 0.999975
Brute Force-Web         : 0.882682
Brute Force-XSS         : 0.905660
DDOS attack-HOIC        : 1.000000
DDOS attack-LOIC-UDP    : 0.959108
DDoS attack-LOIC-HTTP   : 0.999450
DoS attacks-GoldenEye   : 0.999919
DoS attacks-Hulk        : 1.000000
DoS attacks-SlowHTTPTest: 0.533333
DoS attacks-Slowloris   : 0.998982
FTP-BruteForce          : 0.363636
Infilteration           : 0.814434
SQL Injection           : 0.888889
SSH-Bruteforce          : 0.999929
```

> 위 결과는 **Unique-pattern V3 Validation 결과이며 최종 Test 성능이 아닙니다.**

---

## Ensemble Experiment

XGBoost와 LightGBM이 서로 다른 Sample을 맞히는지 Prediction Disagreement를 분석했습니다.

```text
Both Correct             : 132,908
XGBoost Only Correct     :   1,092
LightGBM Only Correct    :   1,472
Both Wrong               :   6,610
```

LightGBM이 XGBoost가 틀린 Sample 중 일부를 추가로 정확하게 분류하는 것을 확인했습니다.

특히:

```text
                    XGB Only   LGBM Only   Both Wrong
Benign                   547         714        3,889
Infilteration            530         742        2,689
```

이를 기반으로 XGBoost + LightGBM Soft Voting을 실험했습니다.

| Model | Accuracy | Macro F1 |
|---|---:|---:|
| **LightGBM Top40** | 0.945792 | **0.876563** |
| LGBM50 + XGB50 | 0.946095 | 0.864666 |
| LGBM80 + XGB20 | 0.946256 | 0.863183 |
| LGBM70 + XGB30 | **0.946453** | 0.861869 |
| XGBoost Top40 | 0.943117 | 0.859573 |

Soft Voting은 Accuracy를 최대 **0.946453**까지 향상시켰지만 Macro F1은 감소했습니다.

보안 데이터의 Class Imbalance와 희소 공격 클래스 성능을 고려하여 단순 Accuracy 상승보다 Macro F1을 중요하게 평가했습니다.

따라서 현재 단계에서는 Ensemble 대신 **LightGBM Top40 단일 모델을 Validation 후보 모델로 유지**합니다.

---

## Current Model Candidate

```text
Model            : LightGBM
Feature Set      : Top40
Evaluation       : Unique-pattern V3 Validation

Accuracy         : 94.58%
Macro Precision  : 87.11%
Macro Recall     : 88.58%
Macro F1         : 87.66%
Weighted F1      : 94.57%
```

현재 주요 잔여 문제:

- Benign ↔ Infilteration Confusion
- Feature-identical / Label-conflicting Pattern
- 일부 희소 공격 클래스의 매우 적은 Unique Pattern
- Source/Date 기반 Domain Generalization 미검증
- 최종 Test V2 미사용

따라서 현재 LightGBM Top40은 **최종 모델이 아니라 Validation 단계의 우선 후보 모델**입니다.

---

## Evaluation Strategy

클래스 불균형을 고려하여 Accuracy만으로 모델을 평가하지 않습니다.

### ML Metrics

- Precision
- Recall
- F1 Score
- Macro F1
- Weighted F1
- Confusion Matrix
- PR-AUC / ROC-AUC
- False Positive Rate

특히 보안 시스템의 특성을 고려하여 **Attack Recall과 False Positive Rate**를 중요하게 분석합니다.

현재 모델 선택 단계에서는 **Macro F1을 핵심 비교 지표**로 사용하고 있습니다.

---

## Explainability & Lightweight AI

Feature Importance와 필요 시 SHAP을 활용하여 모델이 어떤 네트워크 특징을 기반으로 공격을 판단했는지 분석합니다.

현재 Feature Reduction 실험을 통해:

```text
78 Features
     ↓
40 Features
     ↓
약 49% Feature Reduction
     ↓
Macro F1
0.846377 → 0.859573
```

을 확인했습니다.

향후 최종 후보 모델에서는 탐지 성능뿐 아니라 실제 디바이스 비용까지 함께 측정합니다.

```text
Full Features
      ↓
Reduced Features
      ↓
Lightweight Model
      ↓
F1 / Recall / FPR
Latency / RAM / CPU / Model Size
```

---

## On-Device Benchmark

최종 후보 모델에 대해 다음 항목을 실제 측정할 예정입니다.

- Model Size
- RAM Usage
- CPU Usage
- Average Inference Latency
- P95 Inference Latency
- Throughput
- Feature Extraction Time

**측정되지 않은 성능 수치는 사용하지 않습니다.**

---

## DNS Security AI

Network Threat Classification 이후 CIC-Bell-DNS-EXF-2021을 활용하여 DNS Security AI를 추가할 예정입니다.

```text
DNS Behavior
   ├─ XGBoost
   │      ↓
   │  Known Attack Classification
   │
   └─ IsolationForest
          ↓
      Unknown Behavior
      Anomaly Detection
```

분석 후보 Feature:

- Query Frequency
- Query Length
- Query Interval
- Domain Diversity
- Time Window Statistics

---

## Integration

최종 모델은 독립적인 ML 모델로 끝내지 않고 기존 **Autonomous SOC Agent**의 Security AI 입력으로 연결하는 것을 목표로 합니다.

```text
Network / DNS
      ↓
Lightweight Security AI
      ↓
Security Signal
      ↓
Multi-Model Evidence Fusion
      ↓
Autonomous SOC Agent
```

Network / DNS 모델의 Score 의미와 Evidence Provenance를 유지하면서 Agent가 조사 및 판단에 활용할 수 있는 Security Signal 형태로 변환할 예정입니다.

향후 동일한 경량화 구조를 **Drone On-Device Cybersecurity Module**로 확장하고 별도의 Drone Network Dataset 또는 Testbed를 통해 Domain Shift를 검증할 예정입니다.

> CSE-CIC-IDS2018 및 DNS 데이터에서 학습한 결과를 직접 드론 환경의 탐지 성능으로 간주하지 않습니다.

---

## Current Progress

### CSE-CIC-IDS2018

- [x] 데이터 수집
- [x] CSV 통합 및 스키마 정리
- [x] 데이터 품질 분석
- [x] 클래스 불균형 분석
- [x] Network Traffic EDA
- [x] Feature 분포 및 상관관계 분석
- [x] Preprocessing
- [x] Duplicate Pattern 분석
- [x] Label Conflict 분석
- [x] Feature-only Hash Split V2
- [x] Train / Valid / Test Feature Overlap 검증
- [x] Unique-pattern V3 Dataset 구축
- [x] XGBoost Baseline
- [x] Feature Importance
- [x] Feature Reduction
- [x] RandomForest 비교
- [x] HistGradientBoosting 비교
- [x] LightGBM 비교
- [x] XGBoost + RandomForest Ensemble
- [x] XGBoost + LightGBM Ensemble
- [x] Validation Candidate 선정
- [ ] 추가 Model Diversity 실험
- [ ] Conflict-aware Final Evaluation
- [ ] Untouched Test V2 Evaluation
- [ ] PR-AUC / ROC-AUC / FPR 분석
- [ ] On-Device Benchmark

### DNS / Integration

- [ ] DNS Security EDA
- [ ] DNS Known Attack Classification
- [ ] DNS Anomaly Detection
- [ ] Security AI Adapter
- [ ] SOC Agent Integration
- [ ] Drone AI Prototype

---

## Tech Stack

`Python` · `Pandas` · `NumPy` · `DuckDB` · `Scikit-learn` · `XGBoost` · `LightGBM` · `Matplotlib` · `PyArrow` · `Parquet` · `Jupyter` · `uv`

---

## Repository Structure

```text
notebooks/
├── EDA.ipynb
└── preprocessing.ipynb

results/
├── network_eda/
├── preprocessing/
├── split_diagnosis/
├── feature_selection/
├── xgboost_baseline/
├── xgboost_v3/
├── xgboost_top40_v3/
├── random_forest_top40_v3/
├── hist_gradient_boosting_top40_v3/
├── lightgbm_top40_v3/
├── model_comparison_v3/
├── ensemble_analysis_v3/
└── xgb_lgbm_ensemble_v3/
```

대용량 원본/전처리 데이터와 학습된 Model Artifact는 Git 저장소에서 제외합니다.

---

## Next Steps

```text
Additional Model Diversity
        ↓
Final Candidate Selection
        ↓
Conflict-aware Evaluation
        ↓
Untouched Test V2 Evaluation
        ↓
PR-AUC / FPR Analysis
        ↓
On-Device Benchmark
        ↓
DNS Security AI
        ↓
Security AI Fusion
        ↓
Autonomous SOC Agent Integration
```

최종 모델 선정 전까지 **Test V2는 모델 선택 및 Hyperparameter 조정에 사용하지 않습니다.**

---

## Goal

> **대규모 네트워크 및 DNS 보안 데이터에서 공격 행동의 특징을 발견하고, 실제 제한된 환경에서 실행 가능한 경량 Security AI로 발전시킬 수 있는가?**

데이터 분석, Machine Learning, Cybersecurity, Explainable AI, On-Device AI 및 AI Agent Integration을 하나의 프로젝트에서 연결하는 것을 최종 목표로 합니다.