# On-Device Network Threat Intelligence AI

대규모 네트워크 보안 데이터를 분석하고, 공격 행동을 탐지하는 **경량 Machine Learning 기반 Security AI**를 개발하는 프로젝트입니다.

단순 IDS 분류 모델 구축을 넘어 **데이터 분석 → ML → 모델 해석 → 경량화 → On-Device Benchmark → Security AI 연동**까지 하나의 파이프라인으로 구현하는 것을 목표로 합니다.

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
ML Training
      ↓
Explainability
      ↓
Feature Reduction
      ↓
On-Device Benchmark
      ↓
Security AI Adapter
      ↓
Autonomous SOC Agent / Drone AI
```

## Dataset

### CSE-CIC-IDS2018

네트워크 Flow 기반 **Multi-Class Attack Classification**에 사용합니다.

주요 분석 대상은 Flow Duration, Packet/Byte Rate, Packet Length, IAT, TCP Flags, Active/Idle Time 등이며 정상 트래픽과 다양한 공격 유형의 행동 차이를 분석합니다.

**Primary Model:** XGBoost
**Comparison:** RandomForest · LightGBM · Logistic Regression

### CIC-Bell-DNS-EXF-2021

정상 DNS와 DNS Tunneling/Data Exfiltration 등 **악성 DNS 행동 분석**에 사용합니다.

단일 요청뿐 아니라 시간 Window 기반 Query Frequency, Query Length, Interval, Domain Diversity 등의 행동 Feature를 분석합니다.

**Known Attack:** XGBoost
**Anomaly Detection:** IsolationForest

## Analysis & Modeling

### 1. Data Quality

* 데이터 크기 및 Feature 구조
* 결측치 / ±Inf / 중복 데이터
* 이상값
* Label 및 클래스 불균형
* Feature 분포 및 상관관계

### 2. Security EDA

공격 유형별 Traffic Volume, Packet Size, IAT, TCP Flag, Active/Idle 패턴을 비교하여 공격 행동을 분석합니다.

DNS 데이터에서는 시간 Window 기반 통신 빈도와 규칙성, Query 특성 및 Domain Diversity를 분석합니다.

### 3. Machine Learning

```text
Network Flow
   ↓
XGBoost
   ↓
Attack Class + Probability
```

```text
DNS Behavior
   ├─ XGBoost → Known Attack Classification
   └─ IsolationForest → Unknown Behavior Anomaly Detection
```

## Evaluation

클래스 불균형을 고려하여 Accuracy만으로 모델을 평가하지 않습니다.

**ML Metrics**

* Precision / Recall / F1
* Macro / Weighted F1
* Confusion Matrix
* PR-AUC / ROC-AUC
* False Positive Rate

특히 보안 시스템의 특성을 고려하여 **Attack Recall과 False Positive Rate**를 중요하게 분석합니다.

## Explainability & Lightweight AI

Feature Importance와 필요 시 SHAP을 활용하여 모델이 어떤 네트워크 특징을 기반으로 공격을 판단했는지 분석합니다.

이후 Feature를 단계적으로 축소하여 탐지 성능과 디바이스 비용의 Trade-off를 측정합니다.

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

## On-Device Benchmark

최종 후보 모델에 대해 다음 항목을 실제 측정합니다.

* Model Size
* RAM / CPU Usage
* Average / P95 Inference Latency
* Throughput
* Feature Extraction Time

측정되지 않은 성능 수치는 사용하지 않습니다.

## Integration

최종 모델은 독립적인 ML 모델로 끝내지 않고 기존 **Autonomous SOC Agent**의 Security AI 입력으로 연결하는 것을 목표로 합니다.

```text
Network / DNS
      ↓
Lightweight Security AI
      ↓
Security Signal
      ↓
Multi-Model Fusion
      ↓
Autonomous SOC Agent
```

향후 동일한 경량화 구조를 **Drone On-Device Cybersecurity Module**로 확장하고, 별도의 Drone Network Dataset 또는 Testbed를 통해 Domain Shift를 검증할 예정입니다.

> CSE-CIC-IDS2018 및 DNS 데이터에서 학습한 결과를 직접 드론 환경의 탐지 성능으로 간주하지 않습니다.

## Current Progress

* [x] CSE-CIC-IDS2018 데이터 수집
* [x] CSV 통합 및 스키마 정리
* [x] 데이터 품질 분석
* [x] 클래스 불균형 확인
* [x] Feature 분포 및 상관관계 분석
* [ ] Network Traffic EDA
* [ ] Network Attack Classification
* [ ] Explainability / Feature Selection
* [ ] DNS Security EDA
* [ ] DNS Security AI
* [ ] On-Device Benchmark
* [ ] SOC Agent Integration
* [ ] Drone AI Prototype

## Tech Stack

`Python` · `Pandas` · `NumPy` · `Scikit-learn` · `XGBoost` · `LightGBM` · `Matplotlib` · `PyArrow` · `uv`

## Goal

> **대규모 네트워크 및 DNS 보안 데이터에서 공격 행동의 특징을 발견하고, 실제 제한된 환경에서 실행 가능한 경량 Security AI로 발전시킬 수 있는가?**

데이터 분석, Machine Learning, Cybersecurity, Explainable AI, On-Device AI 및 AI Agent Integration을 하나의 프로젝트에서 연결하는 것을 최종 목표로 합니다.
