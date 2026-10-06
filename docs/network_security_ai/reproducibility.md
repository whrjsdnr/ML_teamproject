# Network Security AI 재현 경로

## 환경과 책임

ML root에서 `uv sync`로 기존 실험 dependency와 로컬 `network-security-ai` package를 설치합니다. Jupyter kernel은 이 환경을 선택하고 root 또는 `notebooks/`에서 시작합니다. Notebook 실행 도구는 사용하는 IDE/Jupyter 환경에서 별도 준비합니다. Package-only 실행은 package README의 uv 명령을 사용하며 root의 torchao/xgboost 등을 설치할 필요가 없습니다. `.env`나 SOC checkout을 필요로 하지 않습니다.

Training과 inference는 다른 책임입니다. Notebook은 실험·분석·시각화·학습용이며 순서대로 실행하면 큰 데이터 처리/학습/결과 쓰기가 발생합니다. 이 정리 작업에서는 notebook을 실행하거나 모델을 재학습하지 않았습니다. Existing outputs는 그대로 보존했고 project-root 설정만 이식 가능하게 바꿨습니다.

## 실험 순서와 파일

| 단계 | canonical 실험 코드 | 결과 / artifact |
|---|---|---|
| CSE-CIC-IDS2018 CSV 준비·데이터 품질 | `notebooks/data.ipynb` | `data/raw/`, `results/data_quality/` |
| Network EDA | `notebooks/EDA.ipynb` | `results/network_eda/` |
| preprocessing, 중복/label conflict, Split V2, feature selection, V3 unique sampling | `notebooks/preprocessing.ipynb` | `data/processed/`, split/feature-selection results |
| V3 모델 비교 | `notebooks/model_diversity_v3.ipynb` | V3 model comparison results |
| V4 frequency-aware sampling, duplicate/conflict 분석, LightGBM V4-B2 | `notebooks/model_sample_v4.ipynb` | `models/network/lightgbm_top40_v4b2.txt`, `results/lightgbm_top40_v4b2/` |
| V4 statistical validation | `notebooks/statistical_analysis_v4.ipynb` | `results/statistical_analysis_v4/` |
| DNN Top40 V4 학습, scaler, full validation, TorchAO INT8 실험 | `notebooks/dnn_top40_v4.ipynb` | DNN/scaler artifacts, `results/dnn_top40_v4/` |
| FP32/INT8/LightGBM CPU on-device benchmark | `notebooks/ondevice_benchmark_v4.ipynb` | `results/ondevice_benchmark_v4/` |
| runtime RSS/peak memory benchmark | `scripts/benchmark_model_memory.py` | JSON stdout; 저장 위치는 사용자가 지정 |
| 기존 최종 비교 | `notebooks/final_evaluation.ipynb` | 기존 evaluation results |
| 보고서 작성/검증 | `results/final_report/*.py`, `reports/` | 보고서 scaffolding과 기존 보고서 |
| inference / evidence / CLI | `packages/network-security-ai/` | 독립 Python package |

Notebook의 학습 로직을 runtime package에 복제하지 않습니다. 공통 inference architecture는 `predictors.build_dnn()`, fitted-scaler batch 처리는 `preprocessing.preprocess_dnn_batch()`가 관리하고 memory benchmark가 import합니다. Notebook의 독립 실험 정의는 당시 실험 재현용으로 유지하며 inference 수정은 package에서 수행합니다.

V2/V3/V4는 다른 split/sampling 실험입니다. 경로와 각 notebook의 markdown을 먼저 확인하세요. Test V2는 기존 V3 실험에서 이미 소비했습니다. V4 개발의 full validation 지표를 새로운 holdout 성능이라고 해석하지 말고, 이 정리 과정에서 Test V2를 재사용하지 않습니다. 원본/processed 데이터, 모델 checkpoint, scaler는 별도 artifact이며 Git clone만으로 대규모 실험을 실행할 수는 없습니다.

## Inference contract와 artifact

Top40 canonical order는 기존 `results/feature_selection/top40_features.csv`에서, 15-class mapping은 기존 `data/processed/network_ml/label_mapping.json`에서 byte-identical로 복사했습니다. Package의 `resources/`와 `artifact_manifest.json`을 함께 버전 관리합니다. 원래 `Infilteration` 철자를 유지합니다. 테스트는 fixture/resource/checksum 일치를 검증하며 missing/modified override는 fail closed입니다.

필요한 모델 이름, profile별 설치 및 실제 CLI 예시는 [package README](../../packages/network-security-ai/README.md)에 있습니다. 모델 파일이 없는 경우 typed artifact error/CLI exit 1을 반환하며 자동 학습/다운로드/Benign fallback을 하지 않습니다. Smoke inference는 API/shape/load 확인이지 정확도 평가가 아닙니다.

## Memory benchmark

```bash
# ML root; 현재 root dependency 환경 사용
uv run python scripts/benchmark_model_memory.py --model fp32 --batch-size 4096
uv run python scripts/benchmark_model_memory.py --model int8 --batch-size 4096
uv run python scripts/benchmark_model_memory.py --model lightgbm --batch-size 4096
```

`data/processed/network_ml_dev_v4/validation/valid_v2_top40.parquet`와 해당 모델이 있어야 합니다. 첫 validation batch를 사용하고 결과는 stdout JSON으로 내보냅니다. Test V2를 사용하지 않습니다. DNN만 training scaler를 적용하며 LightGBM은 raw Top40/nonfinite→NaN을 받습니다. 기존 script의 LightGBM scaler 적용은 정리하면서 바로잡았으며 과거 저장 결과를 다시 쓰지 않았습니다. Linux `ru_maxrss`를 MiB로 변환합니다. 실제 ARM/NPU 성능을 의미하지 않습니다. Quantized model은 runtime profile로 등록하지 않습니다.

## 팀 공유 / 제외

COMMIT: source, tests, package/root pyproject와 uv.lock, 작은 resources/manifest, synthetic input, README/docs, notebook의 portable root 설정.

DO NOT COMMIT: `data/`, `models/`, parquet/large CSV, wheel/sdist, cache/logs/temp patches, regenerated quantized checkpoint. 기존 tracked checkpoint/log/patch는 삭제하거나 untrack하지 않았습니다. 새 `.gitignore`가 이미 tracked 파일을 제거하지는 않으므로 팀의 artifact 정책을 별도로 결정하세요.

OPTIONAL: 실험 notebook 자체, 작은 결과 table/plot 및 보고서는 과학적 이력을 공유할 때 유지합니다. Source inventory의 superseded SOC integration patch는 적용하지 않습니다.

경계는 NetworkSecurityEvidence까지입니다. ThreatAssessor, Investigation, Policy, Approval, Execution, DNS/Fusion, drone integration은 이번 정리 범위가 아닙니다. Production traffic 검증, calibration, DNN minority-class, SlowHTTP/FTP ambiguity, ARM/NPU 및 drone 일반화 검증이 남아 있습니다.

Benchmark input branch regression (mock data, 모델 실행/결과 저장 없음):

```bash
uv run --with pytest pytest -q scripts/tests
```
