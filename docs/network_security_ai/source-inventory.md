# Network AI source inventory

수정 전에 ML / SOC / temporary checkout을 비교하여 분류했습니다. ML standalone package를 canonical로 사용하며 SOC/tmp source는 복사하지 않았습니다. 기존 SOC Network pipeline은 CICIDS2017 및 SOC state/tool contracts에 의존하며 CSE-CIC-IDS2018 V4 training의 누락 구현이 아닙니다. Temp V4 predictor는 import를 제외한 AST가 ML predictor와 동일했습니다.

MOVE/COPY는 작은 metadata 2개뿐입니다. 원본을 보존하고 package `resources/top40_features.csv`, `resources/label_mapping.json`으로 byte-identical 복사했습니다. 모델/데이터/실험 결과를 복사하거나 overwrite하지 않았습니다. MERGE는 portability와 공통 inference preprocessing 정리입니다. OBSOLETE는 삭제 지시가 아니며 기존 patch/log를 보존합니다.

| Location | File | Classification |
|---|---|---|
| ML | `notebooks/EDA.ipynb` | EXPERIMENT ONLY |
| ML | `notebooks/data.ipynb` | EXPERIMENT ONLY |
| ML | `notebooks/dnn_top40_v4.ipynb` | EXPERIMENT ONLY |
| ML | `notebooks/final_evaluation.ipynb` | EXPERIMENT ONLY |
| ML | `notebooks/model_diversity_v3.ipynb` | EXPERIMENT ONLY |
| ML | `notebooks/model_sample_v4.ipynb` | EXPERIMENT ONLY |
| ML | `notebooks/ondevice_benchmark_v4.ipynb` | EXPERIMENT ONLY |
| ML | `notebooks/preprocessing.ipynb` | EXPERIMENT ONLY |
| ML | `notebooks/statistical_analysis_v4.ipynb` | EXPERIMENT ONLY |
| ML | `packages/network-security-ai/src/network_security_ai/__init__.py` | KEEP |
| ML | `packages/network-security-ai/src/network_security_ai/__main__.py` | KEEP |
| ML | `packages/network-security-ai/src/network_security_ai/adapter.py` | KEEP |
| ML | `packages/network-security-ai/src/network_security_ai/contracts.py` | MERGE |
| ML | `packages/network-security-ai/src/network_security_ai/errors.py` | KEEP |
| ML | `packages/network-security-ai/src/network_security_ai/evidence.py` | KEEP |
| ML | `packages/network-security-ai/src/network_security_ai/predictors.py` | MERGE |
| ML | `packages/network-security-ai/src/network_security_ai/preprocessing.py` | KEEP |
| ML | `packages/network-security-ai/src/network_security_ai/schema.py` | KEEP |
| ML | `packages/network-security-ai/tests/conftest.py` | KEEP |
| ML | `packages/network-security-ai/tests/test_contracts.py` | KEEP |
| ML | `packages/network-security-ai/tests/test_predictors.py` | KEEP |
| ML | `packages/network-security-ai/tests/test_resources.py` | KEEP |
| ML | `packages/network-security-ai/tests/test_standalone.py` | KEEP |
| ML | `results/final_report/build_report.py` | EXPERIMENT ONLY |
| ML | `results/final_report/inspect_pdf.py` | EXPERIMENT ONLY |
| ML | `results/final_report/render_final_report.py` | EXPERIMENT ONLY |
| ML | `results/final_report/verify_benchmark.py` | EXPERIMENT ONLY |
| ML | `results/final_report/verify_data.py` | EXPERIMENT ONLY |
| ML | `scripts/benchmark_model_memory.py` | MERGE |
| SOC | `src/soc_agent/security_ai/network/__init__.py` | SOC ONLY |
| SOC | `src/soc_agent/security_ai/network/anomaly.py` | SOC ONLY |
| SOC | `src/soc_agent/security_ai/network/anomaly_training.py` | SOC ONLY |
| SOC | `src/soc_agent/security_ai/network/artifacts.py` | SOC ONLY |
| SOC | `src/soc_agent/security_ai/network/classifier.py` | SOC ONLY |
| SOC | `src/soc_agent/security_ai/network/dataset.py` | SOC ONLY |
| SOC | `src/soc_agent/security_ai/network/preprocessing.py` | SOC ONLY |
| SOC | `src/soc_agent/security_ai/network/schema.py` | SOC ONLY |
| SOC | `src/soc_agent/security_ai/network/train.py` | SOC ONLY |
| SOC | `src/soc_agent/security_ai/network/training.py` | SOC ONLY |
| TEMP | `examples/network_v4/predict.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/__init__.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/anomaly.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/anomaly_training.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/artifacts.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/classifier.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/dataset.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/preprocessing.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/schema.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/train.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/training.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/v4/__init__.py` | SOC ONLY |
| TEMP | `src/soc_agent/security_ai/network/v4/contracts.py` | OBSOLETE (duplicate) |
| TEMP | `src/soc_agent/security_ai/network/v4/predictors.py` | OBSOLETE (duplicate) |
| TEMP | `tests/unit/security_ai/network_v4/__init__.py` | SOC ONLY |
| TEMP | `tests/unit/security_ai/network_v4/conftest.py` | SOC ONLY |
| TEMP | `tests/unit/security_ai/network_v4/test_contracts.py` | SOC ONLY |
| TEMP | `tests/unit/security_ai/network_v4/test_predictors.py` | SOC ONLY |

그 밖의 기존 `reports/network_security_ai_standalone.patch`, `reports/network_v4_*.log`, `reports/superseded_soc_integration/*`는 OBSOLETE이며 보존했습니다. Package metadata fixture는 기존 66개 테스트와 학습 artifact 일치 검증용으로 유지합니다. Root/package README와 root pyproject/uv.lock은 MERGE입니다. Raw/processed data와 trained models는 DO NOT COMMIT입니다. DNS notebook은 Network 범위 밖의 EXPERIMENT ONLY이며 수정하지 않았습니다.
