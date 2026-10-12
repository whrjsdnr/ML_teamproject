# DNS source inventory

모든 원본 파일은 보존했습니다. 새 canonical 추론 구현은 `packages/dns-security-ai`입니다.

| Path | Classification | Role / dependencies | Execution status |
|---|---|---|---|
| `packages/dns_security_package/dns_security_package/README.md` | DOCUMENTATION | supplied usage README; none | readable; installation fenced block incomplete |
| `packages/dns_security_package/dns_security_package/README.md:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |
| `packages/dns_security_package/dns_security_package/demo.py` | INFERENCE / EVALUATION | two sample rows, not statistical evaluation; legacy DNSDetector | native TF UNVERIFIED; samples reused only as synthetic smoke |
| `packages/dns_security_package/dns_security_package/demo.py:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |
| `packages/dns_security_package/dns_security_package/dns_security/__init__.py` | INFERENCE | eager DNSDetector re-export; all legacy runtime dependencies | native import requires missing TF |
| `packages/dns_security_package/dns_security_package/dns_security/__init__.py:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |
| `packages/dns_security_package/dns_security_package/dns_security/__pycache__/detector.cpython-312.pyc` | DOCUMENTATION | supplied usage README; none | readable; installation fenced block incomplete |
| `packages/dns_security_package/dns_security_package/dns_security/detector.py` | INFERENCE / PREPROCESSING | supplied eager TF+joblib INT8 detector; TF2.21, numpy, pandas, sklearn, joblib | native TF UNVERIFIED; original algorithm validated with LiteRT adapter |
| `packages/dns_security_package/dns_security_package/dns_security/detector.py:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |
| `packages/dns_security_package/dns_security_package/dns_security/model/dnn_int8.tflite` | ARTIFACT | INT8 DNN; TFLite interpreter | actual load/inference PASS |
| `packages/dns_security_package/dns_security_package/dns_security/model/dnn_int8.tflite:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |
| `packages/dns_security_package/dns_security_package/dns_security/preprocessor/scaler.joblib` | ARTIFACT | named fitted StandardScaler; trusted joblib, sklearn1.9.1 | actual load/inference PASS |
| `packages/dns_security_package/dns_security_package/dns_security/preprocessor/scaler.joblib:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |
| `packages/dns_security_package/dns_security_package/requirements_addon.txt` | DOCUMENTATION | tensorflow==2.21.0 addon only; assumes existing ML dependencies | not complete standalone packaging |
| `packages/dns_security_package/dns_security_package/requirements_addon.txt:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |
| `reports/CIC-Bell-DNS-EXF-2021_DNS_Security_EDA.ipynb` | EXPERIMENT / PREPROCESSING / EVALUATION | stateless string and stateful EDA; external DNS CSV, pandas/plotting; ML uses sklearn/xgboost/lightgbm | not executed; referenced DNS CSV absent |
| `reports/CIC-Bell-DNS-EXF-2021_DNS_Security_EDA.ipynb:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |
| `reports/CIC-Bell-DNS-EXF-2021_DNS_Security_EDA_clean.pdf` | DOCUMENTATION | saved EDA/ML result; text inspected with PyMuPDF; PDF reader | readable; no DNN training/export code |
| `reports/CIC-Bell-DNS-EXF-2021_DNS_Security_EDA_clean.pdf:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |
| `reports/CIC-Bell-DNS-EXF-2021_DNS_Security_ML.ipynb` | EXPERIMENT / PREPROCESSING / EVALUATION / TRAINING | RF/XGB/LGBM/IF training and saved metrics; external DNS CSV, pandas/plotting; ML uses sklearn/xgboost/lightgbm | not executed; referenced DNS CSV absent |
| `reports/CIC-Bell-DNS-EXF-2021_DNS_Security_ML.ipynb:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |
| `reports/CIC-Bell-DNS-EXF-2021_DNS_Security_ML_clean.pdf` | DOCUMENTATION | saved EDA/ML result; text inspected with PyMuPDF; PDF reader | readable; no DNN training/export code |
| `reports/CIC-Bell-DNS-EXF-2021_DNS_Security_ML_clean.pdf:Zone.Identifier` | UNUSED | Windows origin metadata; none | not executable; preserved |

검색 범위: tracked/untracked 파일, Python/README/requirements/JSON, 모든 notebook source cells, DNS PDF 텍스트. 새로운 ignore 규칙에 걸린 제공 모델 및 Zone.Identifier도 직접 조사했습니다. `notebooks/data.ipynb`의 DNS 언급은 dataset 계획뿐입니다. 신규 패키지는 아래 보고서의 Final Package Structure에 별도 분류합니다.

DNS CSV 참조: `data/Benign/stateless_features-benign_1.pcap.csv`, `data/Attack_heavy_Benign/Attacks/stateless_features-heavy_text.pcap.csv`. EDA는 light_text/heavy_audio/image/video/compressed/exe 및 stateful 파일도 참조합니다. 현재 `data/`에는 해당 DNS 데이터가 없어 데이터 기반 중복/entity/session/domain 감사는 UNVERIFIED입니다. DNN 학습/export 코드, encoder/imputer/calibration artifact, anomaly model artifact는 발견하지 못했습니다.

Legacy detector는 제공된 비교 reference로 보존하며 새 runtime에서 import하지 않습니다. 유지보수 대상 canonical source는 새 독립 DNS package 하나입니다. Zone.Identifier는 runtime에서 사용하지 않는 metadata이며 새 Git 추가에서 제외합니다. RF/XGB/LGBM/IF는 사용하지 않는 코드로 확정하지 않고 EXPERIMENT로 분류합니다. 원본을 삭제하거나 변경하지 않았습니다.

기존 Network 파일별 역할·검토는 [통합 보고서](../../reports/Security_AI_Integration_Report.md)의 Network Model Review에 기록합니다.
