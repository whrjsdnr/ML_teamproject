# DNS Security AI

독립 DNS 추론 패키지입니다. 입력은 미리 계산된 stateless DNS feature 9개이며,
출력은 `DNSThreatPrediction`과 immutable `DNSSecurityEvidence`입니다.
원본 domain·packet 추출, 모델 학습, SOC 의존성은 없습니다.

## 확인한 모델과 제한

공급된 `dnn_int8.tflite`는 Dense 9→64→32→16→1, hidden ReLU 및 최종 sigmoid의
INT8 binary classifier입니다. StandardScaler와 입력/출력 INT8 quantization을 재사용합니다.
`NORMAL=0`, `MALICIOUS=1`, threshold 0.5는 기존 detector의 의미를 유지합니다.
Score는 **미보정 malicious probability**이며 anomaly score나 위험도는 아닙니다.

DNN의 학습/export 코드, 원래 DNN 평가 결과, train-only scaler fit은 **UNVERIFIED**입니다.
DNS notebook의 RF/XGBoost/LightGBM/IsolationForest 결과는 이 DNN의 성능이 아닙니다.
Content version `int8-sha256-28e089af363d`는 artifact 식별자이며 학습 버전의 증명이 아닙니다.

## 설치

ML root에서 Python 3.12 이상, uv를 사용합니다.

```bash
uv sync --project packages/dns-security-ai --extra litert
uv run --project packages/dns-security-ai --extra litert python -m dns_security_ai \
  --artifact-root packages/dns_security_package/dns_security_package/dns_security \
  --input packages/dns-security-ai/examples/synthetic_stateless9.json \
  --observation-ref synthetic-dns-example
```

`litert`는 검증한 LiteRT 2.3.0 CPU runtime입니다. `tensorflow` extra와
`--runtime tensorflow`는 기존 TensorFlow 2.21.0 Interpreter를 선택합니다.
이번 검증에서는 TensorFlow를 설치하지 않았으므로 native TensorFlow 실행은 UNVERIFIED입니다.
모델 파일이 없어도 base import와 artifact-free unit tests는 가능합니다.
optional sklearn/pandas가 없는 환경에서는 해당 전처리 테스트가 명시적으로 skip됩니다.

## Artifact 준비

신뢰하는 팀원이 전달한 다음 파일을 관리자가 선택한 root 아래에 준비합니다.
다운로드 주소는 아직 없으며 자동 다운로드/학습은 하지 않습니다.

```text
<dns-artifact-root>/
├── model/dnn_int8.tflite        # 9,288 bytes
└── preprocessor/scaler.joblib  # 1,135 bytes, sklearn 1.9.1
```

`artifact_manifest.json`의 크기·SHA-256을 두 파일 모두 역직렬화 전에 확인합니다.
Scaler는 pickle 기반 joblib이므로 **출처를 신뢰할 수 없는 파일은 절대 로드하지 않습니다**.
Checksum은 서명이나 공급자 인증이 아닙니다. Root는 관리자만 변경할 수 있어야 합니다.
Root 밖으로 나가는 symlink, 절대/상위 상대경로, 다른 모델/scaler 조합을 거부합니다.
Bundle 변경은 별도 검토·manifest/package 버전 변경이 필요합니다.

## API / feature contract

```python
from pathlib import Path
from dns_security_ai import DNSConfig, DNSPredictor, prediction_to_evidence

predictor = DNSPredictor(DNSConfig(artifact_root=Path("/trusted/dns-bundle")))
features = {
    "FQDN_count": 14.0,
    "subdomain_length": 0.0,
    "numeric": 0.0,
    "entropy": 2.7813014714884527,
    "special": 2.0,
    "labels": 2.0,
    "labels_max": 10.0,
    "labels_average": 6.5,
    "len": 11.0,
}
prediction = predictor.predict(features)
evidence = prediction_to_evidence(prediction, observation_ref="opaque-dns-reference")
print(evidence.model_dump_json(indent=2))
```

Canonical feature order는 위 순서 그대로이며 dict 삽입 순서에 의존하지 않습니다.
`feature_contract.json`에 position/dtype/required/missing/range를 기록합니다.
모든 값은 finite nonnegative float32 scalar입니다. None/NaN/Inf, bool, 문자열,
container, 누락·추가 key를 거부합니다. Imputer/encoder는 제공되지 않았습니다.
학습 데이터의 extractor 정의·정확한 단위·물리적인 상한은 UNVERIFIED이므로
이 패키지는 raw domain에서 feature를 임의로 계산하지 않습니다.

전처리: float32 row → 동일 이름의 DataFrame → 저장된 `StandardScaler.transform`
→ round(x / input_scale + input_zero_point) → clip[-128,127] → INT8.
출력: (INT8 − output_zero_point) × output_scale. 확률을 보정하거나 clip하지 않습니다.
극단값의 INT8 saturation은 원 구현과 동일하며 분포 밖 입력의 정확도를 보장하지 않습니다.
첫 유효 predict만 runtime/model/scaler를 로드하고 cache합니다. 같은 predictor는 lock으로
직렬 실행합니다. 지원 API는 single record이며 batch 32는 32회 순차 호출입니다.

Evidence schema는 `dns-evidence-v1`, feature schema는 `cic-bell-dns-stateless9-v1`입니다.
UUID는 추론 receipt의 고유 참조입니다. `inferred_at`은 추론 시각이며 관측 시각이 아닙니다.
선택 observation_ref는 호출자가 제공한 opaque 참조이며 원본 domain/PII를 넣지 않습니다.
Raw features/payload, 정책·action·tool 실행 기능은 evidence에 없습니다.

오류는 `DNSInputError`, `DNSArtifactError`, `DNSInferenceError`, `DNSOutputError`로
구분하고 정상으로 fallback하지 않습니다. Metadata 오류는 Pydantic `ValidationError`입니다.
CLI는 실패 시 민감한 input/path/backend 내용을 출력하지 않고 exit 1을 반환합니다.

## 검증 / 빌드

```bash
uv run --project packages/dns-security-ai --extra litert pytest -q \
  -c packages/dns-security-ai/pyproject.toml packages/dns-security-ai/tests
uv run --project packages/dns-security-ai ruff check packages/dns-security-ai
uv run --project packages/dns-security-ai ruff format --check packages/dns-security-ai
uv build --project packages/dns-security-ai --out-dir /tmp/dns-security-ai-dist
```

실제 모델 smoke와 legacy parity는 [통합 보고서](../../reports/Security_AI_Integration_Report.md)에
측정 조건과 함께 기록합니다. 같은 LiteRT runtime에서 legacy/new 전처리와 확률·label이
합성 35개 row에서 정확히 일치합니다. **학습 전처리 일치 검증은 코드 부재로 UNVERIFIED**입니다.
SOC 연결은 상위 [security-ai](../security-ai/README.md)와
[integration contract](../../docs/security_ai/soc_integration_contract.md)를 사용합니다.
