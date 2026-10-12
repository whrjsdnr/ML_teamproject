# Security AI → SOC integration contract

Version: `security-ai-envelope-v1`. 검토일: 2026-10-12.
이번 구현의 경계는 independent prediction/evidence output입니다. SOC 소스는 변경하지 않습니다.

## 설치와 artifact

Python >=3.12. ML clone 후 root에서:

```bash
uv sync --project packages/security-ai --extra network-quality --extra dns-litert
```

Network edge는 `--extra network-edge`, 원래 DNS TensorFlow runtime은
`--extra dns-tensorflow`와 `DNSConfig(runtime="tensorflow")`를 선택합니다.
Native TensorFlow 실행은 이번 검증에서 UNVERIFIED입니다.
모델 없는 환경은 extras 없이 base import/unit tests를 실행할 수 있습니다.
외부 SOC 프로젝트에는 이 저장소에서 빌드한 세 wheel을 전달하고:

```bash
uv pip install --find-links /path/to/reviewed-wheels 'security-ai[network-quality,dns-litert]==0.1.0'
```

Registry 공개/다운로드 URL은 미정입니다. 설치에 SOC checkout은 필요하지 않습니다.
Artifact 다운로드/업로드, incident 연결, production registration은 구현하지 않습니다.
Network 기본 root-relative files:
`models/network/lightgbm_top40_v4b2.txt`, `models/network/dnn_top40_v4_best.pt`,
`models/network/dnn_top40_v4_scaler.joblib`.
DNS는 별도 root의 `model/dnn_int8.tflite`, `preprocessor/scaler.joblib`입니다.
모델별 manifest와 [inventory](../../reports/security_ai/artifact_inventory.json)를 함께 전달하세요.
Network Top40/label resources 및 DNS feature/manifest는 wheel에 포함됩니다.
상대경로·symlink containment, SHA-256, tensor/feature/scaler compatibility를 검증합니다.
신뢰하는 관리자만 artifact root와 설치 코드를 변경해야 합니다. joblib은 trusted pickle only입니다.

## Network API

```python
from pathlib import Path
from security_ai.network import (
    NetworkSecurityAIConfig, create_network_security_ai, prediction_to_evidence,
)
from security_ai import to_envelope

model = create_network_security_ai(NetworkSecurityAIConfig(
    enabled=True, artifact_root=Path("/trusted/network"), profile="detection_quality",
))
assert model is not None
# network_features: precomputed flow Top40, exact names from Top40Contract.names
prediction = model.predict(network_features)
receipt = prediction_to_evidence(prediction, flow_reference="application-flow-id")
output = to_envelope(receipt)
```

Canonical implementation/API는 기존 `network_security_ai`입니다. Re-export는 동일 객체입니다.
Feature version `cse-cic-ids2018-top40-v1`, 40 names/order는 bundled CSV rank로 결정합니다.
15-class ID/mapping은 bundled JSON을 사용하며 `Infilteration`의 기존 철자를 보존합니다.
None/NaN/Inf는 기존 계약대로 NaN으로 변환합니다. LightGBM은 native missing 처리,
DNN은 training mean imputation → fitted scaler → FP32 CPU inference입니다.
Network profile은 서로 다른 deployment 선택이며 ensemble이 아닙니다.

## DNS API

```python
from pathlib import Path
from security_ai.dns import DNSConfig, DNSPredictor, prediction_to_evidence
from security_ai import to_envelope

model = DNSPredictor(DNSConfig(artifact_root=Path("/trusted/dns")))
# dns_features: exact named stateless9 numeric mapping, separate observation
prediction = model.predict(dns_features)
receipt = prediction_to_evidence(prediction, observation_ref="application-dns-record-id")
output = to_envelope(receipt)
```

Feature version `cic-bell-dns-stateless9-v1`. 입력 순서:
`FQDN_count, subdomain_length, numeric, entropy, special, labels, labels_max, labels_average, len`.
All required finite nonnegative float32; no missing imputation/categorical encoding.
Input dict order is irrelevant. Supplied scaler `feature_names_in_` must match the full ordered tuple.
Canonical `StandardScaler.transform` on a named float32 DataFrame precedes INT8 rounding/clipping.
No fit is allowed on inference data. Batch input is unsupported; call predict separately for each record.
Exact upstream extractor units/aggregation remain UNVERIFIED; SOC must not derive features by guessing.

DNS class IDs/labels: 0=NORMAL, 1=MALICIOUS, probability>=0.5 yields MALICIOUS.
Mapping follows supplied detector/notebook convention; DNN training mapping provenance is UNVERIFIED.
Model identity `dns_cicbell_dnn_int8`, content version `int8-sha256-28e089af363d`.
This version identifies reviewed bytes; original training revision is UNVERIFIED.

## Evidence types and schema

| Type | Schema | Required provenance | Optional observation linkage |
|---|---|---|---|
| NetworkSecurityEvidence | network-evidence-v1 | source, typed NetworkThreatPrediction | flow_reference |
| DNSSecurityEvidence | dns-evidence-v1 | evidence_id, source, typed DNSThreatPrediction incl model/scaler SHA-256 | observation_ref |
| EvidenceEnvelope | security-ai-envelope-v1 | evidence_id, evidence_type, source, model_id, model_version, inference timestamp, typed payload | observation_ref |

Network original evidence schema is preserved. Its unique receipt ID exists on the new envelope.
DNS envelope retains its payload evidence_id. Rewrapping Network produces a new receipt ID;
persist the envelope once and reuse it when deduplication requires stable identity.
UUID is generated receipt metadata, never a claim about a raw event identifier.
Timestamp is `prediction.inferred_at` in UTC, never invented capture/event time.
Caller-supplied observation_ref is a short opaque identifier (<=256 chars), not raw DNS/IP/user payload.
Missing linkage stays null. Envelope metadata must agree exactly with typed payload provenance.
DNS nested schema and existing Network snapshots are frozen; mutable raw feature/metadata dicts are omitted.
Public conversion revalidates model_copy inputs before producing evidence/envelopes.
No observation payload, action/policy/approval API or tool execution is present.

## Score meanings

| Field | Meaning | Calibration / interpretation |
|---|---|---|
| Network class_probabilities | 15 model class probabilities | uncalibrated |
| Network confidence | maximum class probability | not a common risk score |
| Network threat_score | 1 − P(Benign) | not severity or attack confirmation |
| DNS probability | dequantized sigmoid P(MALICIOUS) | uncalibrated; quantization step 1/256 |
| DNS score_type | uncalibrated_malicious_probability | explicit semantics; not anomaly score |
| DNS threshold | supplied detector default 0.5 | threshold selection validation UNVERIFIED |

No anomaly detector is deployed. Notebook IsolationForest remains experimental:
raw predict -1 means outlier, +1 means inlier; there is no serialized detector/score contract.
Never convert an anomaly score to probability or sum these heterogeneous probabilities.
Both evidence types retain `model_derived=True`, `attack_confirmed=False`,
`confidence_calibrated=False`. A classification receipt cannot authorize a response action.

## Errors and failure isolation

| Failure | Network | DNS |
|---|---|---|
| Bad feature input | SecurityAIInputValidationError | DNSInputError |
| Missing/corrupt/incompatible/untrusted artifact | NetworkArtifactError | DNSArtifactError |
| Runtime/import/inference failure | SecurityAIInferenceError | DNSInferenceError |
| Invalid score/output | SecurityAIOutputValidationError | DNSOutputError |
| Bad configuration/evidence metadata | Pydantic ValidationError | Pydantic ValidationError |

No benign fallback. SOC records a model-specific degraded/unavailable state.
Continue independent predictors if appropriate; do not fabricate missing evidence or overwrite successful results.
Do not log sensitive raw input or internal exception contents. CLI failure is exit 1 with a generic message.
The upper package keeps original error hierarchies to preserve API compatibility.

## Responsibility boundary

Security AI owns exact feature validation/order, trusted artifact integrity checks,
reproduction of supplied inference preprocessing, lazy per-backend runtime loading,
bounded single-record prediction, score semantics and immutable inference receipts.
It does not prove artifact training lineage beyond available bytes/metadata.

SOC owns authentic input collection/extraction, entity/session/domain/flow linkage,
capture timestamp/incident binding, transport/authenticity, persistence/deduplication,
failure coverage, eventual Evidence Fusion, ThreatAssessor, Investigation,
Policy, Human Approval and Execution. No new response actions are provided.

Read-only inspection found that existing SOC `SecurityAIResult`/`AISignal` requires
incident_id and validates source_evidence_ids against IncidentState. Our receipts have no incident_id
and no SOC source-evidence assertion. A later application-owned adapter must assign and validate
those references. This package cannot be registered by assuming structural compatibility.
`AISignal` confidence is optional and scores preserve their meaning; future adapters should retain
typed payload/score names rather than force a shared float confidence.

## Future Fusion considerations

Network flow and DNS stateless record may cover different entities/time windows.
Join only after validating observation references, capture times, entity semantics and coverage.
Repeated receipts for correlated observations are not independent evidence.
Account for model availability, missing linkage, quantization, calibration gaps,
domain/session split leakage uncertainty, and deployment distribution shift.
Do not compare validation-developed Network metrics with unverified DNS DNN performance.
Model version/feature contract/scaler digest must remain traceable through downstream transformations.
Schema validation authenticates shape only, not supply chain or observation authenticity.

Current readiness: install/import/inference/evidence boundary tested. Actual SOC adapter/fusion and
operational readiness are pending. DNS training/evaluation provenance remains a reliability blocker
for production assessment, not a reason to fabricate performance.

## Artifact distribution v1

Network/DNS artifact 설치는 버전별 pinned bundle로 제공합니다.
[Artifact 설치 가이드](artifact_installation.md)에서 설치 경로·SHA-256·선택 다운로드·오류 처리와 검증 명령을 확인하세요.

```bash
uv run --project packages/security-ai --frozen python -m security_ai artifacts install \
  --bundle-dir /path/to/trusted-bundles --artifact-root ./artifacts --model all
uv run --project packages/security-ai --frozen python -m security_ai artifacts verify \
  --artifact-root ./artifacts --model all
# 실제 GitHub Release 게시 이후
uv run --project packages/security-ai --frozen python -m security_ai artifacts download \
  --artifact-root ./artifacts --model all --version security-ai-artifacts-v1
```

설치 후 Network config root는 `./artifacts`, DNS config root는 `./artifacts/dns`입니다.
GitHub API가 반환한 실제 asset URL만 다운로드하며 package catalog의 archive/member SHA-256을 검증합니다.
기존 정상 파일은 재사용하고 다른 기존 파일을 덮어쓰지 않습니다. Predictor API와 evidence schema는 그대로 유지합니다.
