> SUPERSEDED: 범위 수정 이전의 미적용 SOC 통합 설계 기록. 현재 산출물은 packages/network-security-ai이며 NetworkSecurityEvidence에서 멈춥니다.

# Actual architecture reviewed before integration

ML and Autonomous SOC Agent were both on branch main. The SOC working tree already had
untracked improvement_promotion implementation/tests/docs and tests/fusion_support.py;
these files are excluded from this integration patch. ML already had experiment/report
changes; none of its model/data/experiment artifacts is overwritten by integration.

SOC uses Python 3.12+, src layout, frozen Pydantic v2 models, uv/uv.lock, pytest +
pytest-asyncio and Ruff. Existing security_ai contains wrappers, model registry, predictions,
AI signals, provenance-checked features, selection, investigation, packaging and fusion.
Its network implementation is a different CICIDS2017 XGBoost contract, so V4 gets an
adjacent version-specific inference module rather than replacing that classifier.

Evidence attests source records, AISignal represents model-derived context, ThreatAssessor
is advisory and bounded, Investigation uses existing coordinators. PolicyEngine,
ApprovalManager and GovernedExecutor own response authority. They are not imported or
modified by V4 runtime. The adapter opt-in registers with the existing SecurityAIRegistry.
No root application CLI/global settings service exists; an example script and frozen config
are supplied. Only the chosen native backend is loaded; no inference import or training at
module import. Selected artifacts are checksum-pinned and administrator-provisioned.

The only existing runtime changes are four prompt lines and five validator lines in
assessment: receipt metadata is not proof of attack and cannot support Observations.
State, llm, tools, policy, approval, execution and investigation implementations are preserved.

Patch and exact per-file old/new hashes: autonomous_soc_network_v4.patch and
network_v4_change_plan.json. Existing source is checked before applying any change.
