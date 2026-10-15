# Final research package compatibility audit

Validated 2026-10-15 on WSL2. Baselines: ML
`9c36c83f9d2a85d7fd91233552cef23f75fd6aa8`, SOC
`3c70170470aa6244f90e93fbdbdb64c8aa15ab5c`. Both matched the requested main
commits; both indexes were empty. Existing local ML CTU-13/acquisition changes,
untracked legacy DNS package, raw data and all model artifacts remain untouched.

## Environment and package matrix

Paths below are relative to the existing sibling SOC and ML repositories.
No dependency was installed, copied or upgraded during this audit.

| Component | Actual location / identity | Execution boundary |
|---|---|---|
| SOC | SOC `src/soc_agent`, imported source checkout; autonomous-soc-agent 0.1.0 distribution metadata | SOC `.venv/bin/python`, Python 3.12.14 |
| Network research | ML `models/network-research-v1-final` and `src/ml/network_research` | SOC `.security-ai-demo/inference/bin/python`, Python 3.12.14 |
| Producer | ML `src/ml/verified_producers/network_v1_1.py`, version 1.1.0, Network14 float32 | Existing verified OFFLINE_PCAP replay only |
| Quality | RandomForest, threshold 0.35, `quality_rf/model.joblib`, 117,241 bytes | One owned subprocess per explicit request |
| Edge | StandardScaler + LogisticRegression, threshold 0.8, `edge_lr/model.joblib`, 1,773 bytes | Same existing isolated worker |
| DNS package | ML `packages/dns-security-ai/src/dns_security_ai`, 0.1.0 | Explicit pinned source import in the worker |
| DNS artifacts | SOC `.security-ai-demo/artifacts/dns`, reviewed existing bundle | LiteRT 2.3.0; DNS9 fixture only |
| Existing installed packages | Network/DNS/Security AI 0.1.0 in SOC `.venv/lib/python3.12/site-packages` | Package/native regression imports plus explicit worker source checks |

The isolated interpreter reuses the existing ML environment's numpy 2.5.3,
scikit-learn 1.9.1 and joblib 1.6.0. LiteRT 2.3.0 is installed in the isolated
environment itself. SOC Python does not contain LiteRT; this is intentional
isolation, not grounds to report DNS unavailable when the isolated backend works.
ML Python has Network package distribution metadata but no DNS/Security AI installed
metadata; their existing package source is supplied explicitly to package tests.
Actual imports and native inference are checked separately from metadata presence.
The historical DNS manifest's numpy 2.5.4 differs from current 2.5.3; successful
fixture execution does not prove training/scaler provenance or operational parity.

## Immutable artifact and contract checks

| File | Current verified SHA256 |
|---|---|
| Quality joblib | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` |
| Edge joblib | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` |
| DNS TFLite | `28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33` |
| DNS scaler | `2735f7650a7d7888ee68f2df870b4e29d83666962931ae2aecb9aa339f40266a` |
| Producer 1.1.0 source | `19fbcd702632b9b86605681b3b3f54a5b759b9ee26c373256dae360cf4b4634f` |

Network ordered names and float32 semantics remain those of Producer 1.1.0 / 14
features. DNS ordered-name digest remains
`3276c1b595ec566677bce530f2839247b7fa1320dc5e3549f85c0c17c959edd0`;
StandardScaler and existing int8 quantization are unchanged. DNS7 is not DNS9.
Seven legacy model/scaler/resource identities were also rehashed against preserved
reviewed evidence, with no mismatch. No model was deserialized before integrity
checks. Model binaries and raw data are excluded from this commit.

## Worker lifecycle and SOC integration

SOC's existing research worker enforces address space 3 GiB, CPU 15 seconds, result
file 128 KiB, denied network sockets, one BLAS thread and parent wall timeout up to
30 seconds. Investigation has a separate 20 second deadline. A limit is not a
measurement of actual RSS or elapsed inference latency.

This stabilization fixes two reproduced SOC defects: a model worker could survive
abrupt GUI parent death, and Stop during asynchronous Start preflight could be
undone when preflight returned. Parent binding now fails closed before model load,
and the existing coordinator preserves Stop/duplicate-start intent. No ML source
or environment fix was required. Timeout/crash/uncertain dispatch remains UNKNOWN
without automatic replay; successful retained receipts are not new invocations.

Actual WSLg replay executes Quality, Edge and DNS twice each, followed by six
separate READ-only investigations and checkpoint/audit recovery. Network inputs
are four preselected available training flows (two used in this GUI run), not a
new generalization evaluation. DNS inputs are existing precomputed DNS9 fixtures.
Scores remain uncalibrated advisory data. Full current evidence, test executions
and actual screenshots are in SOC's `docs/linux-soc-v1/final-runtime-stabilization.md`
and `final-runtime-evidence.json`.

## Tests, reproduction and limits

Current working ML tests plus Network/DNS/Security AI package tests: **630 passed,
4.07 s**. pytest is supplied from the existing SOC test environment to the existing
ML interpreter; no packages are installed. Existing tiny synthetic estimator fits
validate preprocessing/serialization only; no reviewed model is retrained. Existing seven user test cases are
excluded from clean Git Export. Clean ML Git Export: **623 passed, 5.02 s**. The seven extra working cases are
pre-existing user tests; no user source change is needed. SOC Ruff checks ML `src tests`: pass. ML whole-repository format has
**24 pre-existing violations**; none is changed by this documentation-only audit.
Clean Export Ruff passes; its full format has 21 baseline violations (the extra
three working violations belong to existing user changes). Diff whitespace check passes. Existing user source changes are excluded from Export.

Operational Network/DNS inference stays BLOCKED / NOT_INFERABLE,
feature generation DIAGNOSTIC_ONLY and security action WRITE_DENIED. Research-only
success is not operational deployment readiness. DNS Producer parity, calibration,
class mapping and scaler pairing are unverified. No new capture, traffic, dataset retraining,
threshold tuning, promotion or physical Linux validation occurred. Further runtime
capability development ends here; the next stage is GUI UX and final demonstration.

Final SOC clean Export also passed 491 Core/self-improvement cases, 381 native/external
cases, 325 governance/GUI/research/scenario cases (1 deliberate deselection), 697
boundary cases (23 Windows-only skips), 256 Runtime cases, 117 focused research/GUI
cases and 3 actual WSLg checks. These overlapping executions are not summed. Six
fresh native GUI results match the working run's model/input/artifact/score and
checkpoint outcomes while invocation IDs differ. This documentation is the only
ML change; existing user file hashes and the original empty index are preserved
before selective staging. Scoped research compatibility: VERIFIED. Operational
Network/DNS deployment readiness: BLOCKED.
