# Network Research Adapter Contract

2026-10-15. ML baseline `fe884521f1b8138f3016ad7bc770243193a85bf8`;
SOC baseline `f088c80814cca0e23c59f09b044a9c35cdb4de3e`.

## Architecture and ownership

SOC owns `soc_agent.security_ai.research` and the existing Tk GUI's Network Research page.
ML provides the existing Network Producer v1.1.0, PCAP/IoT-23 recovery code and pinned local
RESEARCH_ONLY artifacts. No ML source, feature contract, training result or binary is changed.
This report is the only ML change. No model training or locked-test evaluation is repeated.

```text
Explicit GUI offline replay → fixed 8-1 PCAP flow → existing Producer 1.1.0
 → owned sklearn subprocess → research receipt → untrusted advisory context
 → existing governed READ-only investigation → GUI / audit / checkpoint
```

## Artifacts and loading

| Profile | Model | Model SHA256 | Threshold |
|---|---|---|---:|
| quality | RandomForestClassifier | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` | 0.35 |
| edge | StandardScaler + LogisticRegression | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` | 0.8 |

Paths remain `models/network-research-v1-final/{quality_rf,edge_lr}/model.joblib`.
Model IDs remain `linux-network14-research-v1-{quality_rf,edge_lr}`. Manifest digests are
`80bb31b38c6e35dac1628f8c5c3ed1843ae81779ca3173a356f18473821b5f66` and
`293e6046e2b46777c383ae0b5de5951596238d4f26e552263022b9b65357e2d9` respectively.
SOC checks hashes, model manifest, ownership/permissions, source code pins and regular files
before existing `ml.network_research.artifacts.load_research` loads trusted joblib bytes.
After loading, model types, input width and threshold are checked. Arbitrary models,
caller paths and new model IDs are not accepted. Hashes are not publisher signatures;
joblib is never safe for untrusted bytes.

## Producer contract and offline input

Producer v1.1.0's 14 feature names/order, dtype and semantics are unchanged. Four fixed
VERIFIED_MATCH Capture 8-1 training flows form the SOC `replay.json` catalogue. The child
reconstructs these from retained PCAP and rechecks Zeek references and independent
wire-reference binding before producing features. Catalogue/source/configuration and
feature integrity are validated; saved label references are not prompt evidence.

The demo only accepts OFFLINE_PCAP. It does not alias PCAP as NATIVE_AF_PACKET/FIXTURE,
open capture sockets, download data, repeat Test 34-1, or claim operational parity.
Native Linux flow integration remains diagnostic pending explicit parity and promotion work.

## Environment and isolation

The existing sibling SOC `.security-ai-demo/inference/bin/python` is used: Python 3.12.14,
sklearn 1.9.1, existing numpy/joblib. No dependency installation or environment modification.
The production path is fixed; callers cannot supply Python/module/model paths. Independent
tests explicitly point the Worker at clean exported ML source while retaining pinned local
raw/model/interpreter resources. The Worker checks its actual producer import root.

One owned Worker/request, concurrency one, no retry. Limits: 3 GiB address space, 15 CPU
seconds, 30-second maximum parent timeout, 128 KiB output, no core dumps, BLAS threads one.
Audit hook denies IPv4/IPv6/AF_PACKET sockets. Credentials are not forwarded. This is not an
OS sandbox for malicious same-UID code. Limits do not imply measured RSS or benchmark claims.
Crash/timeout/cancel produce sanitized UNKNOWN with no automatic retry/re-execution.

## Receipt and advisory contract

`soc-network-research-receipt:v1` includes request/invocation identity, model+artifact+manifest,
producer, origin, source/feature digest, ordered vector, timestamp, score, fixed threshold,
CLASS_0/CLASS_1, prediction-only latency and applied worker limits. Status is RESEARCH_ONLY,
uncertainty UNKNOWN, calibration UNCALIBRATED_SCORE_NOT_ATTACK_PROBABILITY,
operational inference BLOCKED and WRITE_DENIED.

`soc-network-research-advisory:v1` binds incident ID, receipt digest and full result, marked
UNTRUSTED_MODEL_INFERENCE_NOT_EVIDENCE / OFFLINE_RESEARCH_DEMO. It is separate from legacy
Top40/DNS9 context identities. No probability fusion, security fact or automatic Finding.

## Investigation, GUI and recovery

SOC reuses compose_application, SOCRuntime, InvestigationOrchestrator, policy/executor,
Core Evidence persistence and checkpoints. Explicit SCRIPTED reasoning receives a separate
untrusted projection; only an incident-bound READ tool returns raw source metadata. Scores
do not become observations. The demo stops at ASSESSED_READ_ONLY with zero provider calls.

Launch `.venv/bin/python -m soc_agent.gui` in SOC, then Network Research → Start → select
model(s)/flow → Run Offline Replay → inspect scores/trace → Stop. Existing Tk components,
background loop, charts, error/detail panes and scroll containers are reused. Status reads
do not invoke inference. Actual Runtime/queue health is shown as UNKNOWN when offline.

Private attempt files reserve a maximum of eight model/flow pairs. Existing runtime lock,
governance SQLite and hash-chain audit bind attempts and receipts. Cached replay does not
increase counts. Pending attempts on restart are UNKNOWN, never automatically retried.
Restored checkpoints and evidence are verified. GUI shutdown stops owned research work,
not an independently running Linux Runtime. File+SQLite commits are not globally atomic.

## Actual E2E results and limitations

Actual WSLg tests at 1920×1080 and 1366×768 executed both trusted binaries on flow 1
(2 packets) and flow 3 (6 packets). Quality scores: 0 / 1; Edge: 0.000242734 / 0.999817193.
Both count series reached 2; all four receipts reached ASSESSED_READ_ONLY, one source
Evidence each, with verified audit and checkpoint restore after restart. Scores are not
attack probabilities or new accuracy measurements. Prediction-only measured latencies:
Quality 11.24/12.66 ms, Edge 9.11/11.70 ms; four samples are not a benchmark.

The SOC report `docs/linux-soc-v1/network-research-advisory-integration.md` contains actual
screenshots, sanitized receipt digests, security/test results and independent Export details.
The research adapter is verified for this offline demo. Operational readiness stays BLOCKED:
no new source admission, artifact replacement, automatic model promotion, security WRITE,
native capture or physical Linux validation was performed.

## Regression and independent Export

Each row is one execution; counts overlap and are not summed.

| Execution | Result |
|---|---|
| ML working tree: `tests`, network-security-ai, dns-security-ai and security-ai package tests | 630 passed (4.09 s) |
| Clean ML Git Export, same test scope with explicit existing local dependency paths | 623 passed (3.94 s) |
| SOC Research Adapter plus GUI unit/integration tests | 83 passed (31.68 s) |
| SOC clean Export plus clean ML producer source, same focused tests, actual RF/LR | 83 passed (29.85 s) |
| SOC clean Export full Runtime/native/context/approval/restricted/GUI/research suite | 842 passed, 1 deselected (556.51 s) |
| Actual WSLg Research window plus module launch/duplicate/graceful-SIGTERM | 2 passed (29.35 s) |
| Export actual WSLg Research window using explicit pinned dependency composition | 1 passed (16.63 s) |

The seven additional ML working-tree tests are pre-existing user CTU tests, not part of
this change. Export uses committed PCAP/label helper source and proves no dependency on
those local source edits or uncommitted SOC Replay code. Known raw/model bytes and the
existing interpreter are external dependencies, not exported research binaries.

ML tests use its existing Python with pytest imported explicitly from the existing SOC
test environment; Ruff uses the existing SOC Python/tool installation. ML's own environment
has neither test command installed. No environment was rebuilt or dependency installed.

ML `ruff check src tests` and the new report's format check pass. Full ML format remains
24 pre-existing violations in the working tree (21 in clean HEAD Export); no formatter
was applied to these files. `git diff --check` passes. The broader SOC working-tree
batch had an unexplained SIGTERM (143) before summary and was not counted as
passing; the SOC report records the replacement isolated group runs and their results.
Those replacement working SOC groups completed with 266, 381 and 205 passing tests
respectively (one deliberately unbound-socket case deselected and separately passed).
Working and exported Policy/Scenario regression each passed 86 tests. No failing test
was ignored or treated as a successful model inference.
