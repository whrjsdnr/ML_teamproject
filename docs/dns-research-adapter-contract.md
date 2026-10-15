# DNS Research Advisory Adapter Contract

2026-10-15. ML baseline `a82925dba04203beb85b61814fab703cab62c097`; SOC baseline
`441c63e42fd7596b93416d13be0b4d4be6c715f0`. This report is the only ML change.
Existing packages, producers, binaries, datasets, evaluation locks and user edits are preserved.

## Architecture

SOC extends its existing Network Research Adapter/Worker/ResearchDemo and Tk Command Center.
DNS uses the same bounded process, private governance store, audit, Orchestrator and
READ-only checkpoint path. ML provides its unchanged official `DNSPredictor` and DNS9
contract. No new ML model, Runtime, queue, Feature Producer or operating registry entry.

## Artifact and feature identity

| Item | Value |
|---|---|
| Package | `dns-security-ai` 0.1.0 |
| Model ID/version | `dns_cicbell_dnn_int8` / `int8-sha256-28e089af363d` |
| Bundle | `dns-int8-reviewed-1` |
| Model SHA256 / size | `28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33` / 9,288 bytes |
| Scaler SHA256 / size | `2735f7650a7d7888ee68f2df870b4e29d83666962931ae2aecb9aa339f40266a` / 1,135 bytes |
| Feature schema | `cic-bell-dns-stateless9-v1` |
| Ordered-name digest | `3276c1b595ec566677bce530f2839247b7fa1320dc5e3549f85c0c17c959edd0` |
| Default threshold | 0.5, supplied detector default; not tuned/validated |

Order: `FQDN_count, subdomain_length, numeric, entropy, special, labels, labels_max,
labels_average, len`. Named nonnegative finite float32 values are required. Existing
StandardScaler precedes rounding/clipping to INT8. Input tensor `(1,9)` quantization
`(0.0387900173664093,-40)`; output `(1,1)` quantization `(0.00390625,-128)`.

Source is this repository's existing DNS package metadata and existing reviewed bundle
deployed under SOC `.security-ai-demo/artifacts/dns`. SOC pins package/source metadata and
checks both artifact byte identities before loading. `DNSPredictor` independently verifies
its bundle before scaler deserialization and LiteRT loading. No arbitrary model paths.
Digests are integrity checks, not publisher signatures or an OS sandbox for same-UID code.

The existing isolated Python 3.12.14 / LiteRT 2.3.0 / sklearn 1.9.1 / joblib 1.6.0 is reused;
no install/rebuild. Its numpy is 2.5.3, while historical review metadata lists 2.5.4. Actual
inference is verified here; upstream training/scaler pairing and class mapping are still
UNVERIFIED. The default score is never presented as a calibrated malicious probability.

## Input boundary

Only two existing explicit precomputed fixtures are replayed:

- Existing SOC GUI DNS9 all-ones fixture.
- Existing DNS package fixture `[14,0,0,2.78,2,2,10,6.5,11]`.

Their origin is FIXTURE / validation FIXTURE_NATIVE_ONLY. Input digest identifies the
canonical named fixture payload before scaling/quantization. These are not raw queries,
ground truth, raw-feature golden pairs or producer parity evidence. No Raw FQDN→DNS9
extractor or DNS7→DNS9 conversion is implemented. Actual DNS operational input stays
NOT_INFERABLE; model execution and Finding promotion stay BLOCKED for those inputs.

## Receipt, advisory and governance

`soc-dns-research-receipt:v1` preserves original model identity and contains artifact,
scaler, feature contract, fixture/input digest, ordered names, native score/prediction,
threshold, timestamp, package-reported latency, worker limits and provenance digest.
Status is RESEARCH_ONLY, producer parity UNVERIFIED, uncertainty UNKNOWN,
FIXTURE_ONLY_NO_OPERATIONAL_SOURCE, uncalibrated score, operating BLOCKED and WRITE_DENIED.

`soc-dns-research-advisory:v1` binds a fresh research incident and full receipt digest.
Network and Authentication sources remain independent. No cross-domain incident correlation
or automatic operating Finding is generated. The existing ResearchClient's untrusted
projection and governed READ tool expose fixture metadata as such, never model output as
an observed fact. Actual SOCRuntime/Orchestrator/assessment runs in SCRIPTED mode with zero
provider calls and stops ASSESSED_READ_ONLY before response planning/execution.

## Isolation and recovery

Existing Worker: one concurrent request, 3 GiB address-space, 15 CPU seconds, at most
30-second parent timeout, 128 KiB result limit, no core dump, single BLAS thread, new
network/capture sockets denied. Credentials are not forwarded. No automatic retry/respawn.
Crash/timeout/uncertain dispatch stays UNKNOWN. Existing audit/attempt keys prevent duplicate
replay; cached results do not increase invocation counts. At most eight Network + two DNS
keys per private demo. GUI close stops only its owned Worker. Reopen restores receipts,
verifies audit/checkpoints and leaves the demo STOPPED with operating gates still blocked.
File/SQLite commits are not globally atomic; exactly-once external effects are not claimed.

## GUI and actual evidence

SOC command remains `.venv/bin/python -m soc_agent.gui`. Dashboard presents separate
Network/DNS RESEARCH_ONLY cards and Authentication Runtime state. Research button permits
model/fixture selection, replay, detail and stop without another terminal or JSON editing.
Scores, inference timestamps/counts, source labels, audit/checkpoints, DNS trend and
investigation progress come from actual receipts; empty/failed measurements stay NO_DATA
or UNKNOWN. Research start/status does not automatically infer. IDLE is not ACTIVE.

Actual WSLg final run: Quality 2, Edge 2, DNS 2 native invocations and six separate
ASSESSED_READ_ONLY incidents. DNS scores were 0.55859375 and 0; existing Network scores
were Quality 0/1, Edge 0.000242734/0.999817193. One retained verified NATIVE_OS Authentication
event and its provenance/audit were reviewed read-only in a STOPPED WSL Runtime; no new
capture or collection. No source correlation is claimed. GUI close/reopen retained counts,
verified audit and restored checkpoints, with no automatic replay.

DNS package latency includes lazy loading/preprocessing/invoke; Network's reported latency
is prediction only. These scopes and tiny sample counts do not support performance ranking.
Actual screenshots, sanitized receipt summary and final regression/Export results are in
SOC `docs/linux-soc-v1/unified-research-command-center.md` and its evidence links.

## Limits and next stage

Native fixture success does not validate operating detection, class mapping, calibration,
producer parity or physical Linux deployment. No training, artifact replacement, operating
gate release, real security WRITE or live LLM API call occurred. With this integration,
further AI feature expansion stops; next work is stabilization, UI/UX and final reporting.

## Executed regression and Export results

Counts are per execution and overlapping tests are not summed. Working ML regression
(`tests` and the existing Network/DNS/Security AI package suites) passed 630 tests in
4.76 s; clean Export passed 623 in 4.80 s. The seven extra working cases are existing
user CTU tests. The existing ML interpreter uses pytest supplied explicitly from the
existing SOC test environment; Ruff also uses the existing SOC installation. No installs.

Final SOC DNS/Network Research plus GUI focused tests passed 110 cases (42.70 s). A clean
SOC Export using clean exported ML producer/package code passed those tests plus an actual
WSLg unified window test, 111 cases (62.03 s). Broader working SOC Runtime, Native and
Governance/GUI/Scenario groups passed 266, 381 and 318 cases; Export passed 256, 381 and
318 respectively. Ten pre-existing untracked operational-feature cases explain the Runtime
difference. One deliberately unbound operator-socket case was deselected from the network
Guard and passed separately without connection or transmission. Working actual WSLg
unified + existing Network + actual module launch/SIGTERM checks passed three tests;
the final unified window was separately rechecked and passed.

SOC lint/full format/diff checks pass. ML lint/new-report format/diff checks pass; full
ML format retains 24 existing violations, unchanged by this report-only change. Original
binary and source hashes remain intact. Export reproduction has explicit local pinned
artifact/raw/interpreter dependencies and does not redistribute them or rely on uncommitted
Replay code. Detailed executed evidence, development failures/corrections and screenshots
are linked in the SOC report.
