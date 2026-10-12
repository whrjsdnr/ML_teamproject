# Security AI Artifact Distribution Report

검증일: 2026-10-12. Branch: `main`. Target: `whrjsdnr/ML_teamproject` (public).
이 보고서는 로컬 구현·검증과 외부 게시 승인 단계를 구분합니다.
현재 원격 Release/push는 **BLOCKED — 사용자 게시 승인 대기**입니다.
확정되지 않은 asset URL을 만들거나 원격 다운로드 성공으로 표시하지 않습니다.

## 배포 결정 / GitHub 확인

- GitHub Release의 versioned artifact bundle을 선택했습니다.
- GitHub API로 `private=false`, 계정 `permissions.admin/push=true`를 확인했습니다.
- 기존 Release 목록은 비어 있고 `security-ai-artifacts-v1` Release 조회는404였습니다.
- Git ls-remote로 remote main=`59c16b29520cf8410984e2fe06566c2d5d496533`, 해당 tag 없음 확인.
- Git LFS 클라이언트가 없으며 LFS 정책/quota 설정 없이 migration/push하지 않았습니다.
- Release는 asset당2GiB 미만이고 이번 archive 합계20,329,122 bytes로 범위 안입니다.
  근거: [GitHub Release docs](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
- LFS는 별도 storage/bandwidth quota를 사용합니다.
  [GitHub LFS billing](https://docs.github.com/en/billing/concepts/product-billing/git-lfs).
- 공개 저장소이므로 승인 후 업로드되는 모델도 공개됩니다. 데이터셋/raw observations는 제외합니다.

## Bundle / Manifest

Version=`security-ai-artifacts-v1`; catalog schema=`security-ai-artifact-catalog-v1`;
embedded bundle schema=`security-ai-bundle-v1`.
Canonical transport manifest는 `packages/security-ai/src/security_ai/artifact_catalog.json`입니다.
Independent Network/DNS predictor manifest와 public API는 변경하지 않았습니다.
각 bundle은 모델 + 필수 preprocessor + feature/label/threshold metadata를 같이 제공합니다.

| Group / filename | Bytes | SHA-256 |
|---|---:|---|
| network-quality / security-ai-artifacts-v1-network-quality.tar.gz | 19959438 | 2ca983baf8d85b97791e43c1f31f267b547a0d371e5d39bb0732108b48f97acf |
| network-edge / security-ai-artifacts-v1-network-edge.tar.gz | 361380 | 4c513228e613c8013d3fef22f4bb8bf8f6d432d7834c6afddcf95915b1e21aeb |
| dns / security-ai-artifacts-v1-dns.tar.gz | 8304 | 05241751478e9fd1d707534422e6b1033af9489006d8523f7bb78a210dbfd08b |

게시 대기 파일은 `/tmp/security-ai-release-v1-confirmed/`의 위3개 archive입니다.
초기 생성 directory와 최종 재생성 directory 사이의 byte-level hash가 동일합니다.
Streaming tar+gzip, metadata order/mtime/uid/gid 고정으로 재생성 결과를 검증했습니다.
Archive SHA뿐 아니라 원본5개 모델/preprocessor와 metadata5개 파일 SHA도 검증했습니다.
원본 위치/size/hash는 [artifact_inventory.json](security_ai/artifact_inventory.json),
archive/member pin은 [bundle_inventory.json](security_ai_distribution/bundle_inventory.json)에 있습니다.

## 구현

새 `security_ai.artifacts` / `artifact_cli` / `security-ai-artifacts` entrypoint를 제공합니다.
통합 CLI는 기존 network/dns 인자를 보존하고 `python -m security_ai artifacts ...`만 추가했습니다.

- `bundle`: trusted 원본 및 bundled metadata를 확인하고 재현 가능한 archive 생성.
- `install`: local trusted bundle 선택/전체 설치.
- `download`: 고정 repository/tag의 실제 published GitHub API 응답으로 asset URLs 확인 후 설치.
- `verify`: 선택 모델의 모든 필수 file size/SHA 검증.
- `manifest`: 패키지에 pin된 archive/member metadata 출력.

선택 값은 `network-quality`, `network-edge`, `network`, `dns`, `all`입니다.
Unknown version은 I/O 전에 거부합니다. Archive의 embedded manifest도 version/model/feature
계약이 정확히 일치해야 합니다. 사용자가 임의 URL/manifest를 주입하는 옵션은 없습니다.

## 안전성

1. HTTPS + 기본 TLS certificate 검증. API hostname은 api.github.com.
2. Asset URL은 실제 GitHub Release 응답에서 받은 정확한 repo/tag/file의 github.com 경로만 허용.
3. Redirect는 HTTPS의 github.com/release-assets.githubusercontent.com만 허용.
   다른 host, HTTP downgrade, userinfo, fragment, 비표준 port는 거부.
4. API response1MiB, download pinned size 제한; archive hash 실패 시 추출/설치 안 함.
5. Extractall 대신 streaming regular-file whitelist. Traversal/absolute/backslash/duplicate/extra/
   missing member, symlink/hardlink/special/directory/PAX header 거부.
6. 모든 선택 bundle/member 검증 후 final path 쓰기. 기존 정상 동일 파일은 inode 그대로 재사용.
   기존 다른/손상 파일은 자동 덮어쓰지 않음.
7. Private temporary stage와 atomic no-replace hardlink 사용. 실패 rollback은 이번 호출이
   만든 inode와 빈 directory만 대상으로 하며 기존 사용자 파일 보존.
8. Download TemporaryDirectory는 실패 시 정리. Signed redirect URL/token/server payload를 로그로 출력하지 않음.
9. Installer는 model/pickle을 역직렬화하지 않음. Predictor는 load 직전에 기존 자체 manifest를 다시 검증.

Root는 관리자 통제이며 설치 완료 전에 predictor를 실행하거나 cached model을 hot-swap하지 않습니다.
전체 root에 대한 concurrent-reader snapshot transaction은 아닙니다.
Joblib은 trusted pickle only이고 hash는 공급자 서명 인증을 대신하지 않습니다.

## 설치 / SOC 명령

ML root에서:

```bash
uv sync --project packages/security-ai --frozen \
  --extra network-quality --extra network-edge --extra dns-litert

# 게시 전에도 가능한 local trusted install
uv run --project packages/security-ai --frozen python -m security_ai artifacts install \
  --bundle-dir /path/to/trusted-bundles --artifact-root ./artifacts --model all
uv run --project packages/security-ai --frozen python -m security_ai artifacts verify \
  --artifact-root ./artifacts --model all

# 실제 Release 게시 후
uv run --project packages/security-ai --frozen python -m security_ai artifacts download \
  --artifact-root ./artifacts --model all --version security-ai-artifacts-v1
```

SOC 환경에 package를 설치하려면 ML root에서3 wheels를 빌드하고:

```bash
uv pip install --python ../autonomous-soc-agent/.venv/bin/python --find-links /tmp/security-ai-wheels \
  'security-ai[network-quality,network-edge,dns-litert]==0.1.0'
../autonomous-soc-agent/.venv/bin/python -m security_ai artifacts download \
  --artifact-root /tmp/soc-security-ai-artifacts --model all --version security-ai-artifacts-v1
```

이는 가이드이며 이번 작업은 SOC 소스/환경에 위 명령을 실행하지 않습니다.
Network API config.artifact_root는 통합 root, DNS config.artifact_root는 그 아래 `dns/`입니다.
API/Evidence schemas/error mapping은 [SOC contract](../docs/security_ai/soc_integration_contract.md),
정확한 build/install/verify/inference 명령은 [설치 가이드](../docs/security_ai/artifact_installation.md)에 있습니다.

## 검증 결과

실행 순서: diff-check → Ruff/Format → Network tests → DNS tests → upper tests →
wheel/sdist → fresh package install → local artifact install/verify → actual inference → staged review → commit.

| Check | Result |
|---|---|
| git diff --check | PASS |
| Ruff / Format | PASS |
| 기존 Network tests | 76 passed |
| DNS tests | 61 passed |
| Upper integration/distribution | 57 passed (기존17 + 새 배포/보안40) |
| 합계 package tests | 194 passed, failure0 |
| wheel/sdist | 6 builds PASS; catalog 포함, model/data/SOC 파일 없음 |
| Fresh package install | /tmp/security-ai-artifact-validation 에3 wheel/base dependency 설치 PASS |
| Runtime dependencies | 메모리/다운로드 제한 고려하여 ML/cache의 기존 heavy dependency directory를 .pth로 재사용; SOC env 미사용 |
| Model별/Network/all install | PASS,10 required files; install_local/verify_install |
| SHA-256 | archive3/member10/원본5 모두 PASS |
| 정상 기존 파일 보호 | PASS, 재설치 installed_files=0/reused_files=10 |
| 손상/누락/잘못된 버전 | PASS, 실제 CLI exit1 및 no prediction; corrupt 기존 파일 유지 |
| Archive/HTTPS/cleanup tests | PASS,40 unit tests에 traversal/link/redirect/corrupt/truncated/download failure 포함 |
| 실제 LightGBM | integrated CLI exit0, network-evidence-v1 payload |
| 실제 Network DNN FP32 | integrated CLI exit0, profile=edge |
| 실제 DNS INT8 LiteRT | integrated CLI exit0, dns-evidence-v1 payload |
| 기존 standalone Network/DNS CLI | exit0 |
| HTTPS 실제 원격 download | BLOCKED: Release publication 승인 대기; mocked transport는 원격 성공 근거가 아님 |

검증 JSON/XML은 `reports/security_ai_distribution/`에 보존했습니다.
Fresh root는 `/tmp/security-ai-artifact-validation/final-artifacts`입니다.
합성 feature smoke는 model loading/schema 확인이며 정확도 평가가 아닙니다.
추가 학습·성능 개선·DNS training code 보완·SOC adapter/Fusion은 수행하지 않았습니다.

## Git 반영 / 게시 승인 경계

Commit message: `feat: finalize security AI artifact distribution`.
Git stage 대상은 이전 통합 구현의 source/tests/lockfile/docs/작은 reports와 이번 distribution 구현입니다.
원래 사용자 미추적 `packages/dns_security_package/`는 보존하고 stage 대상에서 제외합니다.
Model 원본5개, data/virtualenv/build/archive/temp files는 stage하지 않습니다.
기존 tracked benchmark checkpoint2개는 새로 변경/삭제/untrack하지 않습니다.

Local commit hash는 `git log -1 --format=%H`로 확인하며 최종 사용자 응답에 보고합니다.
Self-referential hash를 commit 내 report에 임의로 작성하지 않습니다.
Push와 Release upload는 명시적 사용자 승인 전에는 실행하지 않습니다.
승인 대상은 public main의 검증된 commit과 위3개 public Release assets/준비된 release notes입니다.
게시 후 원격 download/검증 결과를 기록하는 경우 같은 범위의 검증 문서 반영도 승인 범위에 포함해 요청합니다.

## 미해결 / 범위 밖

- 외부 게시 승인 전 remote download/push는 BLOCKED.
- DNS training/export/metrics/train-only fit/원래 pairing은 기존 UNVERIFIED 그대로.
- Native TensorFlow2.21 실행은 기존 UNVERIFIED; 이번 배포 smoke는 LiteRT2.3.0.
- SOC 내부 integration/operational accuracy는 이번 배포 작업 범위 밖.
