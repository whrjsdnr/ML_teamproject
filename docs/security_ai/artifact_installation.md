# Security AI artifact 설치 및 배포

Artifact release version: `security-ai-artifacts-v1`.
대상 저장소는 확인된 공개 `whrjsdnr/ML_teamproject`입니다. 실제 게시·push는 사용자 승인 후 수행합니다.
GitHub Release를 선택하며 모델 원본은 일반 Git에 추가하지 않습니다.

## Release / LFS 결정

세 archive의 합계는 약 20.33 MB입니다. Release는 code clone과 모델 설치를 분리하고
모델 선택 설치, pinned SHA-256 및 버전 고정에 적합합니다. 인증된 계정의 admin/push 권한을
읽기 전용으로 확인했습니다. 저장소는 public이며 업로드한 모델도 공개됩니다.
기존 Release 및 해당 tag는 없었습니다. Git LFS 클라이언트는 현재 설치되어 있지 않습니다.
LFS는 clone 시 모델을 자동 받는 방식에 적합하지만 별도 storage/bandwidth quota와 클라이언트가 필요합니다.
이 작업은 LFS 설치/track/migration/push를 수행하지 않습니다.

GitHub 공식 기준으로 Release asset당 2 GiB 미만이어야 하며 아래 archive는 모두 여유가 있습니다.
[Release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases),
[LFS quotas](https://docs.github.com/en/billing/concepts/product-billing/git-lfs).

## 설치할 파일과 계약

| Selection | Archive | Bytes | SHA-256 |
|---|---|---:|---|
| network-quality | security-ai-artifacts-v1-network-quality.tar.gz | 19959438 | 2ca983baf8d85b97791e43c1f31f267b547a0d371e5d39bb0732108b48f97acf |
| network-edge | security-ai-artifacts-v1-network-edge.tar.gz | 361380 | 4c513228e613c8013d3fef22f4bb8bf8f6d432d7834c6afddcf95915b1e21aeb |
| dns | security-ai-artifacts-v1-dns.tar.gz | 8304 | 05241751478e9fd1d707534422e6b1033af9489006d8523f7bb78a210dbfd08b |

`--model network`는 quality+edge, `--model all`은 세 archive를 설치합니다.
quality는 LightGBM만, edge는 DNN checkpoint+필수 scaler, dns는 INT8+필수 scaler입니다.
각 bundle에는 `bundle.json`과 해당 feature/label/threshold/model manifest가 포함됩니다.
Archive와 모든 member의 크기·SHA-256은 패키지의 `artifact_catalog.json`에 고정되어 있습니다.
원본5개 파일 hash는 [artifact inventory](../../reports/security_ai/artifact_inventory.json)에 있습니다.
Catalog는 전송 계약이며 기존 Network/DNS loader manifest를 대체하지 않습니다.

설치 결과:

```text
<artifact-root>/
├── models/network/
│   ├── lightgbm_top40_v4b2.txt
│   ├── dnn_top40_v4_best.pt
│   └── dnn_top40_v4_scaler.joblib
├── dns/
│   ├── model/dnn_int8.tflite
│   └── preprocessor/scaler.joblib
└── metadata/
    ├── network/{artifact_manifest.json,top40_features.csv,label_mapping.json}
    └── dns/{artifact_manifest.json,feature_contract.json}
```

Network API artifact_root는 `<artifact-root>`, DNS API는 `<artifact-root>/dns`입니다.
Package APIs, model/feature versions, class labels, threshold0.5, score 의미는 변경하지 않습니다.
DNS training/export·성능 provenance의 기존 UNVERIFIED 제한도 그대로 유지합니다.

## Clone → package install

ML root에서 필요한 runtime만 설치합니다.

```bash
# 세 모델 모두 사용
uv sync --project packages/security-ai --frozen \
  --extra network-quality --extra network-edge --extra dns-litert

# DNS만 사용할 경우 network extras를 생략합니다.
```

SOC checkout 자체는 수정할 필요가 없습니다. SOC의 선택 Python environment에서 별도 설치할 때:

```bash
# ML에서 wheel3개를 빌드
uv build --project packages/network-security-ai --out-dir /tmp/security-ai-wheels
uv build --project packages/dns-security-ai --out-dir /tmp/security-ai-wheels
uv build --project packages/security-ai --out-dir /tmp/security-ai-wheels

# 실제 SOC 환경 Python 경로를 명시하여 관리자가 설치
uv pip install --python ../autonomous-soc-agent/.venv/bin/python --find-links /tmp/security-ai-wheels \
  'security-ai[network-quality,network-edge,dns-litert]==0.1.0'
```

Registry 공개를 가정하지 않습니다. 마지막 명령은 설치 가이드이며 이번 작업에서 SOC에 실행하지 않습니다.
현재 사용자 환경의 절대 Python 경로는 `/home/geonug/kdt-linux/autonomous-soc-agent/.venv/bin/python`입니다.
SOC에서 직접 설치한 후 `python -m security_ai artifacts ...`로 artifact root를 SOC가 관리하는
별도 디렉터리로 지정하세요. Package 출력과 SOC adapter의 연결은 후속 작업입니다.
Root는 관리자 소유의 로컬 directory여야 합니다. Root parent는 미리 존재해야 합니다.
예제의 `./artifacts`는 .gitignore로 제외됩니다.

## Local trusted bundle 설치

팀 관리자가 모델이 존재하는 ML checkout에서 bundle을 만듭니다. 모델을 다시 fit하지 않습니다.

```bash
uv run --project packages/security-ai --frozen python -m security_ai artifacts bundle \
  --network-root . \
  --dns-root packages/dns_security_package/dns_security_package/dns_security \
  --output /tmp/security-ai-artifact-bundles --model all
```

기존 같은 이름의 archive를 덮어쓰지 않습니다. 별도 output directory를 선택하세요.
관리자가 전달한 신뢰할 수 있는 bundle directory에서:

```bash
uv run --project packages/security-ai --frozen python -m security_ai artifacts install \
  --bundle-dir /path/to/trusted-bundles --artifact-root ./artifacts \
  --model all --version security-ai-artifacts-v1
uv run --project packages/security-ai --frozen python -m security_ai artifacts verify \
  --artifact-root ./artifacts --model all --version security-ai-artifacts-v1
```

`bundle` 명령은 선택 모델만 만들 수 있지만 인자 network-root/dns-root는 항상 받습니다.
선택하지 않은 root의 모델은 읽지 않습니다. `install`은 모델을 로딩하거나 pickle을 실행하지 않습니다.

## HTTPS Release 다운로드 설치

Release가 실제 게시된 뒤 다음 명령을 사용합니다. 게시되지 않았으면 실패하며 원격 배포는 BLOCKED입니다.

```bash
uv run --project packages/security-ai --frozen python -m security_ai artifacts download \
  --artifact-root ./artifacts --model all --version security-ai-artifacts-v1

# 필요한 모델만 설치
uv run --project packages/security-ai --frozen python -m security_ai artifacts download \
  --artifact-root ./artifacts --model dns --version security-ai-artifacts-v1
```

Downloader는 확인된 repository/tag의 GitHub API에서 **실제로 게시된 asset URL**을 읽습니다.
가상의 다운로드 URL이나 사용자 지정 `--url`은 제공하지 않습니다.
API는 api.github.com, asset 초기 URL은 정확한 repo/tag/file의 github.com HTTPS만 허용합니다.
Redirect도 HTTPS의 github.com/release-assets.githubusercontent.com으로 제한하고
userinfo, 비표준 port, fragment, 다른 host, HTTP downgrade를 거부합니다. 기본 TLS 검증을 유지합니다.
공개 Release라 토큰을 보내지 않으며 private 저장소 다운로드를 임의로 우회하지 않습니다.
GitHub API rate limit/일시 장애 시 로컬 trusted bundle 설치를 사용할 수 있습니다.

## Integrity / 안전한 설치 / 오류

- Archive 크기·SHA-256 검증 후 member별 정확한 이름·크기·SHA-256과 bundle version을 검증합니다.
- 모든 선택 archive를 검증하기 전에는 최종 root에 파일을 쓰지 않습니다.
- Archive path traversal/절대경로/중복/extra/missing members, symlink/hardlink/device/directory/PAX를 거부합니다.
- 기존 동일 파일은 재사용하고 inode를 유지합니다. 다른 파일·기존 symlink는 거부하며 자동 교체하지 않습니다.
- 같은 filesystem의 temporary stage에서 atomic no-replace hardlink로 파일을 게시합니다.
- 설치 도중 실패하면 이번 호출이 생성한 파일·빈 directory만 제거하고 기존 사용자 파일은 보존합니다.
- 실패한 다운로드/부분 archive는 TemporaryDirectory 안에서 제거하며 검증 실패 bytes는 설치하지 않습니다.
- 설치 root는 관리자 통제가 필요합니다. 동시 reader 전체에 대한 snapshot transaction은 아니므로
  설치 완료 후 predictor를 생성하세요. 기존 predictor cache를 hot-swap하지 않습니다.
- Predictor는 기존대로 model load 직전에 자체 manifest hash/feature/scaler 계약도 확인합니다.
- Joblib은 trusted pickle only입니다. Checksum은 출처 서명 인증을 대신하지 않습니다.

오류: `ArtifactVersionError`, `ArtifactIntegrityError`, `ArtifactDownloadError`,
`ArtifactInstallConflict`는 `ArtifactDistributionError` 하위입니다. CLI는 exit1이며
서명 redirect URL/token/raw server response를 출력하지 않습니다. 정상 prediction fallback은 없습니다.

## 검증된 모델 실행

```bash
uv run --project packages/security-ai --frozen --extra network-quality python -m security_ai network \
  --artifact-root ./artifacts --profile detection_quality \
  --input packages/network-security-ai/examples/synthetic_top40.json
uv run --project packages/security-ai --frozen --extra network-edge python -m security_ai network \
  --artifact-root ./artifacts --profile edge \
  --input packages/network-security-ai/examples/synthetic_top40.json
uv run --project packages/security-ai --frozen --extra dns-litert python -m security_ai dns \
  --artifact-root ./artifacts/dns --input packages/dns-security-ai/examples/synthetic_stateless9.json
```

출력은 `security-ai-envelope-v1`과 typed `network-evidence-v1`/`dns-evidence-v1` payload입니다.
합성 smoke이며 정확도 검증이 아닙니다. API 예제는 [SOC contract](soc_integration_contract.md)를 참조하세요.

## 재현 및 배포 검증 기록

[Artifact distribution report](../../reports/Security_AI_Artifact_Distribution_Report.md)에
모델별 설치, 전체 설치, 손상/누락/버전/링크/실패 cleanup, wheel/sdist, 실제 추론 결과 및
Git/Release 게시 상태를 기록합니다. 외부 게시 전 검증을 원격 다운로드 성공으로 표시하지 않습니다.
