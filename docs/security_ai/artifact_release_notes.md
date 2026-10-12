# Security AI artifacts v1

Reviewed artifact bundles for the independent `security-ai` Python package.
No datasets, raw DNS/network payloads, virtual environments or SOC source are included.

Assets:

- `security-ai-artifacts-v1-network-quality.tar.gz`: LightGBM V4-B2 + Top40/label/model metadata.
- `security-ai-artifacts-v1-network-edge.tar.gz`: DNN FP32 epoch13 + fitted scaler + Top40/label/model metadata.
- `security-ai-artifacts-v1-dns.tar.gz`: DNS INT8 TFLite DNN + fitted StandardScaler + feature/threshold/model metadata.

The package's `artifact_catalog.json` pins archive and member sizes and SHA-256 values.
Install only the required model or all three; existing different files are never overwritten.
The downloader obtains confirmed HTTPS asset URLs from this published Release and verifies checksums.

From the ML checkout:

```bash
uv sync --project packages/security-ai --frozen \
  --extra network-quality --extra network-edge --extra dns-litert
uv run --project packages/security-ai --frozen python -m security_ai artifacts download \
  --artifact-root ./artifacts --model all --version security-ai-artifacts-v1
uv run --project packages/security-ai --frozen python -m security_ai artifacts verify \
  --artifact-root ./artifacts --model all
```

Network predictor root is `./artifacts`; DNS predictor root is `./artifacts/dns`.
See `docs/security_ai/artifact_installation.md` for local trusted-bundle installation,
standalone inference and error handling.

Model accuracy is not newly evaluated. DNS DNN training/export provenance, train-only scaler fit,
original model/scaler training pairing and DNS DNN accuracy remain UNVERIFIED.
Joblib artifacts are trusted pickle only. Checksums do not replace source authenticity.
No retraining, tuning, model API changes or SOC integration is included.
