# Team-share consolidation validation

검증일: 2026-10-06. 모델 재학습/tuning, Test V2 재사용, 실제 SOC 통합은 수행하지 않았습니다.

| 검증 | 결과 |
|---|---|
| 변경 전 standalone package | 66 passed, package 자체 uv 환경 |
| 변경 후 standalone package 전체 | 76 passed |
| memory benchmark raw LightGBM / DNN scaler branches | 2 passed, mock data |
| Ruff check / format | PASS, package 전체 + 변경 benchmark + script tests |
| git diff --check | PASS |
| wheel / sdist | build 성공, `/tmp/network-security-ai-dist/` |
| wheel resource 검사 | Top40 CSV / label mapping JSON / digest manifest 포함 |
| wheel isolated import | SOC sys.path/import 없이 40 features / 15 classes 로딩 |
| LightGBM CLI smoke | 실제 reviewed V4-B2 artifact, exit 0 |
| DNN CLI smoke | 실제 reviewed epoch13 checkpoint + fitted scaler, exit 0 |
| Notebook 보존 검사 | outputs / execution counts / cell metadata 변경 없음 |
| metadata 원본 비교 | source artifact와 byte-identical, manifest SHA256 일치 |

실제 CLI smoke는 synthetic 0..39 input으로 model loading과 prediction/evidence schema를 검증한 것이며 정확도 평가나 실제 traffic 검증이 아닙니다. `.env`를 읽거나 수정하지 않았고 live API/network를 사용하지 않았습니다. 모델/데이터/실험 결과는 복사하거나 overwrite하지 않았습니다. Commit/stage/push는 수행하지 않았습니다.

실행 명령은 package README와 reproducibility 문서를 참조하세요. `uv run --project`는 Python 환경을 선택하며 pytest config/test path는 README처럼 별도 명시합니다. 모델이 없다면 artifact error는 정상적인 fail-closed 결과입니다. Team clone은 작은 metadata와 코드만으로 tests/build가 가능하고 inference에는 별도로 공유되는 trusted model artifacts가 필요합니다.
