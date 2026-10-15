"""Explicit offline stages. Test is never opened by prepare/train/lock/diagnostic."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from ml.network_research.dataset import (
    acquisition,
    build_session,
    leakage,
    seal,
    store_split,
    write_new,
)
from ml.network_research.locked_test import (
    create_lock,
    diagnostic_evaluation,
    final_evaluation,
)
from ml.network_research.training import CANDIDATES, select


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "stage", choices=("prepare", "train", "lock", "final-test", "diagnostic")
    )
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--trusted-lock-digest")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    if args.stage == "prepare":
        args.data.mkdir(mode=0o700, parents=True, exist_ok=False)
        sources = acquisition(repo)
        sets, reports = {}, {}
        for role in ("train", "validation", "diagnostic"):
            rows, report = build_session(*sources[role], role)
            store_split(args.data, role, rows, report)
            sets[role], reports[role] = rows, report
        checks = {
            a + "__" + b: leakage(sets[a], sets[b])
            for a, b in (
                ("train", "validation"),
                ("train", "diagnostic"),
                ("validation", "diagnostic"),
            )
        }
        write_new(
            args.data / "research-split.json",
            seal(
                {
                    "status": "RESEARCH_ONLY",
                    "roles": {k: v["session"] for k, v in reports.items()},
                    "manifests": {k: v["manifest_digest"] for k, v in reports.items()},
                    "leakage": checks,
                    "test": "34-1_LOCKED_UNTIL_SELECTION_COMPLETE",
                    "operational_admission": "BLOCKED",
                }
            ),
        )
    elif args.stage == "train":
        args.artifacts.mkdir(mode=0o700, parents=True, exist_ok=False)
        reports = []
        for name in CANDIDATES:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ml.network_research.training",
                    "--data",
                    str(args.data),
                    "--output",
                    str(args.artifacts / name),
                    "--candidate",
                    name,
                ],
                env={
                    **os.environ,
                    "OPENBLAS_NUM_THREADS": "1",
                    "OMP_NUM_THREADS": "1",
                    "MKL_NUM_THREADS": "1",
                },
                check=True,
                timeout=180,
                stdout=subprocess.DEVNULL,
            )
            reports.append(
                json.loads((args.artifacts / name / "artifact.json").read_text())
            )
        write_new(
            args.artifacts / "selection.json",
            seal({"selection": select(reports), "candidates": reports}),
        )
    elif args.stage == "lock":
        document = create_lock(repo, args.data, args.artifacts)
        write_new(args.artifacts / "test-lock.json", document)
        print(document["manifest_digest"])
    elif args.stage == "final-test":
        if not args.trusted_lock_digest:
            parser.error("--trusted-lock-digest is mandatory")
        result = final_evaluation(
            repo,
            args.data,
            args.artifacts,
            trusted_lock_digest=args.trusted_lock_digest,
        )
        print(result["manifest_digest"])
    else:
        write_new(
            args.artifacts / "diagnostic-result.json",
            diagnostic_evaluation(args.data, args.artifacts),
        )


if __name__ == "__main__":
    main()
