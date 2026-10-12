"""Manage pinned trusted bundles without changing predictor APIs."""

import argparse
import json
import sys
from pathlib import Path

from security_ai.artifacts import (
    SELECTIONS,
    VERSION,
    ArtifactDistributionError,
    catalog,
    create_bundles,
    download_install,
    install_local,
    verify_install,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("manifest")
    for name in ("bundle", "install", "download", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--model", choices=SELECTIONS, default="all")
        p.add_argument("--version", default=VERSION)
        if name == "bundle":
            p.add_argument("--network-root", type=Path, required=True)
            p.add_argument("--dns-root", type=Path, required=True)
            p.add_argument("--output", type=Path, required=True)
        else:
            p.add_argument("--artifact-root", type=Path, required=True)
            if name == "install":
                p.add_argument("--bundle-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "manifest":
            result = catalog()
        elif args.command == "bundle":
            result = create_bundles(
                args.network_root,
                args.dns_root,
                args.output,
                model=args.model,
                version=args.version,
            )
        elif args.command == "install":
            result = install_local(
                args.bundle_dir, args.artifact_root, model=args.model, version=args.version
            )
        elif args.command == "download":
            result = download_install(args.artifact_root, model=args.model, version=args.version)
        else:
            result = verify_install(args.artifact_root, model=args.model, version=args.version)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (ArtifactDistributionError, OSError) as error:
        # Typed, fixed messages only; do not expose signed redirect URLs or raw server responses.
        print(
            f"{type(error).__name__}: artifact operation failed; verify trusted bundle, "
            "version, installation path and published Release availability.",
            file=sys.stderr,
        )
        return 1
