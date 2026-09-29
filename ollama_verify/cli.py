"""Command line interface for Ollama model store diagnostics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .store import default_root, scan_store


def _short(value: str) -> str:
    return value[:22] + "..." if len(value) > 22 else value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ollama-verify",
        description="Inspect local Ollama model manifests and blobs without changing them.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Report missing, corrupt, and orphaned blobs")
    scan.add_argument("--root", type=Path, default=default_root(), help="Ollama models directory")
    scan.add_argument(
        "--verify", action="store_true", help="Hash referenced blobs, which may take time"
    )
    scan.add_argument(
        "--max-hash-bytes",
        type=int,
        help="Maximum referenced blob bytes to hash with --verify",
    )
    scan.add_argument("--json", action="store_true", help="Print a machine-readable JSON report")
    scan.add_argument(
        "--strict-orphans",
        action="store_true",
        help="Exit with status 2 when orphaned blobs exist",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.max_hash_bytes is not None and args.max_hash_bytes < 0:
        print("error: --max-hash-bytes must be non-negative", file=sys.stderr)
        return 2
    if args.max_hash_bytes is not None and not args.verify:
        print("error: --max-hash-bytes requires --verify", file=sys.stderr)
        return 2
    report = scan_store(args.root, verify=args.verify, max_hash_bytes=args.max_hash_bytes)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        summary = report["summary"]
        print(f"Store: {report['root']}")
        if not report["store_exists"]:
            print("No model store found. Nothing to scan.")
        else:
            print(f"Models: {summary['models']}")
            print(f"Referenced blobs: {summary['referenced_blobs']}")
            print(f"Verified blobs: {summary['verified_blobs']}")
            print(f"Orphan blobs: {summary['orphan_blobs']} ({summary['orphan_bytes']} bytes)")
            print(f"Problems: {summary['problems']}")
            if not args.verify:
                print("Content hashes not checked. Add --verify for full integrity verification.")
            elif summary["skipped_blobs"]:
                print(f"Hash budget skipped {summary['skipped_blobs']} referenced blobs.")
            for item in report["problems"]:
                print(
                    f"{item['code']}: {_short(Path(item['path']).name)} "
                    f"({_short(item['detail'])})"
                )
            for item in report["orphans"]:
                print(f"orphan: {_short(item['digest'])} ({item['size_bytes']} bytes)")
            if report["problems"] or report["orphans"]:
                print("Use --json for full paths and digests.")
    return 2 if report["problems"] or (args.strict_orphans and report["orphans"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
