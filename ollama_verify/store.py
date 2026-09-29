"""Inspect local Ollama manifests and content-addressed blobs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
BLOB = re.compile(r"^sha256-([0-9a-f]{64})$")
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024


def default_root() -> Path:
    """Return the active Ollama model path without requiring the daemon."""
    return Path(os.environ.get("OLLAMA_MODELS", "~/.ollama/models")).expanduser()


def _problem(code: str, path: Path, root: Path, detail: str) -> dict[str, str]:
    return {"code": code, "path": str(path.relative_to(root)), "detail": detail}


def _read_manifest(path: Path, root: Path) -> tuple[set[str], list[dict[str, str]]]:
    problems: list[dict[str, str]] = []
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            return set(), [_problem("unsafe_manifest", path, root, "Not a regular file")]
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return set(), [_problem("manifest_too_large", path, root, "Manifest exceeds 2 MiB")]
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return set(), [_problem("invalid_manifest", path, root, str(exc))]
    if not isinstance(document, dict):
        return set(), [_problem("invalid_manifest", path, root, "Expected a JSON object")]
    entries: list[Any] = [document.get("config")]
    layers = document.get("layers")
    if not isinstance(layers, list):
        problems.append(_problem("invalid_manifest", path, root, "Missing layers array"))
    else:
        entries.extend(layers)
    digests: set[str] = set()
    for index, entry in enumerate(entries):
        digest = entry.get("digest") if isinstance(entry, dict) else None
        match = DIGEST.fullmatch(digest) if isinstance(digest, str) else None
        if match is None:
            problems.append(
                _problem("invalid_digest", path, root, f"Invalid digest at entry {index}")
            )
        else:
            digests.add(match.group(1))
    return digests, problems


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_store(
    root: Path,
    *,
    verify: bool = False,
    max_hash_bytes: int | None = None,
) -> dict[str, Any]:
    """Build a read-only graph of manifests and blobs.

    Metadata scanning never loads model weights into memory. Hash verification
    reads regular files sequentially. Symlinks are reported but never followed.
    """
    if max_hash_bytes is not None and max_hash_bytes < 0:
        raise ValueError("max_hash_bytes must be non-negative")
    root = root.expanduser().absolute()
    report: dict[str, Any] = {
        "schema_version": 1,
        "root": str(root),
        "store_exists": root.is_dir(),
        "verification_requested": verify,
        "models": [],
        "blobs": [],
        "orphans": [],
        "problems": [],
        "summary": {},
    }
    if not root.is_dir():
        report["summary"] = _summary(report)
        return report
    manifest_root = root / "manifests"
    blob_root = root / "blobs"
    references: dict[str, set[str]] = {}
    if manifest_root.is_dir():
        for path in sorted(manifest_root.rglob("*")):
            if path.is_dir():
                continue
            model = str(path.relative_to(manifest_root))
            digests, problems = _read_manifest(path, root)
            report["problems"].extend(problems)
            report["models"].append({"name": model, "blob_count": len(digests)})
            for digest in digests:
                references.setdefault(digest, set()).add(model)
    elif manifest_root.exists():
        report["problems"].append(
            _problem("unsafe_manifest_root", manifest_root, root, "Not a directory")
        )
    actual: dict[str, dict[str, Any]] = {}
    if blob_root.is_dir():
        for path in sorted(blob_root.iterdir()):
            match = BLOB.fullmatch(path.name)
            if match is None:
                continue
            digest = match.group(1)
            try:
                info = path.lstat()
            except OSError as exc:
                report["problems"].append(_problem("unreadable_blob", path, root, str(exc)))
                continue
            if not stat.S_ISREG(info.st_mode):
                report["problems"].append(
                    _problem("unsafe_blob", path, root, "Not a regular file")
                )
                continue
            actual[digest] = {"digest": f"sha256:{digest}", "size_bytes": info.st_size}
    elif blob_root.exists():
        report["problems"].append(
            _problem("unsafe_blob_root", blob_root, root, "Not a directory")
        )
    hashed_bytes = 0
    for digest in sorted(references):
        blob = actual.get(digest)
        path = blob_root / f"sha256-{digest}"
        if blob is None:
            report["problems"].append(
                _problem("missing_blob", path, root, ", ".join(sorted(references[digest])))
            )
            continue
        entry = {**blob, "models": sorted(references[digest]), "integrity": "unchecked"}
        if verify:
            size = blob["size_bytes"]
            if max_hash_bytes is not None and hashed_bytes + size > max_hash_bytes:
                entry["integrity"] = "skipped_budget"
            else:
                try:
                    observed = _sha256(path)
                    hashed_bytes += size
                    entry["integrity"] = "verified" if observed == digest else "corrupt"
                    if observed != digest:
                        report["problems"].append(
                            _problem("corrupt_blob", path, root, f"Observed sha256:{observed}")
                        )
                except OSError as exc:
                    entry["integrity"] = "unreadable"
                    report["problems"].append(_problem("unreadable_blob", path, root, str(exc)))
        report["blobs"].append(entry)
    for digest in sorted(actual.keys() - references.keys()):
        report["orphans"].append(actual[digest])
    report["summary"] = _summary(report)
    return report


def _summary(report: dict[str, Any]) -> dict[str, int]:
    blobs = report["blobs"]
    orphans = report["orphans"]
    return {
        "models": len(report["models"]),
        "referenced_blobs": len(blobs),
        "orphan_blobs": len(orphans),
        "orphan_bytes": sum(item["size_bytes"] for item in orphans),
        "verified_blobs": sum(item["integrity"] == "verified" for item in blobs),
        "unchecked_blobs": sum(item["integrity"] == "unchecked" for item in blobs),
        "skipped_blobs": sum(item["integrity"] == "skipped_budget" for item in blobs),
        "problems": len(report["problems"]),
    }
