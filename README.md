# ollama-verify

Find damaged, missing, and unreferenced Ollama model blobs without starting the Ollama daemon.

A metadata scan of the author's local store inspected 4 model manifests and 15 referenced blobs in 0.02 seconds.[^measurement] Hash verification is a separate command because reading every model layer can take much longer.

[![CI](https://github.com/Arthur031221/ollama-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/Arthur031221/ollama-verify/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](CHANGELOG.md)

![Command line demo](demo/demo.gif)

## Why

Ollama stores model layers by SHA-256 digest. A manifest can still point to a file whose contents no longer match its name. A successful pull or a model listing does not prove that existing local bytes are intact. Unreferenced blobs can also occupy disk after model changes. `ollama-verify` inspects those relationships directly, without a model download or daemon connection.

The two motivating reports are an [Ollama corrupted-blob issue](https://github.com/ollama/ollama/issues/17520) and an [orphaned-blob issue](https://github.com/ollama/ollama/issues/18595). These are individual reports, not a prevalence estimate.

## Install

Python 3.10 or newer:

```bash
python3 -m pip install git+https://github.com/Arthur031221/ollama-verify.git
```

For a local checkout, run `python3 -m pip install .` from the repository root.

## Quick start

```bash
ollama-verify scan
ollama-verify scan --verify
```

The first command reads manifests and file metadata. It reports missing and orphaned blobs but does not inspect blob contents. The second hashes each referenced regular file and detects a digest mismatch. Both commands are read-only. Set `OLLAMA_MODELS` or use `--root /path/to/models` for a custom store.

Example:

```text
Store: /Users/example/.ollama/models
Models: 1
Referenced blobs: 2
Verified blobs: 1
Orphan blobs: 1 (16 bytes)
Problems: 1
corrupt_blob: sha256-471901c5e2cfa3c... (Observed sha256:dc1f276...)
orphan: sha256:8a5ca52974b75a9... (16 bytes)
Use --json for full paths and digests.
```

This is illustrative output from a synthetic fixture. No user model was damaged to make the demo.

## How it works

The scanner reads each JSON file below `manifests/`, collects the `config` and `layers` digests, then checks the matching `blobs/sha256-<digest>` files. A blob with no manifest reference is an orphan. With `--verify`, it streams each referenced blob through SHA-256 using a 1 MiB read buffer. It never loads weights into a model and never follows a blob symlink. A missing store returns a clean empty report.

The default scan does not claim that present blobs are sound. A budgeted verification explicitly labels blobs it did not hash as `skipped_budget`. JSON output includes every finding and the integrity state of each referenced blob.

## Comparison

| Tool | Main purpose | Content-hash check | Missing and orphan report |
| --- | --- | --- | --- |
| `ollama list` | List models through Ollama | Not an offline blob audit | No orphan inventory |
| [ollama-inspector](https://github.com/MohamedAliBouhaouala/ollama-inspector) | Inspect model metadata and blob ownership | Not documented in its current README | Orphans, with model references |
| [ollama-audit](https://github.com/bharat3645/ollama-audit) | Audit missing, stale, and orphaned files | Not documented in its current README | Both |
| `ollama-verify` | Check the manifest-to-blob graph and optional bytes | SHA-256 for referenced blobs | Both |

The comparison describes documented behavior checked on 2026-09-30. The other tools solve useful adjacent problems, especially richer model metadata and stale-model reporting.

## Command reference

```text
ollama-verify scan [--root PATH] [--verify] [--max-hash-bytes N] [--json] [--strict-orphans]
```

`--root` defaults to `$OLLAMA_MODELS` or `~/.ollama/models`. `--verify` checks file contents. `--max-hash-bytes N` bounds the total bytes hashed and requires `--verify`. `--json` prints a stable schema with a `schema_version` field. `--strict-orphans` treats orphaned files as a failing condition. The exit status is 0 for no problems, or 2 for malformed manifests, missing or corrupt blobs, unreadable files, and strict orphan findings.

For scripting:

```bash
ollama-verify scan --verify --max-hash-bytes 1073741824 --json > audit.json
```

## Limits and FAQ

- No files are deleted, repaired, downloaded, or quarantined. Review a finding before using Ollama's own commands to repair a model.
- Hash verification can read many gigabytes. Use `--max-hash-bytes` to bound it. A skipped blob is not verified.
- The scanner understands the current local `manifests/` and `blobs/` layout. A future Ollama layout may require an update.
- A valid hash proves only that a local file matches the digest in its filename. It does not prove model safety, license compliance, or that Ollama can load the model.
- Unknown files in `blobs/` are ignored. The orphan total counts only valid `sha256-<digest>` file names.
- A manifest or blob symlink is reported and never followed.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). MIT, copyright 2026 Arthur.

[^measurement]: One `ollama-verify scan --json` run on the author's MacBook Air M5 on 2026-09-30. `/usr/bin/time -p` reported 0.02 seconds of wall time. The local store had 4 manifests and 15 referenced blobs. Content hashing was disabled. This is a startup and metadata-scan observation, not a throughput benchmark.
