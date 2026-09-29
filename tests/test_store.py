"""Behavioral fixtures for manifest and blob audits."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from ollama_verify.cli import main
from ollama_verify.store import scan_store


class StoreFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "blobs").mkdir()
        (self.root / "manifests" / "registry.ollama.ai" / "library" / "fixture").mkdir(
            parents=True
        )

    def blob(self, contents: bytes, *, corrupt: bool = False) -> str:
        digest = hashlib.sha256(contents).hexdigest()
        stored = b"changed" if corrupt else contents
        (self.root / "blobs" / f"sha256-{digest}").write_bytes(stored)
        return f"sha256:{digest}"

    def manifest(self, config: str, layers: list[str]) -> None:
        path = self.root / "manifests" / "registry.ollama.ai" / "library" / "fixture" / "latest"
        path.write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "config": {"digest": config},
                    "layers": [{"digest": digest} for digest in layers],
                }
            )
        )


class ScanTests(StoreFixture):
    def test_clean_store(self) -> None:
        config = self.blob(b"config")
        layer = self.blob(b"weights")
        self.manifest(config, [layer])
        report = scan_store(self.root, verify=True)
        self.assertEqual(report["summary"]["verified_blobs"], 2)
        self.assertEqual(report["summary"]["problems"], 0)
        self.assertEqual(report["summary"]["orphan_blobs"], 0)

    def test_corrupt_missing_and_orphan_are_distinct(self) -> None:
        config = self.blob(b"config", corrupt=True)
        missing = f"sha256:{'0' * 64}"
        self.blob(b"orphan")
        self.manifest(config, [missing])
        report = scan_store(self.root, verify=True)
        self.assertEqual(
            {item["code"] for item in report["problems"]}, {"corrupt_blob", "missing_blob"}
        )
        self.assertEqual(report["summary"]["orphan_blobs"], 1)

    def test_metadata_scan_does_not_claim_integrity(self) -> None:
        config = self.blob(b"config", corrupt=True)
        self.manifest(config, [])
        report = scan_store(self.root)
        self.assertEqual(report["summary"]["unchecked_blobs"], 1)
        self.assertEqual(report["summary"]["problems"], 0)

    def test_hash_budget_skips_large_blob(self) -> None:
        config = self.blob(b"config")
        self.manifest(config, [])
        report = scan_store(self.root, verify=True, max_hash_bytes=3)
        self.assertEqual(report["summary"]["skipped_blobs"], 1)
        self.assertEqual(report["summary"]["verified_blobs"], 0)

    def test_malformed_manifest_is_reported(self) -> None:
        path = self.root / "manifests" / "registry.ollama.ai" / "library" / "fixture" / "latest"
        path.write_text("{broken")
        report = scan_store(self.root)
        self.assertEqual(report["problems"][0]["code"], "invalid_manifest")

    def test_symlink_blob_is_not_followed(self) -> None:
        config = hashlib.sha256(b"config").hexdigest()
        external = self.root / "external"
        external.write_bytes(b"config")
        (self.root / "blobs" / f"sha256-{config}").symlink_to(external)
        self.manifest(f"sha256:{config}", [])
        report = scan_store(self.root, verify=True)
        codes = {item["code"] for item in report["problems"]}
        self.assertIn("unsafe_blob", codes)
        self.assertNotIn("corrupt_blob", codes)

    def test_absent_store_is_empty(self) -> None:
        report = scan_store(self.root / "absent", verify=True)
        self.assertFalse(report["store_exists"])
        self.assertEqual(report["summary"]["problems"], 0)

    def test_cli_exit_code_for_corruption(self) -> None:
        config = self.blob(b"config", corrupt=True)
        self.manifest(config, [])
        with redirect_stdout(StringIO()) as output:
            code = main(["scan", "--root", str(self.root), "--verify", "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["problems"][0]["code"], "corrupt_blob")


if __name__ == "__main__":
    unittest.main()
