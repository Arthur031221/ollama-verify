"""Create a tiny, safe fixture for the recorded command-line demo."""

import hashlib
import json
import tempfile
from pathlib import Path


def main() -> None:
    root = Path(tempfile.mkdtemp(prefix="ollama-verify-demo-"))
    blobs = root / "blobs"
    manifest = root / "manifests" / "registry.ollama.ai" / "library" / "demo" / "latest"
    blobs.mkdir(parents=True)
    manifest.parent.mkdir(parents=True)
    good = hashlib.sha256(b"config").hexdigest()
    bad = hashlib.sha256(b"expected model layer").hexdigest()
    orphan = hashlib.sha256(b"unused old layer").hexdigest()
    (blobs / f"sha256-{good}").write_bytes(b"config")
    (blobs / f"sha256-{bad}").write_bytes(b"damaged model layer")
    (blobs / f"sha256-{orphan}").write_bytes(b"unused old layer")
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "config": {"digest": f"sha256:{good}"},
                "layers": [{"digest": f"sha256:{bad}"}],
            }
        )
    )
    print(root)


if __name__ == "__main__":
    main()
