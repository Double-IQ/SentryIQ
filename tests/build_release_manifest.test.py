import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-release-manifest.py"


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "package"
        (self.root / "app").mkdir(parents=True)
        (self.root / "runtime").mkdir()
        (self.root / "app" / "index.php").write_bytes(b"<?php echo 'ok';")
        (self.root / "runtime" / "vault.php").write_bytes(b"<?php // runtime")
        self.output = Path(self.temp.name) / "release-manifest.json"

    def run_builder(self, *extra):
        return subprocess.run([
            sys.executable, str(SCRIPT),
            "--root", str(self.root),
            "--version", "0.1.3",
            "--commit", "a" * 40,
            "--repository", "Double-IQ/SentryIQ",
            "--repository-id", "1345956206",
            "--workflow-path", ".github/workflows/release.yml",
            "--output", str(self.output),
            *extra,
        ], capture_output=True, text=True)

    def test_manifest_contains_exact_file_hashes_and_metadata(self):
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(self.output.read_text())
        self.assertEqual(manifest["format"], 2)
        self.assertEqual(manifest["repository_id"], "1345956206")
        self.assertEqual(manifest["commit"], "a" * 40)
        files = {entry["path"]: entry for entry in manifest["files"]}
        expected = b"<?php echo 'ok';"
        self.assertEqual(files["app/index.php"]["size"], len(expected))
        self.assertEqual(files["app/index.php"]["sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual(manifest["public_files"], ["app/index.php"])
        self.assertEqual(manifest["runtime_files"], ["vault.php"])

    def test_manifest_is_deterministic(self):
        self.assertEqual(self.run_builder().returncode, 0)
        first = self.output.read_bytes()
        self.assertEqual(self.run_builder().returncode, 0)
        self.assertEqual(self.output.read_bytes(), first)

    def test_rejects_invalid_commit(self):
        result = self.run_builder("--commit", "not-a-commit")
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_missing_runtime_inventory(self):
        (self.root / "runtime" / "vault.php").unlink()
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
