import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_sidecar(artifact: Path, sidecar: Path) -> None:
    fields = sidecar.read_text(encoding="utf-8").strip().split()
    assert len(fields) == 2, f"invalid checksum sidecar: {sidecar.name}"
    assert fields[0] == sha256(artifact.read_bytes()), f"checksum mismatch: {artifact.name}"
    assert fields[1] == artifact.name, f"sidecar filename mismatch: {sidecar.name}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    package = args.dist / f"sentryiq-{args.version}.zip"
    package_sidecar = args.dist / f"{package.name}.sha256"
    manifest_file = args.dist / "release-manifest.json"
    manifest_sidecar = args.dist / "release-manifest.json.sha256"
    for path in (package, package_sidecar, manifest_file, manifest_sidecar):
        assert path.is_file(), f"missing release output: {path.name}"

    check_sidecar(package, package_sidecar)
    check_sidecar(manifest_file, manifest_sidecar)
    external_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))

    with zipfile.ZipFile(package) as archive:
        names = {name for name in archive.namelist() if not name.endswith("/")}
        assert "update-manifest.json" in names
        embedded_manifest = json.loads(archive.read("update-manifest.json"))
        assert embedded_manifest == external_manifest, "embedded/external manifests differ"
        assert not any(name.startswith((".git/", ".github/", "private_data/")) for name in names)
        assert "sentryiq_config.php" not in names
        assert "index.php" in names
        assert "app/Security/FirstRun.php" in names
        installer = archive.read("app/Security/FirstRun.php").decode("utf-8")
        assert "'/runtime'" in installer
        assert "'/private_data'" not in installer
        htaccess = archive.read(".htaccess").decode("utf-8")
        assert "RewriteRule ^runtime(?:/|$) - [F,L]" in htaccess

        expected_runtime = {
            "vault_engine.php",
            "email_template.php",
            "vault_icon_cache.php",
            "VaultKdfPolicy.php",
        }
        assert set(embedded_manifest["runtime_files"]) == expected_runtime
        for required in expected_runtime:
            assert f"runtime/{required}" in names, f"missing runtime file: {required}"

        manifest_entries = {entry["path"]: entry for entry in embedded_manifest["files"]}
        assert set(manifest_entries) == names - {"update-manifest.json"}, (
            "manifest inventory does not exactly cover packaged files"
        )
        for path, entry in manifest_entries.items():
            data = archive.read(path)
            assert entry["size"] == len(data), f"size mismatch: {path}"
            assert entry["sha256"] == sha256(data), f"digest mismatch: {path}"

    print(f"Release package validation passed: {package.name}")


if __name__ == "__main__":
    main()
