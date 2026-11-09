#!/usr/bin/env python3
"""Build a deterministic inventory manifest for a SentryIQ release package.

This manifest is descriptive integrity metadata, not a release signature.
Trust must come from independently verified GitHub provenance until a separate
release-signing key and custody policy are approved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path, version: str, commit: str, repository: str,
                   repository_id: str, workflow_path: str) -> dict:
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("invalid release version")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be a 40-character lowercase SHA")
    if not repository or not repository_id or not workflow_path:
        raise ValueError("repository, repository_id and workflow_path are required")

    entries = []
    public_files = []
    runtime_files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symbolic links are not permitted: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == "update-manifest.json":
            continue
        data = {"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)}
        entries.append(data)
        if relative.startswith("runtime/"):
            runtime_files.append(relative.removeprefix("runtime/"))
        else:
            public_files.append(relative)

    if not public_files or not runtime_files:
        raise ValueError("release must contain public and runtime files")

    return {
        "format": 2,
        "repository": repository,
        "repository_id": str(repository_id),
        "version": version,
        "commit": commit,
        "workflow_path": workflow_path,
        "public_files": public_files,
        "runtime_files": runtime_files,
        "files": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    if not root.is_dir():
        parser.error("--root must be an existing directory")
    try:
        manifest = build_manifest(root, args.version, args.commit,
                                  args.repository, args.repository_id,
                                  args.workflow_path)
    except (OSError, ValueError) as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        return 1

    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    args.output.write_text(encoded, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
