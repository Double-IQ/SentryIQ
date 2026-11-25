#!/usr/bin/env python3
"""Require immutable full-commit references for every GitHub Actions dependency."""
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1]
workflow_dir = root / ".github" / "workflows"
uses_pattern = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
pinned_pattern = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$")
errors = []
checked = 0

for workflow in sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml")):
    content = workflow.read_text(encoding="utf-8")
    for reference in uses_pattern.findall(content):
        checked += 1
        if not pinned_pattern.fullmatch(reference):
            errors.append(f"{workflow.relative_to(root)}: mutable or invalid action reference: {reference}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)

print(f"All {checked} GitHub Actions dependencies use immutable 40-character commit SHAs.")
