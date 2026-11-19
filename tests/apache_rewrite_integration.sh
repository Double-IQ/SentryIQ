#!/usr/bin/env bash
set -euo pipefail

base="${SENTRYIQ_APACHE_TEST_BASE_URL:-http://127.0.0.1}"
expect_status() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${base}${path}")"
  if [[ "$actual" != "$expected" ]]; then
    printf 'Expected HTTP %s for %s, received %s\n' "$expected" "$path" "$actual" >&2
    exit 1
  fi
  printf 'HTTP %s %s\n' "$actual" "$path"
}

# Protected source/configuration trees must not be retrievable directly.
expect_status "/app/Security/SecurityBootstrap.php" 403
expect_status "/app?probe=1" 403
expect_status "/docs/operations/backup-restore-runbook.md" 403
expect_status "/.github/workflows/gallery-security.yml" 403
expect_status "/.git/HEAD" 403

# Confirm the target asset is directly readable, then test the legacy rewrite.
expect_status "/assets/css/sentryiq.css" 200
expect_status "/pm_style.css" 200
