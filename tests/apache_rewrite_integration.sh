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

expect_not_success() {
  local path="$1"
  local actual
  actual="$(curl --path-as-is --silent --show-error --output /dev/null --write-out '%{http_code}' "${base}${path}")"
  if [[ "$actual" =~ ^2 ]]; then
    printf 'Expected a non-success response for protected encoded path %s, received %s\n' "$path" "$actual" >&2
    exit 1
  fi
  printf 'HTTP %s %s (non-success as required)\n' "$actual" "$path"
}

# Protected source/configuration trees must not be retrievable directly.
expect_status "/app/Security/SecurityBootstrap.php" 403
expect_status "/app?probe=1" 403
expect_status "/docs?probe=1" 403
expect_status "/docs/operations/backup-restore-runbook.md" 403
expect_status "/.github/workflows/gallery-security.yml" 403
expect_status "/.git/HEAD" 403

# Encoded path spellings must not bypass source-directory denial.
expect_not_success "/%61pp/Security/SecurityBootstrap.php"
expect_not_success "/app%2fSecurity%2fSecurityBootstrap.php"
expect_not_success "/.%67it/HEAD"

# Static browser assets must be directly readable with their real URLs.
expect_status "/assets/css/sentryiq.css" 200
expect_status "/assets/js/vault_folders.js" 200
expect_status "/assets/js/vault_page.js" 200
expect_status "/assets/js/vault_page_init.js" 200
expect_status "/assets/js/records_view.js" 200
expect_status "/assets/js/safari.js" 200
expect_status "/assets/images/sentryiq-logo-wide.webp" 200
expect_status "/assets/images/sentryiq-icon.png" 200

# Preserve the legacy stylesheet alias through its internal rewrite.
expect_status "/pm_style.css" 200
