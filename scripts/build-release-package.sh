#!/usr/bin/env bash
# Build the exact SentryIQ release archive and its canonical inventory manifest.
# Usage: build-release-package.sh VERSION COMMIT_SHA REPOSITORY REPOSITORY_ID WORKFLOW_PATH SOURCE_REF OUTPUT_DIR
set -euo pipefail

if [[ "$#" -ne 7 ]]; then
  echo "usage: $0 VERSION COMMIT_SHA REPOSITORY REPOSITORY_ID WORKFLOW_PATH SOURCE_REF OUTPUT_DIR" >&2
  exit 2
fi

VERSION="$1"
COMMIT_SHA="$2"
REPOSITORY="$3"
REPOSITORY_ID="$4"
WORKFLOW_PATH="$5"
SOURCE_REF="$6"
OUTPUT_DIR="$7"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid stable release version: $VERSION" >&2
  exit 2
fi
if [[ ! "$COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "commit SHA must be 40 lowercase hexadecimal characters" >&2
  exit 2
fi
if [[ -z "$REPOSITORY" || -z "$REPOSITORY_ID" || -z "$WORKFLOW_PATH" || -z "$SOURCE_REF" ]]; then
  echo "repository, repository ID, workflow path, and source ref are required" >&2
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel)"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PACKAGE="sentryiq-${VERSION}.zip"
RELEASE_ROOT="$WORK/release-root"
mkdir -p "$RELEASE_ROOT"

git -C "$ROOT" archive --format=tar "$SOURCE_REF" | tar -xf - -C "$RELEASE_ROOT"
mkdir -p "$RELEASE_ROOT/runtime"
for name in vault_engine.php email_template.php vault_icon_cache.php VaultKdfPolicy.php; do
  if [[ ! -f "$RELEASE_ROOT/private_data/$name" ]]; then
    echo "required runtime template missing from source archive: $name" >&2
    exit 1
  fi
  cp "$RELEASE_ROOT/private_data/$name" "$RELEASE_ROOT/runtime/$name"
done
rm -rf "$RELEASE_ROOT/private_data" "$RELEASE_ROOT/.git" "$RELEASE_ROOT/.github"

python3 "$ROOT/scripts/build-release-manifest.py" \
  --root "$RELEASE_ROOT" \
  --version "$VERSION" \
  --commit "$COMMIT_SHA" \
  --repository "$REPOSITORY" \
  --repository-id "$REPOSITORY_ID" \
  --workflow-path "$WORKFLOW_PATH" \
  --output "$RELEASE_ROOT/update-manifest.json"

cp "$RELEASE_ROOT/update-manifest.json" "$OUTPUT_DIR/release-manifest.json"
(
  cd "$RELEASE_ROOT"
  zip -qr "$OUTPUT_DIR/$PACKAGE" .
)
(
  cd "$OUTPUT_DIR"
  sha256sum "$PACKAGE" > "$PACKAGE.sha256"
  sha256sum "release-manifest.json" > "release-manifest.json.sha256"
)
echo "Built $OUTPUT_DIR/$PACKAGE"
