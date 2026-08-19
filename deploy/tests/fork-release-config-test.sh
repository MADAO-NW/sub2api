#!/bin/bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORKFLOW="$ROOT_DIR/.github/workflows/release.yml"
GORELEASER="$ROOT_DIR/.goreleaser.yaml"
GORELEASER_SIMPLE="$ROOT_DIR/.goreleaser.simple.yaml"
INSTALLER="$ROOT_DIR/deploy/install.sh"

grep -Fq 'RELEASE_BRANCH: release/madao' "$WORKFLOW"
grep -Fq 'UPDATE_REPOSITORY: ${{ github.repository }}' "$WORKFLOW"
grep -Fq 'UPDATE_CHANNEL: madao' "$WORKFLOW"
grep -Fq 'SIMPLE_RELEASE: false' "$WORKFLOW"
grep -Fq 'ref: ${{ env.RELEASE_BRANCH }}' "$WORKFLOW"
grep -Fq 'git push origin "HEAD:${RELEASE_BRANCH}"' "$WORKFLOW"

if grep -Fq 'simple_release:' "$WORKFLOW"; then
    echo "madao releases must always include binary update artifacts" >&2
    exit 1
fi
if grep -Fq 'ref: ${{ github.event.repository.default_branch }}' "$WORKFLOW"; then
    echo "release workflow must not write VERSION to the upstream mirror branch" >&2
    exit 1
fi

for config in "$GORELEASER" "$GORELEASER_SIMPLE"; do
    grep -Fq -- '-X main.UpdateRepository={{ .Env.UPDATE_REPOSITORY }}' "$config"
    grep -Fq -- '-X main.UpdateChannel={{ .Env.UPDATE_CHANNEL }}' "$config"
done

grep -Fq 'GITHUB_REPO="MADAO-NW/sub2api"' "$INSTALLER"
grep -Fq 'UPDATE_CHANNEL="madao"' "$INSTALLER"
grep -Fq 'raw.githubusercontent.com/MADAO-NW/sub2api/release/madao/deploy/install.sh' \
    "$ROOT_DIR/README.md"
grep -Fq 'raw.githubusercontent.com/MADAO-NW/sub2api/release/madao/deploy/install.sh' \
    "$ROOT_DIR/README_CN.md"
grep -Fq 'raw.githubusercontent.com/MADAO-NW/sub2api/release/madao/deploy/install.sh' \
    "$ROOT_DIR/README_JA.md"
grep -Fq 'raw.githubusercontent.com/MADAO-NW/sub2api/release/madao/deploy/install.sh' \
    "$ROOT_DIR/deploy/README.md"

echo "fork release configuration checks passed"
