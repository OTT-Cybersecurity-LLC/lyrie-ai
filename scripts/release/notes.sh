#!/usr/bin/env bash
# Generate release notes for the current tag against the previous tag.
# Usage: scripts/release/notes.sh [vX.Y.Z]
set -euo pipefail

CURRENT="${1:-$(git describe --tags --abbrev=0 2>/dev/null || true)}"
if [[ -z "${CURRENT}" ]]; then
  echo "No tags found and no tag passed."
  exit 1
fi

PREVIOUS="$(git describe --tags --abbrev=0 "${CURRENT}^" 2>/dev/null || true)"

echo "# Lyrie Agent ${CURRENT}"
echo
if [[ -n "${PREVIOUS}" ]]; then
  echo "_Changes since ${PREVIOUS}_"
else
  echo "_Initial release_"
fi
echo

echo "## Highlights"
echo
git log --pretty=format:'- %s (%h)' "${PREVIOUS:+${PREVIOUS}..}${CURRENT}" \
  | grep -E '^- (feat|fix|perf|security|docs)' || true
echo

echo "## All changes"
echo
git log --pretty=format:'- %s (%h)' "${PREVIOUS:+${PREVIOUS}..}${CURRENT}"
echo

echo "## Contributors"
echo
git shortlog -sne "${PREVIOUS:+${PREVIOUS}..}${CURRENT}" | sed 's/^/- /'
