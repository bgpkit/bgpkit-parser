#!/usr/bin/env bash
# Query Codecov API v2 for per-line missing coverage in a PR.
# Usage: ./scripts/coverage-misses.sh [PR_NUMBER]
#   PR_NUMBER defaults to the value of GITHUB_PR_NUMBER env var.
set -euo pipefail

PR_NUMBER="${1:-${GITHUB_PR_NUMBER:-}}"
if [ -z "$PR_NUMBER" ]; then
  echo "Usage: $0 <PR_NUMBER>" >&2
  exit 1
fi

OWNER="bgpkit"
REPO="bgpkit-parser"
API_BASE="https://api.codecov.io/api/v2/github/${OWNER}/repos/${REPO}"

# -------------------------------------------------------------------
# 1. Fetch impacted files for this PR
# -------------------------------------------------------------------
echo "▶ Fetching impacted files for PR #${PR_NUMBER}..."
IMPACTED=$(curl -sf "${API_BASE}/compare/impacted_files?pullid=${PR_NUMBER}")
STATE=$(echo "$IMPACTED" | jq -r '.state')

if [ "$STATE" != "processed" ]; then
  echo "⚠️  Codecov comparison state is '$STATE' (not yet processed). Retry in ~30s."
  exit 2
fi

# -------------------------------------------------------------------
# 2. Collect files with misses
# -------------------------------------------------------------------
echo "▶ Extracting files with uncovered lines..."
FILES_WITH_MISSES=$(echo "$IMPACTED" | jq -r '
  .files[]
  | select(.patch_coverage != null and .misses_count > 0)
  | [.head_name, (.patch_coverage.misses|tostring), (.patch_coverage.coverage*100|floor/100|tostring)]
  | @tsv
')

if [ -z "$FILES_WITH_MISSES" ]; then
  echo "✅ No files with uncovered lines in this PR."
  exit 0
fi

# -------------------------------------------------------------------
# 3. For each file, get line-level segments from Codecov API
# -------------------------------------------------------------------
echo "▶ Fetching line-level detail for each file..."
echo ""

FIRST=1
while IFS=$'\t' read -r file_name misses coverage_pct; do
  # URL-encode the path
  ENCODED_PATH=$(echo -n "$file_name" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))")

  SEGMENTS_JSON=$(curl -sf "${API_BASE}/compare/segments/${ENCODED_PATH}?pullid=${PR_NUMBER}")
  # Only count NEW lines that are uncovered (base_coverage is null → new line)
  MISS_LINES=$(echo "$SEGMENTS_JSON" | jq -r '
    [.segments[].lines[]
      | select(.head_coverage == 1 and .base_coverage == null)
      | .head_number]
    | sort | unique | join(", ")
  ')
  LINE_COUNT=$(echo "$SEGMENTS_JSON" | jq -r '[.segments[].lines[] | select(.head_coverage == 1 and .base_coverage == null)] | length')
  ALL_UNCOVERED=$(echo "$SEGMENTS_JSON" | jq -r '[.segments[].lines[] | select(.head_coverage == 1)] | length')

  # Spacer between files
  if [ "$FIRST" -eq 1 ]; then
    FIRST=0
  else
    echo ""
  fi

  echo "📄 $file_name"
  if [ "$LINE_COUNT" -ne "$ALL_UNCOVERED" ]; then
    EXTRA="  ($((ALL_UNCOVERED - LINE_COUNT)) pre-existing uncovered)"
  else
    EXTRA=""
  fi
  echo "   Coverage: ${coverage_pct}%  |  Patch misses: ${LINE_COUNT} lines${EXTRA}"
  echo "   Uncovered lines: ${MISS_LINES}"
done <<< "$FILES_WITH_MISSES"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
TOTAL_MISSES=$(echo "$IMPACTED" | jq -r '.totals.patch.misses')
TOTAL_HITS=$(echo "$IMPACTED" | jq -r '.totals.patch.hits')
echo "Total patch: ${TOTAL_HITS} hit / ${TOTAL_MISSES} miss ($(echo "scale=1; ${TOTAL_HITS}*100/(${TOTAL_HITS}+${TOTAL_MISSES})" | bc)% coverage)"
