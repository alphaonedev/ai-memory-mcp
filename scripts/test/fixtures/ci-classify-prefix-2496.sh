# FROZEN HISTORICAL ARTEFACT — DO NOT "FIX" THIS FILE.
#
# This is the `classify` step's shell block from `.github/workflows/ci.yml`
# EXACTLY as it stood at release/v1.0.0 tip 789f1f66, immediately before the
# #2494/#2496 atomic fix. It is the single-base classifier: `docs_only` is
# computed against `$PR_BEFORE` (the previous PR head) on `synchronize`, and an
# empty diff classifies docs-only.
#
# `scripts/test/test-ci-classify-base.sh` executes it to prove the defect is
# real and that the test detects it: fixture scenario 1 (code earlier in the PR,
# docs-only last push — the PR #2031 / PR #2497 shape) MUST yield
# `docs_only=true` here and `docs_only=false` against the live workflow. If this
# file were repaired, that regression leg would pass vacuously and the test
# would stop being load-bearing.
#
# Recovered with:
#   git show 789f1f66:.github/workflows/ci.yml \
#     | awk '/^      - id: cls$/{s=1;next} s&&/^        run: \|$/{r=1;next} r{if($0==""){print"";next} if($0~/^          /){print substr($0,11);next} exit}'
# For test-impact selection we want the SMALLEST defensible
# diff base — i.e. the previous head, not the merge base —
# so per-push impact selection stays effective.
# Event-by-event base resolution:
#   - push: $EVENT_BEFORE = previous branch tip (small)
#   - pull_request synchronize: $PR_BEFORE = previous PR head
#     (small — only the just-pushed commits) when present;
#     fall back to $PR_BASE_SHA (main tip) for opened /
#     reopened where $PR_BEFORE is absent.
if [ "$EVENT_NAME" = "pull_request" ]; then
  if [ -n "$PR_BEFORE" ] && [ "$PR_BEFORE" != "0000000000000000000000000000000000000000" ] && [ "$PR_ACTION" = "synchronize" ]; then
    base="$PR_BEFORE"
  else
    base="$PR_BASE_SHA"
  fi
elif [ "$EVENT_NAME" = "push" ]; then
  base="$PR_BEFORE"
else
  base=""
fi
if [ -z "$base" ] || [ "$base" = "0000000000000000000000000000000000000000" ] || ! git rev-parse "$base" >/dev/null 2>&1; then
  echo "docs_only=false" >> "$GITHUB_OUTPUT"
  echo "test_impact=__ALL__" >> "$GITHUB_OUTPUT"
  echo "test_impact_count=ALL" >> "$GITHUB_OUTPUT"
  echo "test_impact_total=ALL" >> "$GITHUB_OUTPUT"
  echo "test_impact_reason=base-unreachable" >> "$GITHUB_OUTPUT"
  echo "::notice::cannot resolve base commit ($base) — running full pipeline"
  exit 0
fi
# Per issue #1193 PR #1203 — `fetch-depth: 2` is too shallow
# when the PR base SHA is more than 1 commit behind the
# PR-merge ref; `git rev-parse $base` returns the SHA from
# GitHub's pull/N/merge representation but the tree itself
# isn't downloaded, so `git diff $base HEAD` fails with
# `fatal: bad object`. Fetch the base commit on demand
# before the diff. This is a no-op when fetch-depth was
# already deep enough.
if ! git cat-file -e "$base^{tree}" 2>/dev/null; then
  git fetch --depth=50 origin "$base" 2>/dev/null || \
    git fetch --depth=200 origin "$base" 2>/dev/null || \
    git fetch --unshallow origin 2>/dev/null || true
fi
if ! git cat-file -e "$base^{tree}" 2>/dev/null; then
  echo "docs_only=false" >> "$GITHUB_OUTPUT"
  echo "test_impact=__ALL__" >> "$GITHUB_OUTPUT"
  echo "test_impact_count=ALL" >> "$GITHUB_OUTPUT"
  echo "test_impact_total=ALL" >> "$GITHUB_OUTPUT"
  echo "test_impact_reason=base-fetch-failed" >> "$GITHUB_OUTPUT"
  echo "::notice::cannot fetch base tree ($base) after retry — running full pipeline"
  exit 0
fi
changed=$(git diff --name-only "$base" HEAD)
if [ -z "$changed" ]; then
  echo "docs_only=true" >> "$GITHUB_OUTPUT"
  echo "test_impact=__SKIP__" >> "$GITHUB_OUTPUT"
  echo "test_impact_count=0" >> "$GITHUB_OUTPUT"
  echo "test_impact_total=0" >> "$GITHUB_OUTPUT"
  echo "test_impact_reason=empty-diff" >> "$GITHUB_OUTPUT"
  echo "::notice::no diff vs base — treating as docs-only no-op"
  exit 0
fi
# docs-only iff every changed file matches docs/** OR *.md anywhere
if echo "$changed" | grep -qvE '^(docs/|.*\.md$)'; then
  echo "docs_only=false" >> "$GITHUB_OUTPUT"
  echo "::notice::code changes detected — running full pipeline"
else
  echo "docs_only=true" >> "$GITHUB_OUTPUT"
  echo "::notice::docs-only diff — skipping Rust pipeline"
fi
echo "--- Changed files ($(echo "$changed" | wc -l) files) ---"
echo "$changed"

# v0.7.0 Task #12 (#1399) — compute test-impact set.
# Always runs; the consumer steps decide whether to honor
# the output based on docs_only. The script is self-contained
# POSIX-compatible bash; full discipline + foundational list
# documented inline in scripts/ci-test-impact.sh.
chmod +x scripts/ci-test-impact.sh
scripts/ci-test-impact.sh "$base" "HEAD"

