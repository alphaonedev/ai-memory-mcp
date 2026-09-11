#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# test-release-hardening.sh — fixture proof for the #3546 release controls.
#
# release.yml is workflow_dispatch-only and publishes to crates.io, GHCR,
# Homebrew and COPR, so its controls cannot be proven by "run a release and
# see". This harness proves each one refuses what it exists to refuse, using
# throwaway git repositories, canned GitHub API responses and PATH shims:
#
#   A  structure   check-release-workflow.py passes on the live release.yml
#                  and FAILS on the frozen pre-#3546 copy (R-203).
#   B  tag         the preflight "Verify the tag" block, EXTRACTED VERBATIM
#                  from release.yml, accepts an enrolled SSH-signed tag and
#                  refuses a lightweight tag, an unsigned tag, a foreign-key
#                  tag, a signed tag object re-pointed under another name and
#                  an empty allowlist. R-203: the frozen pre-fix preflight
#                  block ACCEPTS the lightweight tag.
#   C  moved tag   the extracted "Re-assert the release tag has not moved"
#                  block passes on an unmoved tag and refuses a tag that was
#                  re-signed onto another commit or deleted after preflight.
#   D  qualify     qualify-sha.py over canned check-runs: missing, skipped-only,
#                  in-progress, failed-latest-attempt, foreign-app spoof and
#                  non-gating-workflow spoof all refuse; skipped-plus-success
#                  and failed-then-rerun-success pass; a required context on
#                  page two is found through a stub `gh`, and a failed page
#                  read refuses.
#   E  ruleset     assert-tag-ruleset.sh accepts only an ACTIVE tag ruleset on
#                  refs/tags/v* carrying both update and deletion rules.
#   F  nfpm        the extracted "Build deb and rpm packages" block refuses an
#                  altered nfpm tarball BEFORE tar runs. R-203: the frozen
#                  pre-fix block pipes the altered bytes straight into tar.
#
# Scratch lives under .local-runs/ (never mktemp -d / system /tmp).
# Exit codes: 0 all cases behave · 1 a case misbehaved.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIVE_YML="$REPO_ROOT/.github/workflows/release.yml"
FROZEN_YML="$REPO_ROOT/scripts/test/fixtures/release-yml-prefix-3546.yml"
T="$REPO_ROOT/.local-runs/test-release-hardening.$$"
mkdir -p "$T"
# shellcheck disable=SC2064
trap "rm -rf '$T'" EXIT

failures=0
pass() { echo "  ok    $*"; }
fail() { echo "  FAIL  $*" >&2; failures=$((failures + 1)); }

# expect_rc NAME WANT(0|nonzero) RC OUTFILE [NEEDLE]
expect_rc() {
  local name="$1" want="$2" rc="$3" out="$4" needle="${5:-}"
  if [ "$want" = 0 ] && [ "$rc" -ne 0 ]; then
    fail "$name: expected success, got rc=$rc: $(tail -3 "$out" | tr '\n' ' ')"
    return
  fi
  if [ "$want" = nonzero ] && [ "$rc" -eq 0 ]; then
    fail "$name: expected a refusal, got rc=0"
    return
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" "$out"; then
    fail "$name: output lacks '$needle': $(tail -3 "$out" | tr '\n' ' ')"
    return
  fi
  pass "$name"
}

# extract_run FILE STEP_NAME — the verbatim `run: |` body of the first step
# with that exact name, de-indented. Fails loudly if the step is missing so a
# renamed step can never make the harness test nothing.
extract_run() {
  local file="$1" name="$2" body
  body="$(awk -v want="      - name: $name" '
    $0 == want { instep = 1; next }
    instep && /^      - / { exit }
    instep && /^        run: \|$/ { inrun = 1; next }
    inrun {
      if ($0 == "") { print ""; next }
      if ($0 ~ /^          /) { print substr($0, 11); next }
      exit
    }
  ' "$file")"
  if [ -z "$body" ]; then
    echo "extract_run: no run block for step '$name' in $file" >&2
    exit 1
  fi
  printf '%s\n' "$body"
}

# ---------------------------------------------------------------------------
echo "A  structure"
out="$T/a.out"
if python3 "$REPO_ROOT/scripts/release/check-release-workflow.py" \
  --workflow "$LIVE_YML" \
  --republish "$REPO_ROOT/.github/workflows/mobile-ios-republish.yml" \
  --signers "$REPO_ROOT/scripts/qc-allowlists/release-tag-signers.txt" \
  --enrolled "$REPO_ROOT/scripts/qc-allowlists/enrolled-commit-signers.txt" >"$out" 2>&1; then
  pass "live release.yml satisfies R1-R10"
else
  fail "live release.yml: $(cat "$out")"
fi
out="$T/a-frozen.out"
set +e
python3 "$REPO_ROOT/scripts/release/check-release-workflow.py" --workflow "$FROZEN_YML" >"$out" 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  fail "R-203: the frozen pre-#3546 release.yml passed the structural check (the check is vacuous)"
else
  missing=""
  for rule in R1: R2: R3: R5: R6: R7: R8: R9:; do
    grep -q "VIOLATION $rule" "$out" || missing="$missing $rule"
  done
  if [ -n "$missing" ]; then
    fail "R-203: frozen release.yml did not trip:$missing"
  else
    pass "R-203: frozen pre-#3546 release.yml trips R1 R2 R3 R5 R6 R7 R8 R9"
  fi
fi

# ---------------------------------------------------------------------------
echo "B  tag verification (extracted preflight block)"
ssh-keygen -q -t ed25519 -N '' -f "$T/op" -C op
ssh-keygen -q -t ed25519 -N '' -f "$T/rogue" -C rogue

git init -q --bare "$T/remote.git"
author="$T/author"
git init -q -b main "$author"
(
  cd "$author"
  git config user.name Operator
  git config user.email op@example.test
  git config gpg.format ssh
  git config user.signingkey "$T/op.pub"
  git config commit.gpgsign false
  git config tag.gpgsign false
  echo one >f && git add f && git commit -q -m one
  git tag -s v1.0.0 -m "signed release"
  git tag v1.0.1
  git tag -a v1.0.2 -m "annotated, unsigned"
  git -c user.signingkey="$T/rogue.pub" tag -s v1.0.3 -m "foreign key"
  git update-ref refs/tags/v1.0.9 "$(git rev-parse refs/tags/v1.0.0)"
  git remote add origin "$T/remote.git"
  git push -q origin main --tags
)

# The trusted tooling checkout: the live scripts plus an allowlist holding
# only the fixture's operator key, at the path release.yml passes.
trusted="$T/trusted"
git clone -q "$T/remote.git" "$trusted" 2>/dev/null
mkdir -p "$trusted/scripts/release" "$trusted/scripts/qc-allowlists"
cp "$REPO_ROOT/scripts/release/"*.sh "$trusted/scripts/release/"
printf 'op@example.test %s\n' "$(cut -d' ' -f1,2 "$T/op.pub")" >"$trusted/scripts/qc-allowlists/release-tag-signers.txt"

extract_run "$LIVE_YML" "Verify the tag (annotated, SSH-signed by an enrolled release key)" >"$T/verify.sh"

run_verify() { # TAG OUT -> rc
  local tag="$1" out="$2"
  : >"$T/gh_output"
  set +e
  (cd "$trusted" && TAG="$tag" GITHUB_OUTPUT="$T/gh_output" bash "$T/verify.sh") >"$out" 2>&1
  local rc=$?
  set -e
  return $rc
}

run_verify v1.0.0 "$T/b1.out" && rc=0 || rc=$?
expect_rc "enrolled SSH-signed annotated tag is accepted" 0 "$rc" "$T/b1.out" "verify-tag: OK"
want_sha="$(git -C "$author" rev-parse 'v1.0.0^{commit}')"
want_obj="$(git -C "$author" rev-parse v1.0.0)"
if grep -qx "sha=$want_sha" "$T/gh_output" && grep -qx "tag_object=$want_obj" "$T/gh_output"; then
  pass "preflight exports the verified sha and tag object"
else
  fail "preflight outputs wrong: $(tr '\n' ' ' <"$T/gh_output")"
fi
run_verify v1.0.1 "$T/b2.out" && rc=0 || rc=$?
expect_rc "lightweight tag is refused" nonzero "$rc" "$T/b2.out" "lightweight tag"
run_verify v1.0.2 "$T/b3.out" && rc=0 || rc=$?
expect_rc "annotated but unsigned tag is refused" nonzero "$rc" "$T/b3.out" "no SSH signature"
run_verify v1.0.3 "$T/b4.out" && rc=0 || rc=$?
expect_rc "tag signed by a key not in the allowlist is refused" nonzero "$rc" "$T/b4.out" "does not verify"
run_verify v1.0.9 "$T/b5.out" && rc=0 || rc=$?
expect_rc "signed tag object re-pointed under another name is refused" nonzero "$rc" "$T/b5.out" "names itself"

set +e
bash "$REPO_ROOT/scripts/release/verify-tag.sh" --repo "$trusted" --tag 'v1.0' \
  --signers "$trusted/scripts/qc-allowlists/release-tag-signers.txt" >"$T/b6.out" 2>&1
rc=$?
printf '# no keys\n' >"$T/empty-signers"
bash "$REPO_ROOT/scripts/release/verify-tag.sh" --repo "$trusted" --tag v1.0.0 \
  --signers "$T/empty-signers" >"$T/b7.out" 2>&1
rc7=$?
set -e
expect_rc "non-SemVer tag name is refused" nonzero "$rc" "$T/b6.out" "does not match SemVer"
expect_rc "an allowlist with no keys refuses everything" nonzero "$rc7" "$T/b7.out" "zero enrolled keys"

# R-203: the frozen pre-fix preflight accepts the lightweight tag.
extract_run "$FROZEN_YML" "Resolve tag + sha + prerelease flag" >"$T/old-preflight.sh"
: >"$T/gh_output"
set +e
(cd "$trusted" && git fetch -q origin 'refs/tags/*:refs/tags/*' &&
  TAG=v1.0.1 GITHUB_OUTPUT="$T/gh_output" bash "$T/old-preflight.sh") >"$T/b8.out" 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  pass "R-203: the frozen pre-#3546 preflight ACCEPTS a lightweight tag"
else
  fail "R-203: the frozen preflight refused the lightweight tag (fixture no longer reproduces the defect): $(cat "$T/b8.out")"
fi

# ---------------------------------------------------------------------------
echo "C  moved tag (extracted re-assert block)"
extract_run "$LIVE_YML" "Re-assert the release tag has not moved (#3546)" >"$T/reassert.sh"
run_reassert() { # OUT -> rc
  set +e
  (cd "$trusted" && REMOTE="$T/remote.git" TAG=v1.0.0 TAG_OBJECT="$want_obj" SHA="$want_sha" \
    bash "$T/reassert.sh") >"$1" 2>&1
  local rc=$?
  set -e
  return $rc
}
run_reassert "$T/c1.out" && rc=0 || rc=$?
expect_rc "an unmoved tag passes the re-assert" 0 "$rc" "$T/c1.out" "assert-tag-unmoved: OK"
(
  cd "$author"
  echo two >f && git commit -q -am two
  git tag -f -s v1.0.0 -m "re-signed onto another commit" >/dev/null
  git push -q -f origin refs/tags/v1.0.0
)
run_reassert "$T/c2.out" && rc=0 || rc=$?
expect_rc "a tag re-signed onto another commit after preflight is refused" nonzero "$rc" "$T/c2.out" "the tag moved after verification"
git -C "$author" push -q origin :refs/tags/v1.0.0
run_reassert "$T/c3.out" && rc=0 || rc=$?
expect_rc "a tag deleted after preflight is refused" nonzero "$rc" "$T/c3.out" "no longer exists"

# ---------------------------------------------------------------------------
echo "D  qualify"
SHA_Q=1111111111111111111111111111111111111111
printf '%s\n' '# fixture mirror' 'Ctx A' 'Ctx B' >"$T/contexts"
python3 - "$T" "$SHA_Q" <<'PY'
import json, sys, os
t, sha = sys.argv[1], sys.argv[2]
APP = {"slug": "github-actions", "id": 15368}
def run(suite, path, event="push"):
    return {"id": suite * 10, "check_suite_id": suite, "path": f".github/workflows/{path}", "event": event, "head_sha": sha}
def cr(name, suite, conclusion, started="2026-09-11T10:00:00Z", status="completed", app=APP, cid=None):
    return {"id": cid or hash((name, suite, started)) & 0xffffff, "name": name, "head_sha": sha, "status": status,
            "conclusion": conclusion if status == "completed" else None, "started_at": started,
            "app": app, "check_suite": {"id": suite}}
cases = {
  "pass":           ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "success")], [run(1, "ci.yml")]),
  "missing":        ([cr("Ctx A", 1, "success")], [run(1, "ci.yml")]),
  "skipped_only":   ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "skipped")], [run(1, "ci.yml")]),
  "skip_plus_ok":   ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "skipped"), cr("Ctx B", 2, "success")],
                     [run(1, "ci.yml"), run(2, "ci.yml", "pull_request")]),
  "rerun_failed":   ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "success", "2026-09-11T10:00:00Z"),
                      cr("Ctx B", 1, "failure", "2026-09-11T11:00:00Z")], [run(1, "ci.yml")]),
  "rerun_fixed":    ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "failure", "2026-09-11T10:00:00Z"),
                      cr("Ctx B", 1, "success", "2026-09-11T11:00:00Z")], [run(1, "ci.yml")]),
  "other_run_fail": ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "success"), cr("Ctx B", 2, "failure")],
                     [run(1, "ci.yml"), run(2, "ci.yml", "pull_request")]),
  "in_progress":    ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, None, status="in_progress")], [run(1, "ci.yml")]),
  "foreign_app":    ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "success", app={"slug": "evil-app", "id": 1})],
                     [run(1, "ci.yml")]),
  "wrong_carrier":  ([cr("Ctx A", 1, "success"), cr("Ctx B", 3, "success")], [run(1, "ci.yml"), run(3, "evil.yml")]),
}
for name, (crs, runs) in cases.items():
    with open(os.path.join(t, f"q-{name}-cr.json"), "w") as fh:
        json.dump({"total_count": len(crs), "check_runs": crs}, fh)
    with open(os.path.join(t, f"q-{name}-wr.json"), "w") as fh:
        json.dump({"total_count": len(runs), "workflow_runs": runs}, fh)
# Pagination fixture: page 1 is 100 unrelated check-runs, page 2 carries both contexts.
filler = [cr(f"Other {i}", 1, "success", cid=100000 + i) for i in range(100)]
with open(os.path.join(t, "page-check-runs-1.json"), "w") as fh:
    json.dump({"total_count": 102, "check_runs": filler}, fh)
with open(os.path.join(t, "page-check-runs-2.json"), "w") as fh:
    json.dump({"total_count": 102, "check_runs": [cr("Ctx A", 1, "success"), cr("Ctx B", 1, "success")]}, fh)
with open(os.path.join(t, "page-runs-1.json"), "w") as fh:
    json.dump({"total_count": 1, "workflow_runs": [run(1, "ci.yml")]}, fh)
PY

q() { # CASE OUT -> rc
  set +e
  python3 "$REPO_ROOT/scripts/release/qualify-sha.py" --sha "$SHA_Q" --contexts "$T/contexts" --carriers ci.yml \
    --check-runs "$T/q-$1-cr.json" --workflow-runs "$T/q-$1-wr.json" >"$2" 2>&1
  local rc=$?
  set -e
  return $rc
}
q pass "$T/d.out" && rc=0 || rc=$?;           expect_rc "every context succeeded: qualified" 0 "$rc" "$T/d.out" "qualify-sha: OK"
q missing "$T/d.out" && rc=0 || rc=$?;        expect_rc "a context with no check-run refuses" nonzero "$rc" "$T/d.out" "no check-run"
q skipped_only "$T/d.out" && rc=0 || rc=$?;   expect_rc "a skipped-only context refuses" nonzero "$rc" "$T/d.out" "never ran to success"
q skip_plus_ok "$T/d.out" && rc=0 || rc=$?;   expect_rc "a skipped run does not veto a success from another run" 0 "$rc" "$T/d.out" "qualify-sha: OK"
q rerun_failed "$T/d.out" && rc=0 || rc=$?;   expect_rc "a re-run that failed is not masked by the earlier success" nonzero "$rc" "$T/d.out" "failure"
q rerun_fixed "$T/d.out" && rc=0 || rc=$?;    expect_rc "a re-run that succeeded supersedes the earlier failure" 0 "$rc" "$T/d.out" "qualify-sha: OK"
q other_run_fail "$T/d.out" && rc=0 || rc=$?; expect_rc "a failure in another run vetoes" nonzero "$rc" "$T/d.out" "failure"
q in_progress "$T/d.out" && rc=0 || rc=$?;    expect_rc "an in-progress context refuses" nonzero "$rc" "$T/d.out" "incomplete:in_progress"
q foreign_app "$T/d.out" && rc=0 || rc=$?;    expect_rc "a same-named check-run from another app is not counted" nonzero "$rc" "$T/d.out" "no check-run"
q wrong_carrier "$T/d.out" && rc=0 || rc=$?;  expect_rc "a same-named check-run from a non-gating workflow is not counted" nonzero "$rc" "$T/d.out" "no check-run"

# --fetch through a stub `gh`: explicit pagination, and a failed page read.
mkdir -p "$T/bin"
cat >"$T/bin/gh" <<'STUB'
#!/usr/bin/env bash
# stub gh: serve canned pages; log every URL.
url="$2"
echo "$url" >>"$STUB_LOG"
page="$(printf '%s' "$url" | sed -n 's/.*[?&]page=\([0-9]*\).*/\1/p')"
case "$url" in
  */check-runs*) kind=check-runs ;;
  */actions/runs*) kind=runs ;;
  *) exit 9 ;;
esac
if [ -n "${STUB_FAIL_PAGE:-}" ] && [ "$kind" = check-runs ] && [ "$page" = "$STUB_FAIL_PAGE" ]; then
  echo "HTTP 502" >&2; exit 1
fi
f="$STUB_DIR/page-$kind-$page.json"
if [ -f "$f" ]; then cat "$f"; else echo '{"total_count":0,"check_runs":[],"workflow_runs":[]}'; fi
STUB
chmod +x "$T/bin/gh"
set +e
PATH="$T/bin:$PATH" STUB_DIR="$T" STUB_LOG="$T/gh.log" \
  python3 "$REPO_ROOT/scripts/release/qualify-sha.py" --fetch --repo o/r --sha "$SHA_Q" \
  --contexts "$T/contexts" --carriers ci.yml >"$T/d-fetch.out" 2>&1
rc=$?
PATH="$T/bin:$PATH" STUB_DIR="$T" STUB_LOG="$T/gh-fail.log" STUB_FAIL_PAGE=2 \
  python3 "$REPO_ROOT/scripts/release/qualify-sha.py" --fetch --repo o/r --sha "$SHA_Q" \
  --contexts "$T/contexts" --carriers ci.yml >"$T/d-fail.out" 2>&1
rc_fail=$?
set -e
expect_rc "contexts on page two are found through explicit pagination" 0 "$rc" "$T/d-fetch.out" "qualify-sha: OK"
if grep -q "commits/$SHA_Q/check-runs?filter=all&per_page=100&page=2" "$T/gh.log"; then
  pass "the API is queried by SHA (never tag), filter=all, per_page=100, page 2 read"
else
  fail "unexpected API URLs: $(tr '\n' ' ' <"$T/gh.log")"
fi
expect_rc "a failed page read refuses instead of qualifying on a partial read" nonzero "$rc_fail" "$T/d-fail.out" "failed"

# ---------------------------------------------------------------------------
echo "E  tag ruleset"
mk_rules() { # DIR LISTJSON DETAILJSON
  mkdir -p "$1"
  printf '%s' "$2" >"$1/list.json"
  printf '%s' "$3" >"$1/7.json"
}
good='{"id":7,"name":"release-tags","target":"tag","enforcement":"active","conditions":{"ref_name":{"include":["refs/tags/v*"]}},"rules":[{"type":"update"},{"type":"deletion"},{"type":"creation"}]}'
mk_rules "$T/r-none" '[{"id":1,"target":"branch","enforcement":"active"}]' '{}'
mk_rules "$T/r-good" '[{"id":7,"target":"tag","enforcement":"active"}]' "$good"
mk_rules "$T/r-eval" '[{"id":7,"target":"tag","enforcement":"evaluate"}]' "${good/active/evaluate}"
mk_rules "$T/r-nodel" '[{"id":7,"target":"tag","enforcement":"active"}]' "${good/\{\"type\":\"deletion\"\},/}"
mk_rules "$T/r-scope" '[{"id":7,"target":"tag","enforcement":"active"}]' "${good/refs\/tags\/v\*/refs\/tags\/other*}"
rs() { set +e; bash "$REPO_ROOT/scripts/release/assert-tag-ruleset.sh" --from-dir "$1" >"$2" 2>&1; local rc=$?; set -e; return $rc; }
rs "$T/r-good" "$T/e.out" && rc=0 || rc=$?;  expect_rc "an active v* tag ruleset with update+deletion is accepted" 0 "$rc" "$T/e.out" "assert-tag-ruleset: OK"
rs "$T/r-none" "$T/e.out" && rc=0 || rc=$?;  expect_rc "no tag ruleset refuses" nonzero "$rc" "$T/e.out" "REFUSED"
rs "$T/r-eval" "$T/e.out" && rc=0 || rc=$?;  expect_rc "an evaluate-mode (not enforced) ruleset refuses" nonzero "$rc" "$T/e.out" "REFUSED"
rs "$T/r-nodel" "$T/e.out" && rc=0 || rc=$?; expect_rc "a ruleset without a deletion rule refuses" nonzero "$rc" "$T/e.out" "REFUSED"
rs "$T/r-scope" "$T/e.out" && rc=0 || rc=$?; expect_rc "a ruleset not scoped to refs/tags/v* refuses" nonzero "$rc" "$T/e.out" "REFUSED"

# ---------------------------------------------------------------------------
echo "F  nfpm archive (extracted packaging block)"
mkdir -p "$T/fbin" "$T/rt" "$T/pkg/dist"
cat >"$T/fbin/curl" <<'SHIM'
#!/usr/bin/env bash
# shim curl: serve ALTERED bytes, to -o FILE when given, else to stdout.
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done
if [ -n "$out" ]; then printf 'not the nfpm release tarball\n' >"$out"; else printf 'not the nfpm release tarball\n'; fi
SHIM
cat >"$T/fbin/tar" <<'SHIM'
#!/usr/bin/env bash
# shim tar: record that extraction happened; never touch /usr/local/bin.
cat >/dev/null 2>&1 || true
touch "$TAR_MARK"
SHIM
cat >"$T/fbin/nfpm" <<'SHIM'
#!/usr/bin/env bash
# shim nfpm: pretend to package.
touch dist/x.deb dist/x.rpm
SHIM
chmod +x "$T/fbin/curl" "$T/fbin/tar" "$T/fbin/nfpm"
# GitHub renders `${{ matrix.nfpm_arch }}` before the shell sees the block;
# render it the same way here.
extract_run "$LIVE_YML" "Build deb and rpm packages" | sed 's/\${{ matrix\.nfpm_arch }}/amd64/g' >"$T/nfpm-live.sh"
extract_run "$FROZEN_YML" "Build deb and rpm packages" | sed 's/\${{ matrix\.nfpm_arch }}/amd64/g' >"$T/nfpm-old.sh"
set +e
(cd "$T/pkg" && PATH="$T/fbin:$PATH" TAR_MARK="$T/tar-live" RUNNER_TEMP="$T/rt" TAG=v1.0.0 \
  bash "$T/nfpm-live.sh") >"$T/f1.out" 2>&1
rc=$?
(cd "$T/pkg" && PATH="$T/fbin:$PATH" TAR_MARK="$T/tar-old" TAG=v1.0.0 bash "$T/nfpm-old.sh") >"$T/f2.out" 2>&1
rc_old=$?
set -e
if [ "$rc" -ne 0 ] && [ ! -e "$T/tar-live" ]; then
  pass "an altered nfpm tarball is refused before tar runs"
else
  fail "altered nfpm tarball: rc=$rc, tar ran=$([ -e "$T/tar-live" ] && echo yes || echo no): $(tail -3 "$T/f1.out" | tr '\n' ' ')"
fi
if [ "$rc_old" -eq 0 ] && [ -e "$T/tar-old" ]; then
  pass "R-203: the frozen pre-#3546 block extracts the altered archive and packages it"
else
  fail "R-203: the frozen nfpm block no longer reproduces the defect (rc=$rc_old): $(tail -3 "$T/f2.out" | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------
if [ "$failures" -ne 0 ]; then
  echo "test-release-hardening: FAIL — $failures case(s) misbehaved" >&2
  exit 1
fi
echo "test-release-hardening: OK — every #3546 release control refuses what it exists to refuse, and the frozen pre-fix workflow is shown to accept it"
