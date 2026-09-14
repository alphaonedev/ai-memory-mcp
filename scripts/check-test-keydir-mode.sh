#!/usr/bin/env bash
# #3733 gate — INVARIANT: a test that creates a directory it uses as a key dir
# MUST use tests/common/key_dir_sandbox.rs::mkdir_0700 (create + chmod 0700),
# NEVER a bare std::fs::create_dir[_all]. This is not a failure prediction: a
# bare-created key dir is 0o755 at umask 022 (the author's machine) but 0o775
# (group-writable) at umask 0002 (this host + most user-private-group distros),
# and the #3198 key-dir guard CORRECTLY refuses a group-writable key dir. A
# fixture that skips the chmod is wrong whether or not its current assertions
# notice — the next assertion added to it will, and it will fail pointing at a
# product check working correctly (the #3733 confusing-failure shape).
# CORRELATED so it only fires on the SAME token bare-created AND passed as the
# key dir (not on an unrelated dir while KEY_DIR points at a TempDir root).
set -u
fail=0
for f in $(git grep -lE 'AI_MEMORY_KEY_DIR|_KEY_DIR"' -- 'tests/*.rs' 'tests/**/*.rs' | sort -u); do
  grep -qE 'mkdir_0700|from_mode\(0o700\)' "$f" && continue
  if grep -qE 'std::fs::create_dir(_all)?\(&(keys|key_dir|kdir|dir)\b' "$f" \
     && grep -qE 'KEY_DIR"?,\s*&?(keys|key_dir|kdir|dir)\b|KEY_DIR",\s*[a-z_]+(\.path\(\))?\.join\("keys"\)|self\.keys' "$f"; then
    echo "INVARIANT VIOLATION ($f): a test that creates a key directory must use"
    echo "  key_dir_sandbox::mkdir_0700 (create + chmod 0700), not a bare create_dir —"
    echo "  otherwise the key dir inherits the umask (0o775 @umask0002) and the #3198"
    echo "  guard refuses it. Fix the FIXTURE, never the product (#3733)."
    fail=1
  fi
done
[ "$fail" -eq 0 ] && echo "ok: every key-dir-creating test uses mkdir_0700"
exit $fail
