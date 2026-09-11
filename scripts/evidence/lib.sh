#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for scripts/evidence/* — repo-relative, no operator paths.
# Sourced, never executed.

evidence_repo_root() {
  # $0 of the caller when this file is sourced.
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$here/../.." && pwd
}

# sha256 of the executable the harness addressed.
# Linux: /proc/<pid>/exe (the inode the kernel ran, not argv[0]).
# macOS: lsof txt mapping of the same pid.
# Prints 64 lowercase hex chars; returns 1 if the pid is gone or unreadable.
evidence_sha256_of_pid() {
  local pid="$1" path digest
  if [[ -z "$pid" ]]; then
    echo "evidence_sha256_of_pid: pid required" >&2
    return 2
  fi
  if [[ -r "/proc/${pid}/exe" ]]; then
    digest="$(sha256sum -b "/proc/${pid}/exe" 2>/dev/null | awk '{print $1}')"
  else
    path="$(lsof -a -p "$pid" -d txt -Fn 2>/dev/null | awk '/^n\// {print substr($0,2); exit}')"
    if [[ -z "$path" || ! -r "$path" ]]; then
      echo "evidence_sha256_of_pid: cannot resolve exe for pid ${pid}" >&2
      return 1
    fi
    digest="$(shasum -a 256 "$path" | awk '{print $1}')"
  fi
  if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "evidence_sha256_of_pid: bad digest '${digest}'" >&2
    return 1
  fi
  printf '%s\n' "$digest"
}

evidence_sha256_of_file() {
  local f="$1" digest
  if [[ ! -r "$f" ]]; then
    echo "evidence_sha256_of_file: not readable: $f" >&2
    return 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum -b "$f" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "$f" | awk '{print $1}')"
  fi
  printf '%s\n' "$digest"
}

evidence_source_commit() {
  git -C "$(evidence_repo_root)" rev-parse HEAD
}

evidence_source_tree_sha() {
  git -C "$(evidence_repo_root)" rev-parse 'HEAD^{tree}'
}

evidence_new_run_id() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
  else
    # Fallback: 32 hex from urandom. Not a UUID; still unique enough as a run token.
    od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
    echo
  fi
}
