#!/usr/bin/env bash
# v1.0.0 #1860 — OPERATOR helper: acquire the vectorlite SQLite
# loadable extension for the opt-in `vectorlite` cargo feature.
#
# ai-memory deliberately performs NO build-time native-lib
# acquisition (it would break the 3-OS CI matrix, the 5 release
# channels, and reproducible builds — the blockers #1860 documents).
# Instead the operator acquires the extension binary out-of-band and
# points AI_MEMORY_VECTORLITE_EXTENSION at it; the daemon loads it at
# runtime and FAILS CLOSED to the default pure-Rust HNSW backend if
# anything about it is wrong.
#
# Upstream (vetted 2026-07-18):
#   repo:    https://github.com/1yefuwang1/vectorlite  (Apache-2.0)
#   release: v0.2.0 (2024-08-19) — prebuilt binaries ship ONLY inside
#            `vectorlite_py` Python wheels (zip archives), 4 platforms.
#            There is NO Rust crate (the crates.io `vectorlite` name is
#            an unrelated in-memory vector DB project) and NO
#            linux-arm64 build — unsupported platforms must build from
#            source with the upstream CMake toolchain.
#
# The wheel SHA256s below were pinned from the upstream v0.2.0 release
# assets. The script verifies the digest BEFORE unzipping; a mismatch
# aborts loudly (fail closed — never install an unverified native lib).
#
# Usage: scripts/fetch-vectorlite.sh <dest-dir>
#   → <dest-dir>/vectorlite.{so|dylib|dll}
#   → export AI_MEMORY_VECTORLITE_EXTENSION=<printed path>
set -euo pipefail

DEST="${1:?usage: fetch-vectorlite.sh <dest-dir>}"
VER="0.2.0"
BASE="https://github.com/1yefuwang1/vectorlite/releases/download/v${VER}"

case "$(uname -s)-$(uname -m)" in
Linux-x86_64)
    WHEEL="vectorlite_py-${VER}-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    SHA256="85df3a88925b48b8350514665ad67b526aa1165d98c2d04e67eb819853daeb35"
    LIB="vectorlite.so"
    ;;
Darwin-x86_64)
    WHEEL="vectorlite_py-${VER}-py3-none-macosx_10_15_x86_64.whl"
    SHA256="eb682db3dbadccf0df9b0c1a2219969fc5d1292393f92bcf7c311d8fc9c873cb"
    LIB="vectorlite.dylib"
    ;;
Darwin-arm64)
    WHEEL="vectorlite_py-${VER}-py3-none-macosx_11_0_arm64.whl"
    SHA256="668d5e956416efb6395ebae21f8c984ac53796a8af261edef5a80f209becbe04"
    LIB="vectorlite.dylib"
    ;;
MINGW* | MSYS* | CYGWIN*)
    WHEEL="vectorlite_py-${VER}-py3-none-win_amd64.whl"
    SHA256="a9a7c78960c3ed9567c3d836f2727f9ad4a124cc2c44eaa5b3e687db8eeeef00"
    LIB="vectorlite.dll"
    ;;
*)
    echo "fetch-vectorlite: no upstream prebuilt for $(uname -s)-$(uname -m)" >&2
    echo "  (upstream v${VER} ships linux-x86_64, macos-x86_64/arm64, win-amd64 only;" >&2
    echo "   build from source: https://github.com/1yefuwang1/vectorlite)" >&2
    exit 2
    ;;
esac

mkdir -p "${DEST}"
TMP="$(mktemp -d "${DEST}/.fetch-vectorlite.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT

echo "fetch-vectorlite: downloading ${WHEEL}" >&2
curl -fsSL -o "${TMP}/${WHEEL}" "${BASE}/${WHEEL}"

echo "${SHA256}  ${TMP}/${WHEEL}" | sha256sum -c - >&2 || {
    echo "fetch-vectorlite: SHA256 MISMATCH — refusing to install (fail closed)" >&2
    exit 3
}

unzip -q -o "${TMP}/${WHEEL}" "vectorlite_py/${LIB}" -d "${TMP}"
install -m 0644 "${TMP}/vectorlite_py/${LIB}" "${DEST}/${LIB}"

echo "fetch-vectorlite: installed $(cd "${DEST}" && pwd)/${LIB}" >&2
echo "export AI_MEMORY_VECTORLITE_EXTENSION=$(cd "${DEST}" && pwd)/${LIB}"
