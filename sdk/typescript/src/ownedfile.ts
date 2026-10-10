// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * The owner-only, descriptor-bound credential reader behind `wake.ts` (#3780,
 * #3812). It lives in its own module so the platform-flag seam used by the
 * tests is never part of `dist/wake.d.ts`, which the `./wake` subpath
 * publishes (#6235). The package `exports` map names no subpath for this file,
 * so a consumer cannot import it either.
 */

import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  type Stats,
} from "node:fs";

/**
 * Apply the bundle's on-disk standard to an ALREADY-OBTAINED stat.
 *
 * Split out so the descriptor-bound path (`fstatSync`) and the Windows
 * path-based fallback refuse with the SAME words. `path` is only ever used to
 * word the message; nothing here resolves it again.
 */
function checkBundleStat(
  path: string,
  st: Stats,
  makeError: (message: string) => Error,
): void {
  if (!st.isFile()) throw makeError(`${path} is not a regular file`);
  if ((st.mode & 0o077) !== 0) {
    throw makeError(
      `${path} is mode ${(st.mode & 0o7777).toString(8).padStart(4, "0")}; a bundle ` +
        "holding a private key must be 0600, or another local user can join the hub " +
        "as this agent",
    );
  }
  if (typeof process.geteuid === "function" && st.uid !== process.geteuid()) {
    throw makeError(`${path} is owned by uid ${st.uid}, not by the caller`);
  }
}

/**
 * The flags a platform's `node:fs` offers for binding the check to the
 * descriptor. Both are `undefined` on Windows (#3812).
 */
export interface OwnerOnlyOpenFlags {
  noFollow?: number;
  nonBlock?: number;
}

/**
 * The owner-only reader with the platform flags passed in, so a POSIX test can
 * exercise the Windows leg (#3812). This module is NOT mapped by the package
 * `exports`, so none of it is part of the SDK's public surface (#6235).
 */
export function readOwnerOnlyWith(
  path: string,
  flags: OwnerOnlyOpenFlags,
  makeError: (message: string) => Error,
): string {
  const { noFollow, nonBlock } = flags;
  let openFlags = fsConstants.O_RDONLY;
  if (typeof noFollow === "number" && typeof nonBlock === "number") {
    openFlags |= noFollow | nonBlock;
  } else if (lstatSync(path).isSymbolicLink()) {
    // Windows (#3812): with no O_NOFOLLOW the link refusal is this pre-check
    // on the path, and nothing else is: the mode/owner check and the read
    // below run on ONE descriptor exactly as on POSIX. The residual on this
    // leg is a link swapped in between here and the open, never a
    // check-then-read on the path.
    throw makeError(
      `${path} is a symlink: a credential reached through a link is one whose ` +
        "permissions were checked on the wrong file",
    );
  }

  let fd: number;
  try {
    fd = openSync(path, openFlags);
  } catch (err) {
    // ELOOP is what O_NOFOLLOW reports for a symlink on Linux and macOS
    // (EMLINK on the BSDs). Kept as its own refusal so the operator is told
    // what is actually wrong rather than handed a bare errno.
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ELOOP" || code === "EMLINK") {
      throw makeError(
        `${path} is a symlink: a credential reached through a link is one whose ` +
          "permissions were checked on the wrong file",
      );
    }
    throw err;
  }
  try {
    // fstat on the descriptor just opened — never a second look at the path.
    checkBundleStat(path, fstatSync(fd), makeError);
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}
