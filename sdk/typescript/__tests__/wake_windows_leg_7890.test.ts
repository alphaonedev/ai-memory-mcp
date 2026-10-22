// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * #7890: the Windows leg of `readOwnerOnly` must bind its check to the bytes it
 * reads. The leg is exercised on any platform through `readOwnerOnlyWindows`.
 * The race is simulated with the `betweenCheckAndRead` / `afterOpen` hooks: the
 * hook swaps the path exactly where a local attacker would.
 */

import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  renameSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { readOwnerOnlyWindows, WakeError } from "../src/wake.js";

const SECRET = "owner-only-credential";
const SWAPPED = "swapped-in-by-another-user";

describe("readOwnerOnlyWindows (#7890)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(process.env.TMPDIR ?? ".", "wake-7890-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const cred = (name = "cred.json"): string => {
    const p = join(dir, name);
    writeFileSync(p, SECRET, { mode: 0o600 });
    return p;
  };

  it("reads a regular 0600 file", () => {
    expect(readOwnerOnlyWindows(cred())).toBe(SECRET);
  });

  it("refuses a symlink", () => {
    const target = cred("real.json");
    const link = join(dir, "link.json");
    symlinkSync(target, link);
    expect(() => readOwnerOnlyWindows(link)).toThrow(WakeError);
  });

  it("refuses a file swapped in after the check (dev/ino mismatch)", () => {
    const p = cred();
    const evil = join(dir, "evil.json");
    writeFileSync(evil, SWAPPED, { mode: 0o600 });
    const swap = (): void => renameSync(evil, p);
    expect(() =>
      readOwnerOnlyWindows(p, { betweenCheckAndRead: swap, afterOpen: swap }),
    ).toThrow(WakeError);
  });

  it("refuses a symlink swapped in after the check", () => {
    const p = cred();
    const other = join(dir, "other.json");
    writeFileSync(other, SWAPPED, { mode: 0o600 });
    const link = join(dir, "l.json");
    symlinkSync(other, link);
    const swap = (): void => renameSync(link, p);
    expect(() =>
      readOwnerOnlyWindows(p, { betweenCheckAndRead: swap, afterOpen: swap }),
    ).toThrow(WakeError);
  });

  it("reports a missing credential file", () => {
    expect(() => readOwnerOnlyWindows(join(dir, "nope.json"))).toThrow(/nope\.json/);
  });
});
