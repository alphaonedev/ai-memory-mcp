// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * #7890: the Windows leg of `readOwnerOnly` must bind its check to the bytes it
 * reads. The leg is exercised on any platform through `readOwnerOnlyWindows`.
 * The race is simulated with the `afterOpen` hook: the
 * hook swaps the path exactly where a local attacker would.
 */

import { jest } from "@jest/globals";
import fs from "node:fs";
import {
  mkdirSync,
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
      readOwnerOnlyWindows(p, { afterOpen: swap }),
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
      readOwnerOnlyWindows(p, { afterOpen: swap }),
    ).toThrow(WakeError);
  });

  it("reports a missing credential file", () => {
    expect(() => readOwnerOnlyWindows(join(dir, "nope.json"))).toThrow(/nope\.json/);
  });

  describe("pre-open check (#8053)", () => {
    // The check on what the path names runs BEFORE the open: a spy on the
    // real `openSync` proves nothing was opened for a refused path.
    let openSpy: ReturnType<typeof jest.spyOn>;
    beforeEach(() => {
      openSpy = jest.spyOn(fs, "openSync");
    });
    afterEach(() => openSpy.mockRestore());
    const read = readOwnerOnlyWindows;
    const Err = WakeError;

    it("the spy sees the open of a regular file (control)", () => {
      const p = cred("ctl.json");
      openSpy.mockClear(); // writeFileSync opened the file too
      expect(read(p)).toBe(SECRET);
      expect(openSpy).toHaveBeenCalledTimes(1);
    });

    it("refuses a directory before opening it", () => {
            const d = join(dir, "adir");
      mkdirSync(d);
      expect(() => read(d)).toThrow(Err);
      expect(() => read(d)).toThrow(/is not a regular file/);
      expect(openSpy).not.toHaveBeenCalled();
    });

    it("refuses a symlink before opening it", () => {
            const target = cred("real2.json");
      const link = join(dir, "link2.json");
      symlinkSync(target, link);
      openSpy.mockClear(); // writeFileSync opened the target
      expect(() => read(link)).toThrow(Err);
      expect(() => read(link)).toThrow(/is a symlink/);
      expect(openSpy).not.toHaveBeenCalled();
    });
  });
});
