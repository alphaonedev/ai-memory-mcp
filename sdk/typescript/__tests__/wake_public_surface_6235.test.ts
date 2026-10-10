// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * The published `./wake` subpath must not expose the owner-only reader's test
 * seam (#6235). `readOwnerOnlyWith({})` selects the Windows leg on POSIX, i.e.
 * the weaker credential-bundle read that #3780 and #3812 exist to avoid; an
 * `@internal` comment does not keep it out of `dist/wake.d.ts`. The check
 * builds the declarations exactly as `npm run build` does and reads them.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

describe("the ./wake public declarations (#6235)", () => {
  it("do not name the owner-only test seam", () => {
    const out = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "wake-dts-6235-"));
    try {
      const root = resolve(__dirname, "..");
      execFileSync(
        join(root, "node_modules", ".bin", "tsc"),
        ["--emitDeclarationOnly", "--declaration", "--outDir", out, "-p", root],
        { cwd: root, stdio: "pipe" },
      );
      const wake = readFileSync(join(out, "wake.d.ts"), "utf8");
      expect(wake).not.toMatch(/readOwnerOnlyWith/);
      expect(wake).not.toMatch(/OwnerOnlyOpenFlags/);
      expect(readdirSync(out)).toContain("wake.d.ts");
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }, 120_000);
});
