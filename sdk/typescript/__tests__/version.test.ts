// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Version-SSOT guard (#2455).
 *
 * The Python SDK shipped four version strings that had drifted to three
 * different answers (pyproject `1.0.0`, `__init__` `0.8.0`, User-Agent
 * `0.6.0-alpha.0`, README `0.6.0-alpha.0`), so a published wheel told PyPI one
 * version and every daemon's access log another. The TypeScript package has
 * exactly one version literal — `package.json` — but its README quotes it in
 * prose, which is the same drift vector one step smaller. This test keeps the
 * quote honest.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(__dirname, "..");

const pkg = JSON.parse(
  readFileSync(resolve(ROOT, "package.json"), "utf8"),
) as { version: string };

describe("version SSOT", () => {
  test("README Status line matches package.json", () => {
    const readme = readFileSync(resolve(ROOT, "README.md"), "utf8");
    const match = /^> Status: `([^`]+)`/m.exec(readme);
    expect(match).not.toBeNull();
    expect(match?.[1]).toBe(pkg.version);
  });

  test("package.json carries a concrete semver", () => {
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+(?:[-+].+)?$/);
  });
});
