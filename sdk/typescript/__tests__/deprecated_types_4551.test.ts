// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * #4551: the grant, revoke and cluster request/response types are deprecated
 * but stay exported for one release (CHANGELOG.md, "Removed - BREAKING").
 *
 * Interfaces are erased at runtime and ts-jest does not fail a run on a missing
 * type export, so this asks the TypeScript compiler for the exports of the
 * package entry point directly. Removing any of the five fails the suite.
 */

import path from "node:path";
import ts from "typescript";

const DEPRECATED_TYPES = [
  "GrantRequest",
  "RevokeRequest",
  "ClusterPeer",
  "ClusterRequest",
  "ClusterResponse",
];

function exportedTypes(): Map<string, ts.Symbol> {
  const entry = path.resolve(__dirname, "../src/index.ts");
  const program = ts.createProgram([entry], {
    module: ts.ModuleKind.ESNext,
    target: ts.ScriptTarget.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    strict: true,
    noEmit: true,
    skipLibCheck: true,
  });
  const checker = program.getTypeChecker();
  const source = program.getSourceFile(entry);
  if (source === undefined) {
    throw new Error("src/index.ts not found in the program");
  }
  const moduleSymbol = checker.getSymbolAtLocation(source);
  if (moduleSymbol === undefined) {
    throw new Error("src/index.ts is not a module");
  }
  const out = new Map<string, ts.Symbol>();
  for (const sym of checker.getExportsOfModule(moduleSymbol)) {
    out.set(sym.getName(), sym);
  }
  return out;
}

describe("deprecated removed-route types stay exported (#4551)", () => {
  const exported = exportedTypes();

  it.each(DEPRECATED_TYPES)("%s is exported from the package entry", (name) => {
    expect(exported.has(name)).toBe(true);
  });

  it.each(DEPRECATED_TYPES)("%s carries a @deprecated tag", (name) => {
    const sym = exported.get(name);
    expect(sym).toBeDefined();
    const tags = (sym?.getJsDocTags() ?? []).map((t) => t.name);
    expect(tags).toContain("deprecated");
  });
});
