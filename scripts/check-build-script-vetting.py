#!/usr/bin/env python3
"""Verify recorded build-script claims against Cargo.lock + cargo metadata."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "supply-chain" / "build-script-vetting.json"


def fail(message: str) -> None:
    print(f"build-script vetting gate: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def package_key(package: dict[str, Any]) -> str:
    return f"{package['name']}@{package['version']}"


def main() -> None:
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    if ledger.get("schema") != 1 or not isinstance(ledger.get("packages"), list):
        fail("unsupported or malformed ledger")

    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    locked = {package_key(p): p for p in lock["package"]}
    metadata_proc = subprocess.run(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if metadata_proc.returncode != 0:
        fail(f"cargo metadata failed: {metadata_proc.stderr.strip()}")
    metadata = json.loads(metadata_proc.stdout)
    packages = {package_key(p): p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    packages_by_id = {p["id"]: p for p in metadata["packages"]}

    for record in ledger["packages"]:
        key = package_key(record)
        lock_package = locked.get(key)
        if lock_package is None:
            fail(f"recorded package {key} is absent from Cargo.lock")
        if lock_package.get("checksum") != record.get("checksum"):
            fail(
                f"{key} checksum drift: lock={lock_package.get('checksum')} "
                f"ledger={record.get('checksum')}"
            )

        package = packages.get(key)
        if package is None:
            fail(f"recorded package {key} is absent from the resolved graph")
        has_custom_build = any("custom-build" in target["kind"] for target in package["targets"])
        if has_custom_build != record.get("custom_build"):
            fail(
                f"{key} custom-build drift: metadata={has_custom_build} "
                f"ledger={record.get('custom_build')}"
            )

        node = nodes[package["id"]]
        actual_build_deps = sorted(
            package_key(packages_by_id[dep["pkg"]])
            for dep in node["deps"]
            if any(kind.get("kind") == "build" for kind in dep["dep_kinds"])
        )
        expected_build_deps = sorted(record.get("build_dependencies", []))
        if actual_build_deps != expected_build_deps:
            fail(
                f"{key} build-dependency drift: metadata={actual_build_deps} "
                f"ledger={expected_build_deps}"
            )

    print(
        "build-script vetting gate: PASS "
        f"({len(ledger['packages'])} checksum/build-target/build-closure records verified)"
    )


if __name__ == "__main__":
    main()
