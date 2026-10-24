"""Shared fixtures for the impact-selection tests (no network, no cargo).

A throwaway git repository and a three-crate cargo metadata document are
built under the repository's own `.local-runs/` so nothing lands in a tmpfs.
Dependency chain of the fixture workspace: app -> store -> core.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List, Optional

SCRIPTS_CI = Path(__file__).resolve().parents[1]
REPO_ROOT = SCRIPTS_CI.parents[1]
SCRATCH_PARENT = REPO_ROOT / ".local-runs" / "impact-tests"
IMPACT_DIR = SCRIPTS_CI / "impact"
RULES_JSON = IMPACT_DIR / "rules.json"
GIT_IDENT = ["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "commit.gpgsign=false"]
CREATE_CRATES = ("core", "store", "app")
DEPENDS_ON = {"core": [], "store": ["core"], "app": ["store"]}

if str(SCRIPTS_CI) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_CI))


def make_scratch() -> tempfile.TemporaryDirectory:
    """Return a TemporaryDirectory rooted under the repo's `.local-runs/`."""
    SCRATCH_PARENT.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=str(SCRATCH_PARENT))


def git(repo: Path, *args: str) -> str:
    """Run git with an argument list inside `repo` and return stdout."""
    res = subprocess.run(["git"] + GIT_IDENT + list(args), cwd=str(repo),
                         capture_output=True, text=True, check=True)
    return res.stdout.strip()


def write_files(repo: Path, files: Dict[str, str]) -> None:
    """Write `files` (relative path -> text) under `repo`."""
    for rel, text in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)


def init_repo(repo: Path) -> str:
    """Create the fixture repository with one base commit and return its sha."""
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")
    files = {"README.txt": "base\n"}
    for name in CREATE_CRATES:
        files["crates/%s/src/lib.rs" % name] = "// %s\n" % name
        files["crates/%s/tests/it_%s.rs" % (name, name)] = "// test\n"
    write_files(repo, files)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    return git(repo, "rev-parse", "HEAD")


def commit_change(repo: Path, files: Dict[str, str]) -> str:
    """Commit `files` on top of HEAD and return the new sha."""
    write_files(repo, files)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "change")
    return git(repo, "rev-parse", "HEAD")


def make_metadata(root: Path) -> dict:
    """Return a cargo-metadata-shaped dict for the three-crate workspace."""
    packages: List[dict] = []
    for name in CREATE_CRATES:
        crate_dir = root / "crates" / name
        packages.append({
            "name": name,
            "manifest_path": str(crate_dir / "Cargo.toml"),
            "dependencies": [
                {"name": dep, "path": str(root / "crates" / dep)}
                for dep in DEPENDS_ON[name]
            ] + [{"name": "serde", "path": None}],
            "targets": [
                {"name": name, "kind": ["lib"],
                 "src_path": str(crate_dir / "src" / "lib.rs")},
                {"name": "it_%s" % name, "kind": ["test"],
                 "src_path": str(crate_dir / "tests" / ("it_%s.rs" % name))},
            ],
        })
    return {"workspace_root": str(root),
            "workspace_members": ["%s 0.1.0 (path+file://%s)" % (n, root)
                                  for n in CREATE_CRATES],
            "packages": packages}


class ImpactCase(unittest.TestCase):
    """Base class: a scratch dir, a fixture repo and a built index."""

    cell_crates: Optional[List[str]] = None

    def setUp(self) -> None:
        self._scratch = make_scratch()
        self.addCleanup(self._scratch.cleanup)
        self.tmp = Path(self._scratch.name)
        self.repo = self.tmp / "repo"
        self.base = init_repo(self.repo)
        self.db = self.tmp / "impact.db"
        self.rules_path = self._rules_file()
        from impact import build_index
        build_index.build_index(self.repo, self.db,
                                metadata=make_metadata(self.repo),
                                rules_path=self.rules_path)

    def _rules_file(self) -> Path:
        """Return the rules file, overriding cell_crates when requested."""
        if self.cell_crates is None:
            return RULES_JSON
        rules = json.loads(RULES_JSON.read_text())
        rules["cell_crates"] = list(self.cell_crates)
        rules["cell_globs"] = []
        out = self.tmp / "rules.json"
        out.write_text(json.dumps(rules))
        return out

    def select(self, changed: List[str], **kwargs) -> dict:
        """Run compute_selection on the fixture index."""
        from impact import select
        return select.compute_selection(self.db, changed, **kwargs)
