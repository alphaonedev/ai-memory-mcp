# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Strict YAML loading and canonical pins for the tier workflows (#8187, round 8).

The hand-written line parser of rounds 1 to 7 missed a construct class in every round (indentation, comments,
continuations, quoted keys, anchors).  Round 8 reads the tier workflows with PyYAML instead, through ``StrictLoader``:

* a duplicate mapping key is refused after the key scalar is normalised, so ``defaults``, ``'defaults'``,
  ``"defaults"`` and ``defaults `` are one key; ``on`` (read as ``True`` by YAML 1.1) is mapped back to the string
  ``on``;
* an anchor, an alias or a merge key (``<<``) is refused anywhere in the document;
* a mapping key that is not a string is refused;
* a top-level key outside ``TOP_LEVEL_KEYS`` is refused.

A job or a workflow-level key is pinned as the SHA-256 of ``canonical_json`` of the loaded object.  The pins are in
``tier_export_job_pins_8187.json`` (section ``primary``); a failure names the workflow, job, step index, step name
or id and the first differing key path, with any ``scheme://user:pass@`` masked.

``import yaml`` failing is an error, never a skip: the message names ``scripts/test/requirements-ci.txt``.
"""

import hashlib
import json
import re

try:
    import yaml
except ImportError as exc:  # fail the module: a missing loader must never turn the pins into a skip
    raise ImportError("PyYAML is required by the tier workflow pins (#8187): install it with `python3 -m pip install "
                      "--require-hashes --no-deps -r scripts/test/requirements-ci.txt` (scripts/test/requirements-ci.txt)"
                      ) from exc

TOP_LEVEL_KEYS = frozenset(("name", "run-name", "on", "permissions", "env", "defaults", "concurrency", "jobs"))
STR_TAG = "tag:yaml.org,2002:str"
BOOL_TAG = "tag:yaml.org,2002:bool"
MERGE_TAG = "tag:yaml.org,2002:merge"
# the discovery list: every workflow that names the tier secret or its environment variable (#8187 security F2)
TIER_MARKERS = re.compile(r"AI_MEMORY_CI_FED_URL|AI_MEMORY_TEST_POSTGRES_URL|pg_ci_url_file|ai-memory-ci-fed-url")
TIER_JOB_MARK = re.compile(TIER_MARKERS.pattern + r"|tier_credential\.py|check-tier-password")
TIER_VERBS = re.compile(r"github-env|export-url")
EXPORT_CALL = re.compile(r"tier_credential\.py\s+github-env\b.*--url-file")
EMPTY_EXPANSION = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-)?\}|\$''|\$\"\"|''|\"\"")
URL_USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^\s/@]*@")
HOSTED_LABEL = re.compile(r"^(?:ubuntu|macos|windows)-(?:latest|\d+(?:\.\d+)?)(?:-(?:arm|arm64|xlarge|large|intel))*$")
LOCAL_USES = re.compile(r"^\./")


class StrictYamlError(ValueError):
    """A construct the strict loader refuses; ``args[0]`` names it."""


# libyaml's parser is used when the build has it (the hosted wheels do): the same events, much faster
BASE_LOADER = yaml.CSafeLoader if getattr(yaml, "__with_libyaml__", False) else yaml.SafeLoader


def refuse_anchors(text):
    """Raise ``StrictYamlError`` when the event stream of ``text`` holds an anchor or an alias."""
    for event in yaml.parse(text, Loader=BASE_LOADER):
        if isinstance(event, yaml.AliasEvent):
            raise StrictYamlError("an alias (*name) is not allowed in a tier workflow")
        if getattr(event, "anchor", None) is not None:
            raise StrictYamlError("an anchor (&name) is not allowed in a tier workflow")


class StrictLoader(BASE_LOADER):
    """Safe loader that refuses duplicate keys, merge keys and non-string keys (anchors: see ``refuse_anchors``)."""

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise StrictYamlError("expected a mapping")
        mapping = {}
        for key_node, value_node in node.value:
            if key_node.tag == MERGE_TAG:
                raise StrictYamlError("a merge key (<<) is not allowed in a tier workflow")
            if not isinstance(key_node, yaml.ScalarNode):
                raise StrictYamlError("a mapping key that is not a scalar is not allowed")
            if key_node.tag == BOOL_TAG and key_node.value == "on":
                key = "on"  # YAML 1.1 reads the bare word as True; the workflow key is the string
            elif key_node.tag == STR_TAG:
                key = self.construct_scalar(key_node)
            else:
                raise StrictYamlError("a mapping key that is not a string is not allowed")
            if key in mapping:
                raise StrictYamlError("the mapping key %r appears twice" % key)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def mask_userinfo(text):
    """``text`` with the user:password of every ``scheme://user:pass@`` replaced (a failure message never echoes it)."""
    return URL_USERINFO.sub(r"\1***@", text)


def load_failure(exc):
    """The rule that refused a document, never a fragment of it (F26): our own rule text for a ``StrictYamlError``, else
    the parser error class and the line of its mark."""
    if isinstance(exc, StrictYamlError):
        return mask_userinfo(str(exc.args[0]))
    mark = getattr(exc, "problem_mark", None)
    where = " at line %d" % (mark.line + 1) if mark is not None else ""
    return "%s%s" % (type(exc).__name__, where)


def load_strict(text):
    """The document of ``text`` through ``StrictLoader``; raises ``StrictYamlError`` or ``yaml.YAMLError``."""
    refuse_anchors(text)
    loader = StrictLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def load_lenient(text):
    """The document through the plain safe loader (anchors expanded): for files outside the pinned set."""
    return yaml.load(text, Loader=yaml.SafeLoader)


def parse_workflow(text):
    """``(data, problems)`` of a tier workflow: strict load, a mapping, top-level keys in the closed set, ``jobs`` set."""
    try:
        data = load_strict(text)
    except (StrictYamlError, yaml.YAMLError) as exc:
        return None, ["the workflow does not load strictly: " + load_failure(exc)]
    if not isinstance(data, dict):
        return None, ["the workflow is not a mapping"]
    problems = []
    extra = sorted(set(data) - TOP_LEVEL_KEYS)
    if extra:
        problems.append("top-level keys outside the closed set: " + ", ".join(extra))
    if not isinstance(data.get("jobs"), dict) or not data["jobs"]:
        problems.append("the workflow holds no jobs mapping")
    return data, problems


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(obj):
    return hashlib.sha256(canonical_json(obj).encode("ascii")).hexdigest()


def leaf_strings(obj):
    """Every key and every scalar value of a loaded document as a string."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key)
            yield from leaf_strings(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from leaf_strings(value)
    elif obj is not None:
        yield str(obj)


def normalise_shell(text):
    """``text`` with comment lines gone, continuations joined, escapes and empty quote/expansion pairs removed.

    The markers are searched in this form, so a name split over a continuation, escaped or padded with empty
    quotes or empty ``${NAME}`` expansions is still found.
    """
    code = "\n".join(ln for ln in text.split("\n") if ln.strip() and not ln.lstrip().startswith("#"))
    code = re.sub(r"\\\n\s*", "", code)
    code = re.sub(r"\\(.)", r"\1", code)
    for _ in range(3):
        code = EMPTY_EXPANSION.sub("", code)
    return code


def normalised_leaves(obj):
    """The normalised text of every leaf of a loaded object, one per line."""
    return "\n".join(normalise_shell(leaf) for leaf in leaf_strings(obj))


def names_tier(obj):
    """True when the normalised leaves of a loaded job (or file) name the tier credential, its loader or its gate."""
    text = normalised_leaves(obj)
    return bool(TIER_JOB_MARK.search(text) or TIER_VERBS.search(text))


def matches_markers(text_or_obj):
    """True when a file's loaded content (or raw text) names the tier secret, normalised."""
    if isinstance(text_or_obj, str):
        return bool(TIER_MARKERS.search(normalise_shell(text_or_obj)))
    return bool(TIER_MARKERS.search(normalised_leaves(text_or_obj)))


def tier_job_names(data):
    """Names of the jobs of a loaded workflow that name the tier credential."""
    return sorted(name for name, job in data["jobs"].items() if names_tier(job))


def pin_value(obj):
    """The pin of one loaded value: whole hash plus the hash of each top-level key (or list item)."""
    if isinstance(obj, dict):
        return {"sha256": digest(obj), "keys": {key: digest(value) for key, value in obj.items()}}
    return {"sha256": digest(obj)}


def pin_job(job):
    """``{"sha256", "keys", "steps"}``: the job, each job-level key, and each step with its keys."""
    entry = pin_value(job)
    steps = job.get("steps") if isinstance(job, dict) else None
    entry["steps"] = [pin_value(step) for step in steps] if isinstance(steps, list) else []
    return entry


def build_pins(data):
    """The primary pin section of one loaded workflow."""
    names = sorted(data["jobs"])
    return {
        "job_names": names,
        "job_names_sha256": digest(names),
        "tier_jobs": {name: pin_job(data["jobs"][name]) for name in tier_job_names(data)},
        "workflow_keys": {key: digest(value) for key, value in data.items() if key != "jobs"},
    }


def step_label(step, index):
    """``name`` or ``id`` of a step for a message, masked BEFORE the 60-character cut (F33); a step with neither is ``step[<index>]``, never its content (F25)."""
    if isinstance(step, dict):
        for key in ("name", "id"):
            value = step.get(key)
            if isinstance(value, str) and value.strip():
                return mask_userinfo(value.strip()).splitlines()[0][:60]
    return "step[%d]" % index


def first_difference(pinned, job):
    """``(step index or None, path)`` of the first key of ``job`` that differs from its pin entry."""
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    for key, value in job.items():
        if key == "steps":
            continue
        if pinned["keys"].get(key) != digest(value):
            return None, "job." + key
    for key in pinned["keys"]:
        if key != "steps" and key not in job:
            return None, "job." + key + " (removed)"
    old_steps = pinned["steps"]
    for index, step in enumerate(steps):
        if index >= len(old_steps):
            return index, "steps[%d] (added)" % index
        if old_steps[index]["sha256"] != digest(step):
            if isinstance(step, dict) and "keys" in old_steps[index]:
                for key, value in step.items():
                    if old_steps[index]["keys"].get(key) != digest(value):
                        return index, "steps[%d].%s" % (index, key)
                for key in old_steps[index]["keys"]:
                    if key not in step:
                        return index, "steps[%d].%s (removed)" % (index, key)
            return index, "steps[%d]" % index
    if len(old_steps) > len(steps):
        return len(steps), "steps[%d] (removed)" % len(steps)
    return None, "job"


EXPRESSION = "${{"


def runs_on_labels(job):
    """The labels in a job's ``runs-on`` as a list, or None when they cannot be read as plain strings (r10 option C).

    No expression is resolved: ``${{`` anywhere in ``runs-on`` (scalar, list element or mapping value) returns None,
    a mapping with any key other than ``labels`` (a ``group``) returns None, a non-string element returns None, and so
    does an empty list.  A job whose label is chosen from a matrix is green only through an exact ``RUNS_ON_EXEMPT`` row.
    """
    value = job.get("runs-on") if isinstance(job, dict) else None
    if isinstance(value, dict):
        if set(value) != {"labels"}:
            return None
        value = value["labels"]
    items = value if isinstance(value, list) else [value]
    labels = []
    for item in items:
        if not isinstance(item, str) or EXPRESSION in item:
            return None
        labels.append(item.strip())
    return labels or None


# (workflow, job) -> (reason, the exact ``runs-on`` string, the set of label tuples the matrix may imply).  The key is
# the pair, never the job name alone.  Rows read from the real files: session-boot-lifetime.yml (lifetime-tests) lists
# `os: ubuntu-latest / runner: '["ubuntu-latest"]'` and `os: macos-fed / runner: '["self-hosted","macos-fed"]'`;
# ci.yml (mobile-cross-compile) lists `os: macos-latest` and `os: ubuntu-latest`; release.yml (release) lists
# `os: ubuntu-latest`, `ubuntu-24.04-arm`, `macos-15-intel` and `macos-latest`.  lifetime-tests is the only row that
# may name a self-hosted tuple: the macOS fleet runner holds the at-rest tier URL file like linux-fed does, so that
# job and its workflow are pinned in the exempt_jobs section of tier_export_job_pins_8187.json (F20, F21): the exempt
# job and every workflow-level key except ``jobs`` of its workflow; the residual is #6181.
RUNS_ON_EXEMPT = {
    ("session-boot-lifetime.yml", "lifetime-tests"): (
        "matrix leg on the macOS fleet runner; no tier credential, steps pinned (F20)",
        "${{ fromJSON(matrix.runner) }}",
        frozenset({("ubuntu-latest",), ("self-hosted", "macos-fed")}),
    ),
    ("ci.yml", "mobile-cross-compile"): (
        "iOS and Android cross-compile on GitHub-hosted images",
        "${{ matrix.os }}",
        frozenset({("macos-latest",), ("ubuntu-latest",)}),
    ),
    ("release.yml", "release"): (
        "release builds on GitHub-hosted images",
        "${{ matrix.os }}",
        frozenset({("ubuntu-latest",), ("ubuntu-24.04-arm",), ("macos-15-intel",), ("macos-latest",)}),
    ),
}
# the matrix field each pinned ``runs-on`` string reads, and whether its values are JSON label lists
RUNS_ON_FORMS = {"${{ matrix.os }}": ("os", False), "${{ fromJSON(matrix.runner) }}": ("runner", True)}


def plain_scalar(value):
    """True for a string without an expression, a number or a bool (a nested list, a mapping or null is not)."""
    if isinstance(value, str):
        return EXPRESSION not in value
    return isinstance(value, (int, float))


def matrix_values(matrix, field):
    """``(values of FIELD over every leg, None)`` for a strictly parsed matrix, or ``(None, why)``.

    The matrix is a mapping of keys to non-empty lists of plain scalars, with an optional ``include`` list of flat
    mappings of plain scalars and no ``exclude``.  An expression, a nested list or mapping, a non-mapping include
    entry, or an include leg that cannot take FIELD from the top level is refused.
    """
    if not isinstance(matrix, dict) or not matrix:
        return None, "strategy.matrix is not a mapping"
    if "exclude" in matrix:
        return None, "strategy.matrix.exclude is present"
    for key, value in matrix.items():
        if not isinstance(key, str) or EXPRESSION in key:
            return None, "a matrix key is not a plain string"
        if key == "include":
            continue
        if not isinstance(value, list) or not value or not all(plain_scalar(item) for item in value):
            return None, "matrix.%s is not a list of plain scalars" % key
    include = matrix.get("include", [])
    if not isinstance(include, list):
        return None, "matrix.include is not a list"
    values = list(matrix.get(field, []))
    for entry in include:
        if not isinstance(entry, dict) or not entry:
            return None, "a matrix.include entry is not a flat mapping"
        if not all(isinstance(key, str) and EXPRESSION not in key and plain_scalar(value) for key, value in entry.items()):
            return None, "a matrix.include entry holds an expression, a nested value or a non-string key"
        if field in entry:
            values.append(entry[field])
        elif field not in matrix:
            return None, "a matrix.include leg has no %s" % field
    return (values, None) if values else (None, "the matrix has no legs")


def label_tuples(values, as_json):
    """``(set of label tuples, None)`` from the matrix values (plain strings, or JSON label lists), else ``(None, why)``."""
    found = set()
    for value in values:
        if not isinstance(value, str):
            return None, "a runner value is not a string"
        if as_json:
            try:
                parsed = json.loads(value)
            except ValueError:
                return None, "a runner value is not JSON"
            if not isinstance(parsed, list) or not parsed or not all(isinstance(item, str) for item in parsed):
                return None, "a runner value is not a non-empty JSON list of strings"
            found.add(tuple(parsed))
        else:
            found.add((value,))
    return found, None


def exemption_problem(row, job):
    """Why a job no longer fits its ``RUNS_ON_EXEMPT`` row, or None.

    ``runs-on`` must equal the pinned string exactly, the matrix must pass the strict parse, and the label tuples the
    matrix implies must EQUAL the row's set (a missing, extra or reordered label set is a problem).
    """
    reason, pinned, expected = row
    if not isinstance(job, dict) or job.get("runs-on") != pinned:
        return "runs-on is not the pinned string"
    form = RUNS_ON_FORMS.get(pinned)
    if form is None:
        return "the row names a runs-on form this check does not read"
    strategy = job.get("strategy")
    values, why = matrix_values(strategy.get("matrix") if isinstance(strategy, dict) else None, form[0])
    if why:
        return why
    found, why = label_tuples(values, form[1])
    if why:
        return why
    if found != expected:
        return "the label sets the matrix implies differ from the pinned sets"
    return None


def runner_problem(workflow, name, job):
    """None, or why the job's runner is not provably GitHub-hosted: only a plain hosted label or an exact row passes."""
    row = RUNS_ON_EXEMPT.get((workflow, name))
    if row is not None:
        why = exemption_problem(row, job)
        return None if why is None else "the runs-on exemption no longer fits (%s)" % why
    labels = runs_on_labels(job)
    if labels is None:
        return ("runs-on cannot be read as plain labels (an expression, a group or a non-string); only an exact "
                "exemption row may use one")
    if any(not HOSTED_LABEL.match(label) for label in labels):
        return "runs-on names a label that is not GitHub-hosted; only a pinned tier job or an exemption row may"
    return None


def stale_row_problems(workflow, data):
    """Problems for the ``RUNS_ON_EXEMPT`` rows of ``workflow`` whose job is not in the loaded workflow."""
    jobs = data.get("jobs") if isinstance(data, dict) else None
    return ["%s job %s: stale exemption row (the job is gone from the workflow)" % (workflow, name)
            for (wf, name) in sorted(RUNS_ON_EXEMPT)
            if wf == workflow and not (isinstance(jobs, dict) and name in jobs)]


def non_tier_runner_problems(workflow, data, tier):
    """A non-tier job must run on a GitHub-hosted label or sit in an exact ``RUNS_ON_EXEMPT`` row (F16, F19)."""
    found = []
    for name, job in data["jobs"].items():
        if name in tier:
            continue
        if isinstance(job, dict) and "uses" in job and "runs-on" not in job:
            continue  # a reusable workflow call: its called file is scanned separately
        why = runner_problem(workflow, name, job)
        if why:
            found.append("%s job %s: %s" % (workflow, name, why))
    return found


def uses_references(data):
    """Every ``uses:`` value of the jobs and steps of a loaded workflow as ``(job, where, value)``."""
    found = []
    for name, job in data["jobs"].items():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):
            found.append((name, "job", job["uses"]))
        for index, step in enumerate(job.get("steps") if isinstance(job.get("steps"), list) else []):
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                found.append((name, "step %d" % index, step["uses"]))
    return found
