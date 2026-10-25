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
or id and the first differing key path, as labels only (r23: nothing is masked after the fact).

Echo class closed by construction (r23, 3-agent vote (6def5ab6)): the checker NEVER emits author- or pin-derived text.  Every
name that reaches a message goes through ``Opaque`` (see the class), whose ``str``, ``repr``, ``format`` and ``bytes`` are
the positional label and the length only; the raw text is reachable only through ``raw()``, which comparison helpers alone
call, and is held in a module-private registry keyed by ``id(wrapper)``, not in an attribute (r24).  There is no deny-list
predicate: a deny-list fails open on every shape nobody listed.

The one exception is a file name: ``repo_problems`` builds its messages from plain file paths (``<name>: does not load ...``,
``<name>: names the tier secret but no pin covers it``).  A workflow file name is settled public: it is a repository path,
visible in the PR body (row 26) and in Rounds 20 and 21, and it is never read from a workflow's content.  Nothing read FROM a
file is printed.

The loaders never re-raise a parser error: ``load_strict`` and ``load_lenient`` raise ``StrictYamlError`` carrying the error
class and the line only, from outside the handler, so no ``__cause__`` or ``__context__`` holds a source fragment (r24).

``import yaml`` failing is an error, never a skip: the message names ``scripts/test/requirements-ci.txt``.
"""

import hashlib
import json
import re
import weakref

try:
    import yaml
except ImportError:  # fail the module: a missing loader must never turn the pins into a skip
    raise ImportError("PyYAML is required by the tier workflow pins (#8187): install it with `python3 -m pip install "
                      "--require-hashes --no-deps -r scripts/test/requirements-ci.txt` (scripts/test/requirements-ci.txt)"
                      ) from None

TOP_LEVEL_KEYS = frozenset(("name", "run-name", "on", "permissions", "env", "defaults", "concurrency", "jobs"))
STR_TAG = "tag:yaml.org,2002:str"
BOOL_TAG = "tag:yaml.org,2002:bool"
MERGE_TAG = "tag:yaml.org,2002:merge"
# the discovery list: every workflow that names the tier secret or its environment variable (#8187 security F2)
TIER_MARKERS = re.compile(r"AI_MEMORY_CI_FED_URL|AI_MEMORY_TEST_POSTGRES_URL|pg_ci_url_file|ai-memory-ci-fed-url")
TIER_JOB_MARK = re.compile(TIER_MARKERS.pattern + r"|tier_credential\.py|check-tier-password")
TIER_VERBS = re.compile(r"github-env|export-url")


class ExportCall:
    """The tier export call, ``tier_credential.py github-env ... --url-file`` on one line, found in LINEAR time (r23 sec F40-e).

    The regex ``tier_credential\\.py\\s+github-env\\b.*--url-file`` restarts its ``.*`` scan to the end of the line at every
    occurrence of the prefix, so a megabyte line of prefixes costs the square of its length.  Here the prefix is found once
    per occurrence and the rest of its line is searched once: a later prefix on the same line has a shorter tail, so it is
    skipped.  The result is the same as the regex's, as a bool."""

    PREFIX = re.compile(r"tier_credential\.py\s+github-env\b")

    def search(self, text):
        checked_to = -1
        for match in self.PREFIX.finditer(text):
            if match.end() <= checked_to:
                continue
            line_end = text.find("\n", match.end())
            line_end = len(text) if line_end < 0 else line_end
            if text.find("--url-file", match.end(), line_end) >= 0:
                return True
            checked_to = line_end
        return False


EXPORT_CALL = ExportCall()

EMPTY_EXPANSION = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-)?\}|\$''|\$\"\"|''|\"\"")
_LABEL = re.compile(r"(?:job|step|key|pin)\[(?:\d+|\?)\]")
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
        for position, (key_node, value_node) in enumerate(node.value):
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
                raise StrictYamlError("the mapping key %r appears twice" % key_label(key, position))
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


_RAW = {}  # id(wrapper) -> the raw value: module-private, so no attribute of a wrapper holds the text (r24 code F42b)


def _forget(key):
    """The finalizer of an ``Opaque``: drops its registry entry.  A module-level function, not the bound ``_RAW.pop``: the
    ``weakref`` finalizer registry holds this function, and a bound method would hand its owner (the registry) to anything
    that walks ``weakref.finalize`` (r25 code C5)."""
    _RAW.pop(key, None)


class Opaque:
    """An author- or pin-derived value that can never be printed (r23, 3-agent vote (6def5ab6), fail closed).

    ``str``, ``repr``, ``format`` and ``bytes`` return ONLY the positional label (``job[3]``, ``step[0]``, ``key[2]``,
    ``pin[1]``) and the length (``len=N``): any f-string, ``%``, ``.format``, ``print``, logging call, exception text or
    assertion message that receives the wrapper prints that, by construction.

    The raw text lives in the module-private registry ``_RAW``, keyed by ``id(self)`` and dropped by ``weakref.finalize``
    when the wrapper dies (r24 code F42b: a slot or a ``__dict__`` entry is one ``getattr`` from a message; the slot read,
    ``object.__getstate__`` and ``json.dumps(default=...)`` each returned it).  The instance holds the label, the length and
    ``__weakref__`` only; ``__getstate__`` returns the label-only string and ``__reduce__`` the label.  ``raw()`` is called
    only inside comparison helpers that return a bool and never build a message (``__eq__``, ``same``).  ``__eq__`` compares
    plain data by digest (``plain_equal``) and refuses any other operand with a typed error, so a comparand's own ``__eq__`` is
    never called with the raw.  ``__hash__`` is the salt plus the length (r28 sec F3): the hash of the raw value would be the
    value for an integer and an equality oracle for any text; two opaques of equal length hash equal whether or not their text
    is equal.  The label is a fixed positional string, so a label-shaped author name prints as its own label and cannot be
    told from one (the intended result).  The length is the only property of the text that is shown: a hash prefix of a
    low-entropy credential is an offline-guess oracle."""

    __slots__ = ("_label", "_n", "__weakref__")

    def __init__(self, raw, label):
        if not isinstance(label, str) or not _LABEL.fullmatch(label):
            raise ValueError("an Opaque label is a positional label")
        try:
            size = len(raw)
        except Exception:  # noqa: BLE001  (a value without a usable length is length 0; nothing it raises is printed)
            size = 0
        self._label = label
        self._n = size if isinstance(size, int) else 0
        _RAW[id(self)] = raw
        weakref.finalize(self, _forget, id(self))

    def raw(self):
        return _RAW.get(id(self))

    def _shown(self):
        return "%s len=%d" % (self._label, self._n)

    def __str__(self):
        return self._shown()

    def __repr__(self):
        return self._shown()

    def __format__(self, spec):
        return self._shown()

    def __bytes__(self):
        return self._shown().encode("ascii")

    def __eq__(self, other):
        if isinstance(other, Opaque):
            return plain_equal(self.raw(), other.raw())
        return NotImplemented

    def __hash__(self):
        return hash((_SALT, self._n))  # r28 sec F3: salt plus length only, never a function of the raw value

    def __getstate__(self):
        return self._shown()

    def __reduce__(self):
        return (Opaque, ("", self._label))

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def opaque(value, label):
    """``value`` as an ``Opaque`` with the positional ``label`` (a test wraps a loaded value this way before it asserts)."""
    return Opaque(value, label)


_SALT = object()  # the hash of an Opaque is this plus its length: an object nobody can recompute from the text
_PLAIN_SCALARS = (str, bytes, int, float, bool, type(None))
_PLAIN_LIMIT = 40


class OpaqueComparisonError(TypeError):
    """A comparison that would hand a raw value to a comparand's own ``__eq__`` (r28 code F3): refused with fixed text."""


def _canonical(value, depth=0):
    """``value`` as nested tuples of tags and digests: str and bytes by digest, scalars by value, containers element by
    element.  Only EXACT built-in types are read; any other object is refused with a typed error that names nothing."""
    if depth > _PLAIN_LIMIT:
        raise OpaqueComparisonError("an Opaque compares plain data only (the value is withheld)")
    kind = type(value)
    if kind is str:
        return ("s", hashlib.sha256(value.encode("utf-8", "surrogatepass")).digest())
    if kind is bytes:
        return ("b", hashlib.sha256(value).digest())
    if kind in _PLAIN_SCALARS:
        return (kind.__name__, value)
    if kind in (list, tuple):
        return (kind.__name__, tuple(_canonical(item, depth + 1) for item in value))
    if kind in (set, frozenset):
        return (kind.__name__, tuple(sorted(_canonical(item, depth + 1) for item in value)))
    if kind is dict:
        return ("dict", tuple(sorted((_canonical(k, depth + 1), _canonical(v, depth + 1)) for k, v in value.items())))
    raise OpaqueComparisonError("an Opaque compares plain data only (the value is withheld)")


def plain_equal(left, right):
    """Whether two plain values are equal; a bool.  Never calls an ``__eq__`` of either operand: both are read by exact type
    (r28 code F3, p1 and p5)."""
    return _canonical(left) == _canonical(right)


def same(left, right):
    """True when two values (``Opaque`` or raw) hold equal plain data; a bool, never a message.  A comparand that is not
    exact-type plain data (a recording ``__eq__``, a subclass, a custom object) is refused with ``OpaqueComparisonError``."""
    left = left.raw() if isinstance(left, Opaque) else left
    right = right.raw() if isinstance(right, Opaque) else right
    return plain_equal(left, right)


def lookup(mapping, key):
    """``mapping[key]`` that never repeats the key when it is missing (r28 sec F1 d: a ``KeyError`` carries the key).  The
    error is a ``LookupError`` with fixed text and nothing chained."""
    if isinstance(mapping, (list, tuple, str, bytes)):  # a sequence: an out-of-range index would also name the index in its error
        value = mapping[key] if isinstance(key, int) and -len(mapping) <= key < len(mapping) else _MISSING
    else:
        value = mapping.get(key, _MISSING)
    if value is _MISSING:
        raise LookupError("a key is missing from the mapping (the key is withheld)")
    return value


_MISSING = object()


def key_label(key, position):
    """``key`` of a mapping as an ``Opaque`` labelled ``key[<position>]`` (r23: no key text is ever printed)."""
    return Opaque(key, "key[%d]" % position)


def name_label(name, universe):
    """``name`` as an ``Opaque`` labelled ``key[<n>]``: ``n`` is its position among the sorted names of ``universe`` (a mapping
    or list of the names it is one of).  Pin data is written from the author's workflow, so a pin-sourced name is opaque
    like a live author key."""
    names = sorted(set(universe) | {name}, key=str)
    return key_label(name, names.index(name))


def job_label(name, jobs):
    """``name`` of a job as an ``Opaque`` labelled ``job[<position>]`` (position in the sorted job keys), ``job[?]`` when it is
    not one of them."""
    names = sorted(jobs, key=str)
    return Opaque(name, "job[%d]" % names.index(name)) if name in names else Opaque(name, "job[?]")


def load_failure(exc):
    """The rule that refused a document, never a fragment of it (F26): our own rule text for a ``StrictYamlError``, else
    the parser error class and the line of its mark."""
    if isinstance(exc, StrictYamlError):
        return str(exc.args[0])
    mark = getattr(exc, "problem_mark", None)
    where = " at line %d" % (mark.line + 1) if mark is not None else ""
    return "%s%s" % (type(exc).__name__, where)


def load_strict(text):
    """The document of ``text`` through ``StrictLoader``; raises ``StrictYamlError`` only: every other exception, parser or
    builtin (r25 sec S1: ``!!int x`` raises ValueError), is converted to its class name (and line when it has one) OUTSIDE the
    handler.

    A parser error is not re-raised (r24 sec F4): its message carries the source line around the fault, and so does a
    chained ``__cause__`` or ``__context__``, so a tag or an escape in an author's workflow would reach pytest's output
    through any uncaught call.  The failure is read inside the handler (class and line only, ``load_failure``) and the new
    error is raised OUTSIDE it, with nothing chained."""
    failure = None
    loader = None
    try:
        refuse_anchors(text)  # its scan can fail on a malformed document too
        loader = StrictLoader(text)
        return loader.get_single_data()
    except Exception as exc:  # our own rule text, a parser error AND a builtin from a standard-tag constructor (r25 sec S1); r28: no bare ``raise``
        failure = load_failure(exc)
    finally:
        if loader is not None:
            loader.dispose()
    raise StrictYamlError(failure)


def load_lenient(text):
    """The document through the plain safe loader (anchors expanded): for files outside the pinned set; raises
    ``StrictYamlError`` (class and line only, nothing chained) for a document it cannot read (r24 sec F4)."""
    failure = None
    try:
        return yaml.load(text, Loader=yaml.SafeLoader)
    except Exception as exc:  # parser errors and builtin constructor errors alike (r25 sec S1): class and line only
        failure = load_failure(exc)
    raise StrictYamlError(failure)


def parse_workflow(text):
    """``(data, problems)`` of a tier workflow: strict load, a mapping, top-level keys in the closed set, ``jobs`` set."""
    try:
        data = load_strict(text)
    except StrictYamlError as exc:
        return None, ["the workflow does not load strictly: " + load_failure(exc)]
    if not isinstance(data, dict):
        return None, ["the workflow is not a mapping"]
    problems = []
    extra = sorted(set(data) - TOP_LEVEL_KEYS)
    if extra:
        problems.append("top-level keys outside the closed set: " + ", ".join(str(key_label(key, position)) for position, key in enumerate(extra)))
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
    """The ``name`` or ``id`` of a step as an ``Opaque`` labelled ``step[<index>]`` (r23: nothing of the text is printed); a step
    with neither wraps the empty string (F25)."""
    if isinstance(step, dict):
        for key in ("name", "id"):
            value = step.get(key)
            if isinstance(value, str) and value.strip():
                return Opaque(value, "step[%d]" % index)
    return Opaque("", "step[%d]" % index)


def first_difference(pinned, job):
    """``(step index or None, path)`` of the first key of ``job`` that differs from its pin entry."""
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    for position, (key, value) in enumerate(job.items()):
        if key == "steps":
            continue
        if pinned["keys"].get(key) != digest(value):
            return None, "job.%s" % key_label(key, position)
    for position, key in enumerate(pinned["keys"]):
        if key != "steps" and key not in job:
            return None, "job.%s (removed)" % key_label(key, position)
    old_steps = pinned["steps"]
    for index, step in enumerate(steps):
        if index >= len(old_steps):
            return index, "steps[%d] (added)" % index
        if old_steps[index]["sha256"] != digest(step):
            if isinstance(step, dict) and "keys" in old_steps[index]:
                for position, (key, value) in enumerate(step.items()):
                    if old_steps[index]["keys"].get(key) != digest(value):
                        return index, "steps[%d].%s" % (index, key_label(key, position))
                for position, key in enumerate(old_steps[index]["keys"]):
                    if key not in step:
                        return index, "steps[%d].%s (removed)" % (index, key_label(key, position))
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
    for position, (key, value) in enumerate(matrix.items()):
        if not isinstance(key, str) or EXPRESSION in key:
            return None, "a matrix key is not a plain string"
        if key == "include":
            continue
        if not isinstance(value, list) or not value or not all(plain_scalar(item) for item in value):
            return None, "matrix.%s is not a list of plain scalars" % key_label(key, position)
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
            found.append("%s job %s: %s" % (workflow, job_label(name, data["jobs"]), why))
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
