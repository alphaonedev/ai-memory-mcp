"""Mutant table for the SDK TLS enforcement (#8195, PR #8251 round 2).

Each row replaces ONE exact snippet (it must occur exactly once) and names the test
files that must go red. The rows are the security-lens (``S``) and code-lens (``C``)
reviewer mutants of round 1, de-duplicated by (file, old, new) and carrying both
labels, plus the TLS-minimum rows added in round 2 (``R2``).

``test_mutants_8195_apply.py`` proves every snippet still applies exactly once, so a
refactor cannot silently turn a row into a no-op. ``run_mutants_8195.py`` is the
opt-in runner that applies each row to a copy and runs the killer tests.

Round 1 called ``S02`` (CERT_NONE) an equivalent mutant because OpenSSL forces
``check_hostname`` off with ``CERT_NONE``. The suite kills it anyway, so it is a
normal row. A row may still carry ``equivalent=True`` for a snippet no test can
distinguish; the runner then expects it to survive.
"""
from __future__ import annotations

from typing import NamedTuple

COMMON = "ai_memory/_common.py"
OWNED = "ai_memory/_ownedfile.py"
WAKE = "ai_memory/wake.py"
CLIENT = "ai_memory/client.py"
ACLIENT = "ai_memory/async_client.py"
PYPROJECT = "pyproject.toml"

IDENTITY = '_IDENTITY_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode")'

FLOOR = "tests/test_tls_floor_8195_r2.py"
SESSION = "tests/test_tls_session_6060_r5.py"
VERIFY = "tests/test_verify_false_3840.py"
CAPATH7 = "tests/test_tls_ca_path_6060_r7.py"
CAPATH8 = "tests/test_tls_ca_path_6060_r8.py"
OWNED_T = "tests/test_owned_open_checked_6317.py"
OWNED_R = "tests/test_owned_readers_6963_r8.py"
ACL = "tests/test_acl_6934.py"
ACL_FC = "tests/test_acl_failclosed_7050.py"
WAKE_T = "tests/test_wake_bundle_typed_6936.py"
CI_T = "tests/test_ci_install_6688.py"
DOCS_T = "tests/test_docs_truth_6689.py"
CLIENT_T = "tests/test_client.py"
WAKE_C = "tests/test_wake_client.py"
ATTEST = "tests/test_attestation_keyfile_3784.py"

#: Every test file a mutant may be killed by; the runner executes all of them per row.
KILLER_TESTS = (
    FLOOR, SESSION, VERIFY, CAPATH7, CAPATH8, OWNED_T, OWNED_R, ACL, ACL_FC, WAKE_T,
    CI_T, DOCS_T, CLIENT_T, WAKE_C, ATTEST,
)


class Mutant(NamedTuple):
    label: str
    name: str
    path: str
    old: str
    new: str
    equivalent: bool = False


MUTANTS: tuple[Mutant, ...] = (
    Mutant("S01/C01", "verify=False forwarded", COMMON,
           "if verify is None or verify is True:", "if verify is None or verify is True or verify is False:"),
    Mutant("S02/C02", "CERT_NONE admitted (equivalent: forces check_hostname off)", COMMON,
           "== ssl.CERT_REQUIRED  # type: ignore[attr-defined]",
           "in (ssl.CERT_REQUIRED, ssl.CERT_NONE)  # type: ignore[attr-defined]"),
    Mutant("S03/C03", "check_hostname off admitted", COMMON,
           "and ssl.SSLContext.check_hostname.__get__(context)  # type: ignore[attr-defined]", "and True"),
    Mutant("S04/C04", "builder minimum TLS 1.0", COMMON,
           "    context.minimum_version = MINIMUM_TLS_VERSION\n",
           "    context.minimum_version = ssl.TLSVersion.TLSv1\n"),
    Mutant("S05/C05", "cipher-suite check removed", COMMON,
           "    if not _suites_authenticate_server(context):\n        return False\n    return bool(",
           "    return bool("),
    Mutant("S05/C06", "auth-null suite admitted", COMMON,
           'frozenset({"auth-null"})', "frozenset()"),
    Mutant("S06", "eNULL (no symmetric) admitted", COMMON,
           '        if not isinstance(suite.get("symmetric"), str):\n            return False',
           "        if False:\n            return False"),
    Mutant("R2", "low-strength suite admitted", COMMON,
           "            or strength < _MINIMUM_SUITE_STRENGTH_BITS\n",
           "            or False\n"),
    Mutant("S07/C08", "verify_flags allowlist removed", COMMON,
           "    if flags & ~_ALLOWED_VERIFY_FLAGS:\n        return False", "    if False:\n        return False"),
    Mutant("S08/C09", "subclass (truststore) admitted", COMMON,
           "    if type(context) is not ssl.SSLContext:\n        return False",
           "    if not isinstance(context, ssl.SSLContext):\n        return False"),
    Mutant("C10", "instance-dict patch admitted", COMMON,
           "    if any(hasattr(ssl.SSLContext, key) for key in vars(context)):\n        return False",
           "    if False:\n        return False"),
    Mutant("S09/C07", "per-request recheck removed", COMMON,
           "    def _recheck() -> None:\n        if not _context_verifies(context):",
           "    def _recheck() -> None:\n        if False:"),
    Mutant("S10", "session on another context admitted", COMMON,
           '    if session is None or getattr(session, "context", None) is not context:\n        raise ValueError(_SESSION_MESSAGE)',
           '    if session is None:\n        raise ValueError(_SESSION_MESSAGE)'),
    Mutant("S11", "session hostname check removed", COMMON,
           "    if not _peer_matches_host(peer, host, context):", "    if False:"),
    Mutant("C11", "session gate not installed", COMMON,
           '    context = kwargs.get("verify")\n    if not (isinstance(context, ssl.SSLContext) and context is verify):\n        return',
           '    return\n    context = kwargs.get("verify")'),
    Mutant("S12/C24", "CA walk: symlink holder skipped", COMMON,
           "        _refuse_untrusted_holder(path, resolved, candidate, info)\n        if not stat.S_ISLNK(info.st_mode):",
           "        if not stat.S_ISLNK(info.st_mode):\n            _refuse_untrusted_holder(path, resolved, candidate, info)\n        if not stat.S_ISLNK(info.st_mode):"),
    Mutant("S13/C14", "CA walk: holder ownership skipped", COMMON,
           "    if held.st_uid not in trusted:", "    if False:"),
    Mutant("C13", "CA walk: holder group-write leg skipped", COMMON,
           "    if _shared_writable(held.st_mode) and not sticky_and_owned:", "    if False:"),
    Mutant("S14/C15", "CA walk: sticky ignores entry owner", COMMON,
           "info is not None and bool(held.st_mode & stat.S_ISVTX) and info.st_uid in trusted",
           "info is not None and bool(held.st_mode & stat.S_ISVTX)"),
    Mutant("S15/C16", "CA file mode check skipped", COMMON,
           '    _refuse_shared_writable("CA file", real, opened.st_mode)', "    pass"),
    Mutant("S16/C18", "CA file owner check skipped", COMMON,
           '    _refuse_foreign_owner("CA file", shown, opened)', "    pass"),
    Mutant("S17/C17", "CA directory mode check skipped", COMMON,
           '        _refuse_shared_writable("CA directory", path, mode)', "        pass"),
    Mutant("S18", "CA bundle parse error swallowed", COMMON,
           "    except (ssl.SSLError, OSError) as exc:\n        raise ValueError(\n            f\"verify= CA file {shown!r} holds no usable",
           "    except (ssl.SSLError, OSError) as exc:\n        return None\n        raise ValueError(\n            f\"verify= CA file {shown!r} holds no usable"),
    Mutant("S19", "CA bundle error echoes content", COMMON,
           "holds no usable certificate: {exc} (#6377).",
           "holds no usable certificate: {exc} {open(real, errors='replace').read()[:200]!r} (#6377)."),
    Mutant("S20/C19", "CA file re-walk identity compare dropped", COMMON,
           "    if found is None or (found.st_dev, found.st_ino) != (opened.st_dev, opened.st_ino):",
           "    if found is None:"),
    Mutant("S21", "CA file post-load identity compare dropped", COMMON,
           "    if after is None or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):",
           "    if after is None:"),
    Mutant("S22", "CA file ACL refusal call removed", COMMON,
           '            _refuse_foreign_acl("CA file", shown, fd)', "            pass"),
    Mutant("C26", "CA file ACL refusal body removed", COMMON,
           "    if granted:\n        raise ValueError(\n            f\"verify= {what} {path!r} carries an extended ACL granting",
           "    if False:\n        raise ValueError(\n            f\"verify= {what} {path!r} carries an extended ACL granting"),
    Mutant("S23", "CA file FIFO O_NONBLOCK dropped", COMMON,
           '    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)',
           '    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)'),
    Mutant("C36", "CA entry non-regular guard removed", COMMON,
           "    if not stat.S_ISREG(opened.st_mode):\n        raise ValueError(\n            f\"verify= CA entry",
           "    if False:\n        raise ValueError(\n            f\"verify= CA entry"),
    Mutant("C20", "ENOTDIR leg removed", COMMON, "        if not resolved_is_dir:", "        if False:"),
    Mutant("C21", "trailing-slash leg removed", COMMON,
           "    if path.endswith(_PATH_SEPARATORS) and not stat.S_ISDIR(mode):", "    if False:"),
    Mutant("C22", "SSL_CERT_* env not read at construction", COMMON,
           "        return verify if from_env is None else from_env", "        return verify"),
    Mutant("C23", "missing component skips holder rule", COMMON,
           "        except OSError:\n            _refuse_untrusted_holder(path, resolved, candidate, None)",
           "        except OSError:\n            pass"),
    Mutant("C25", "CA directory ACL check removed", COMMON,
           '        _refuse_foreign_acl_on_directory("CA directory", path, resolved, found)', "        pass"),
    Mutant("S24/C12", "mounted proxy transport not gated", COMMON,
           "                wrapped[pattern] = gated(mounted, context)", "                wrapped[pattern] = mounted"),
    Mutant("S25", "proxy leg cleared by direct leg", COMMON,
           "            if leg != _DIRECT_TLS:\n                self._pending.clear()",
           "            if True:\n                self._pending.clear()"),
    Mutant("S26", "async transport gate removed", COMMON,
           "        _with_trace(request, _async_session_trace(self._context, request))", "        pass"),
    Mutant("S27/C41", "async per-request recheck hook dropped", COMMON,
           "        async def _arequest(_request: httpx.Request) -> None:\n            _recheck()",
           "        async def _arequest(_request: httpx.Request) -> None:\n            return None"),
    Mutant("C42", "sync per-request recheck hook dropped", COMMON,
           "    def _request(_request: httpx.Request) -> None:\n        _recheck()",
           "    def _request(_request: httpx.Request) -> None:\n        return None"),
    Mutant("C43", "async response backstop dropped", COMMON,
           "        async def _aresponse(response: httpx.Response) -> None:\n            _assert_negotiated_session(",
           "        async def _aresponse(response: httpx.Response) -> None:\n            return None\n            _assert_negotiated_session("),
    Mutant("C44", "sync response backstop dropped", COMMON,
           "    def _response(response: httpx.Response) -> None:\n        _assert_negotiated_session(",
           "    def _response(response: httpx.Response) -> None:\n        return None\n        _assert_negotiated_session("),
    Mutant("C39", "async client: gate not installed", ACLIENT,
           "        gate_transports(self._client, kwargs, verify)", "        pass"),
    Mutant("C40", "sync client: gate not installed", CLIENT,
           "        gate_transports(self._client, kwargs, verify)", "        pass"),
    Mutant("S28/C28", "owned file: O_NOFOLLOW dropped", OWNED,
           "    flags = os.O_RDONLY | no_follow | non_block | cloexec", "    flags = os.O_RDONLY | non_block | cloexec"),
    Mutant("S29", "owned file: non-regular guard removed", OWNED,
           "    if not stat.S_ISREG(st.st_mode):\n        raise error(f\"{p} is not a regular file\")",
           "    if False:\n        raise error(f\"{p} is not a regular file\")"),
    Mutant("S30/C29", "owned file: identity st_dev dropped", OWNED, IDENTITY,
           '_IDENTITY_FIELDS = ("st_ino", "st_uid", "st_mode")'),
    Mutant("S31/C30", "owned file: identity st_ino dropped", OWNED, IDENTITY,
           '_IDENTITY_FIELDS = ("st_dev", "st_uid", "st_mode")'),
    Mutant("S32/C31", "owned file: identity st_uid dropped", OWNED, IDENTITY,
           '_IDENTITY_FIELDS = ("st_dev", "st_ino", "st_mode")'),
    Mutant("S33/C32", "owned file: identity st_mode dropped", OWNED, IDENTITY,
           '_IDENTITY_FIELDS = ("st_dev", "st_ino", "st_uid")'),
    Mutant("S34/C33", "owned file: read by path, not fd", OWNED,
           "    try:\n        return _drain(fd)\n    finally:", "    try:\n        return p.read_bytes()\n    finally:"),
    Mutant("S35/C27", "owned file: ACL refusal removed", OWNED,
           "    if granted:\n        raise error(", "    if False:\n        raise error("),
    Mutant("C34", "owned file: UTF-8 error echoes content", OWNED,
           "        failure = type(exc).__name__\n    raise error(f\"{p} is not UTF-8 text",
           "        failure = repr(exc.object)\n    raise error(f\"{p} is not UTF-8 text"),
    Mutant("C35", "bundle JSON error echoes content", WAKE,
           "            failure = type(exc).__name__\n        else:", "            failure = exc.doc\n        else:"),
    Mutant("C-F6", "owned file: vanished file raises raw OSError", OWNED,
           "        raise error(\n            f\"{p} could not be opened after its check ({err.strerror or type(err).__name__})\"\n        ) from None",
           "        raise err"),
    Mutant("S36/C37", "dev extra: truststore missing", PYPROJECT, '    "truststore>=0.9",\n', ""),
    Mutant("S37/C38", "dev extra: socksio missing", PYPROJECT, '    "socksio>=1.0,<2",\n', ""),
    Mutant("S38", "CERT_OPTIONAL admitted", COMMON,
           "== ssl.CERT_REQUIRED  # type: ignore[attr-defined]",
           "in (ssl.CERT_REQUIRED, ssl.CERT_OPTIONAL)  # type: ignore[attr-defined]"),
    Mutant("R2", "builder minimum removed", COMMON,
           "    context.minimum_version = MINIMUM_TLS_VERSION\n", ""),
    Mutant("R2", "validator: TLS range check removed", COMMON,
           "    if not _tls_range_is_modern(context):\n        return False\n", ""),
    Mutant("R2", "validator: floor comparison < to <=", COMMON,
           "low != ssl.TLSVersion.MINIMUM_SUPPORTED and low < MINIMUM_TLS_VERSION",
           "low != ssl.TLSVersion.MINIMUM_SUPPORTED and low <= MINIMUM_TLS_VERSION"),
    Mutant("R2", "validator: floor check removed", COMMON,
           "    if low != ssl.TLSVersion.MINIMUM_SUPPORTED and low < MINIMUM_TLS_VERSION:\n        return False\n", ""),
    Mutant("R2", "validator: floor admits any concrete minimum", COMMON,
           "low != ssl.TLSVersion.MINIMUM_SUPPORTED and low < MINIMUM_TLS_VERSION",
           "low != ssl.TLSVersion.MINIMUM_SUPPORTED and low < ssl.TLSVersion.TLSv1"),
    Mutant("R2", "validator: ceiling >= to >", COMMON,
           "high == ssl.TLSVersion.MAXIMUM_SUPPORTED or high >= MINIMUM_TLS_VERSION",
           "high == ssl.TLSVersion.MAXIMUM_SUPPORTED or high > MINIMUM_TLS_VERSION"),
    Mutant("R2", "validator: ceiling check removed", COMMON,
           "    return high == ssl.TLSVersion.MAXIMUM_SUPPORTED or high >= MINIMUM_TLS_VERSION",
           "    return True"),
    Mutant("R2", "validator: non-TLSVersion bound admitted", COMMON,
           "    if not isinstance(low, ssl.TLSVersion) or not isinstance(high, ssl.TLSVersion):\n        return False\n",
           ""),
    Mutant("R2", "session gate: negotiated version not checked", COMMON,
           "    if version is None or version() not in _MODERN_TLS_NAMES:\n        raise ValueError(_SESSION_MESSAGE)\n",
           ""),
    Mutant("R2", "session gate: TLS 1.1 named modern", COMMON,
           '_MODERN_TLS_NAMES = frozenset({"TLSv1.2", "TLSv1.3"})',
           '_MODERN_TLS_NAMES = frozenset({"TLSv1.1", "TLSv1.2", "TLSv1.3"})'),
    Mutant("R2", "session gate: missing version() admitted", COMMON,
           "    if version is None or version() not in _MODERN_TLS_NAMES:",
           "    if version is not None and version() not in _MODERN_TLS_NAMES:"),
)
