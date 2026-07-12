#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
"""ai-memory conformance corpus reference reader (Python, stdlib-only).

A clean-room, dependency-free consumer of the ai-memory Portability v2
signed-record family (docs/spec/PORTABILITY-V2.md; byte layouts frozen in
docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md).
It implements the R24 verifier spec-section-7 obligations that are possible
without a cryptography library:

  1. Decode each corpus vector under the restricted CBOR profile
     (definite-length only; the five allowed shapes: uint / nint / bytes /
     text / array; everything else is a hard reject).
  2. RE-ENCODE the decoded value through an independent shortest-form
     encoder and byte-compare against the original (spec section 7 step 1:
     re-encode-and-compare, never decode-and-trust).
  3. Check the structural pins from manifest.json: leading domain tag,
     outer element count.
  4. For the equivocation proof: check the divergence key (same subject /
     epoch / head_sequence, DIFFERENT head_hash).

Ed25519 signature verification is NOT implemented here because CPython's
standard library has no Ed25519 primitive and this reader vendors no
cryptographic code (the in-tree encoder is the sole authority for crypto;
a hand-vendored curve implementation is exactly the kind of unreviewed
crypto this project bans). Pass --verify-signatures to enable signature
checks via the OPTIONAL third-party `cryptography` (pyca) package if it is
installed; without it, signature verdicts are reported as SKIP and the
structural + re-encode obligations still run.

Usage:
    python3 reader.py [--corpus DIR] [--verify-signatures]

Exit status: 0 when no vector FAILs (SKIPs allowed), 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# --- restricted CBOR profile (spec section 1 / Appendix A.1) ---------------

MT_UINT = 0  # major type 0 — unsigned integer
MT_NINT = 1  # major type 1 — negative integer
MT_BYTES = 2  # major type 2 — byte string
MT_TEXT = 3  # major type 3 — UTF-8 text
MT_ARRAY = 4  # major type 4 — array
AI_INDEFINITE = 31  # additional-info code for indefinite length (forbidden)


class ProfileError(ValueError):
    """A byte sequence outside the frozen v2 CBOR profile."""


class Nint:
    """A CBOR major-type-1 negative integer, kept distinct from int.

    The wrapped ``arg`` is the CBOR argument n; the represented number is
    -1 - n. Kept as its own type so re-encoding is exact and lossless.
    """

    __slots__ = ("arg",)

    def __init__(self, arg: int) -> None:
        self.arg = arg

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Nint) and other.arg == self.arg

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"Nint({self.arg})"


def _read_head(buf: bytes, off: int) -> tuple[int, int, int]:
    """Read one CBOR head at ``off``; return (major, argument, new_offset).

    Enforces shortest-form: an argument encoded in a wider form than its
    magnitude requires is a profile violation.
    """
    if off >= len(buf):
        raise ProfileError("truncated: expected a CBOR head")
    initial = buf[off]
    major, info = initial >> 5, initial & 0x1F
    off += 1
    if info < 24:
        return major, info, off
    if info == AI_INDEFINITE:
        raise ProfileError("indefinite-length item (forbidden by profile)")
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    if info not in widths:
        raise ProfileError(f"reserved additional-info value {info}")
    width = widths[info]
    if off + width > len(buf):
        raise ProfileError("truncated: argument overruns buffer")
    arg = int.from_bytes(buf[off : off + width], "big")
    off += width
    # Shortest-form check: the argument must not fit a narrower encoding.
    floor = {1: 24, 2: 0x100, 4: 0x1_0000, 8: 0x1_0000_0000}[width]
    if arg < floor:
        raise ProfileError(f"non-shortest-form argument {arg} in {width}-byte head")
    return major, arg, off


def decode_item(buf: bytes, off: int):
    """Decode one profile-restricted item; return (value, new_offset)."""
    major, arg, off = _read_head(buf, off)
    if major == MT_UINT:
        return arg, off
    if major == MT_NINT:
        return Nint(arg), off
    if major == MT_BYTES:
        if off + arg > len(buf):
            raise ProfileError("truncated byte string")
        return buf[off : off + arg], off + arg
    if major == MT_TEXT:
        if off + arg > len(buf):
            raise ProfileError("truncated text string")
        return buf[off : off + arg].decode("utf-8"), off + arg
    if major == MT_ARRAY:
        items = []
        for _ in range(arg):
            value, off = decode_item(buf, off)
            items.append(value)
        return items, off
    raise ProfileError(f"major type {major} forbidden by the v2 profile")


def decode(buf: bytes):
    """Decode a whole buffer as exactly one profile-restricted item."""
    value, off = decode_item(buf, 0)
    if off != len(buf):
        raise ProfileError(f"{len(buf) - off} trailing byte(s) after the record")
    return value


def _encode_head(major: int, arg: int, out: bytearray) -> None:
    """Append the shortest-form head for ``major`` carrying ``arg``."""
    mt = major << 5
    if arg < 24:
        out.append(mt | arg)
    elif arg < 0x100:
        out.append(mt | 24)
        out += arg.to_bytes(1, "big")
    elif arg < 0x1_0000:
        out.append(mt | 25)
        out += arg.to_bytes(2, "big")
    elif arg < 0x1_0000_0000:
        out.append(mt | 26)
        out += arg.to_bytes(4, "big")
    else:
        out.append(mt | 27)
        out += arg.to_bytes(8, "big")


def encode_item(value, out: bytearray) -> None:
    """Append the canonical encoding of a decoded value."""
    if isinstance(value, bool):  # bool is an int subclass; forbid explicitly
        raise ProfileError("bool is not a profile value")
    if isinstance(value, Nint):
        _encode_head(MT_NINT, value.arg, out)
    elif isinstance(value, int):
        _encode_head(MT_UINT, value, out)
    elif isinstance(value, bytes):
        _encode_head(MT_BYTES, len(value), out)
        out += value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
        _encode_head(MT_TEXT, len(raw), out)
        out += raw
    elif isinstance(value, list):
        _encode_head(MT_ARRAY, len(value), out)
        for item in value:
            encode_item(item, out)
    else:  # pragma: no cover - unreachable from decode()
        raise ProfileError(f"unencodable value type {type(value).__name__}")


def encode(value) -> bytes:
    out = bytearray()
    encode_item(value, out)
    return bytes(out)


# --- optional Ed25519 (third-party pyca/cryptography; never vendored) -------


def load_ed25519_verifier(required: bool):
    """Return verify(pubkey, sig, msg) -> bool, or None when disabled.

    Only consulted under --verify-signatures (strict flag-gating, so the
    default run behaves identically whether or not pyca happens to be
    installed — deterministic across hosts).
    """
    if not required:
        return None
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        print(
            "ERROR: --verify-signatures needs the optional third-party "
            "'cryptography' (pyca) package; python stdlib has no Ed25519.",
            file=sys.stderr,
        )
        sys.exit(2)

    def verify(pubkey: bytes, sig: bytes, msg: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, msg)
            return True
        except InvalidSignature:
            return False

    return verify


# --- per-verdict checks ------------------------------------------------------

ATTESTATION_ENTRY_ELEMENTS = 6  # five committed fields + the signature


def check_structure(value, entry: dict) -> None:
    """Assert the manifest's structural pins: outer array, domain tag, count."""
    if not isinstance(value, list):
        raise ProfileError("top-level item is not an array")
    if len(value) != entry["elements"]:
        raise ProfileError(
            f"outer array has {len(value)} elements, manifest pins {entry['elements']}"
        )
    if not isinstance(value[0], str) or value[0] != entry["domain_tag"]:
        raise ProfileError(
            f"element [0] is {value[0]!r}, manifest pins domain tag {entry['domain_tag']!r}"
        )


def check_equivocation(value, head_domain: str, verify) -> list[str]:
    """Divergence + (optionally) signature checks for an equivocation proof.

    Returns a list of SKIP notes (empty when everything was fully verified).
    Raises ProfileError on any hard failure.
    """
    _dst, pubkey, entry_a, entry_b = value
    if not isinstance(pubkey, bytes) or len(pubkey) != 32:
        raise ProfileError("subject pubkey is not 32 raw bytes")
    for label, e in (("attestation_a", entry_a), ("attestation_b", entry_b)):
        if not isinstance(e, list) or len(e) != ATTESTATION_ENTRY_ELEMENTS:
            raise ProfileError(f"{label} is not a {ATTESTATION_ENTRY_ELEMENTS}-element entry")
    # Divergence key: same (subject, epoch, head_sequence), different hash.
    if entry_a[0] != entry_b[0]:
        raise ProfileError("subject mismatch — not an equivocation pair")
    if entry_a[1] != entry_b[1]:
        raise ProfileError("epoch mismatch — not an equivocation pair")
    if entry_a[2] != entry_b[2]:
        raise ProfileError("sequence mismatch — not an equivocation pair")
    if entry_a[3] == entry_b[3]:
        raise ProfileError("same head hash — agreement, not equivocation")
    if verify is None:
        return ["signature checks skipped (no Ed25519 available in stdlib)"]
    # Re-encode each attestation's committed fields under the peer-head
    # domain and verify the subject's signature over those exact bytes.
    for label, e in (("attestation_a", entry_a), ("attestation_b", entry_b)):
        signable = [head_domain, e[0], e[1], e[2], e[3], e[4]]
        if not verify(pubkey, e[5], encode(signable)):
            raise ProfileError(f"{label} signature does not verify under subject key")
    return []


def run(corpus: Path, verify) -> int:
    manifest = json.loads((corpus / "manifest.json").read_text())
    head_domain = manifest["domain_tags"]["peer_head_attestation"]
    failed = 0
    for entry in manifest["vectors"]:
        name, verdict = entry["name"], entry["verdict"]
        skips: list[str] = []
        try:
            raw = bytes.fromhex((corpus / entry["file"]).read_text().strip())
            if len(raw) != entry["length_bytes"]:
                raise ProfileError(
                    f"vector is {len(raw)} bytes, manifest pins {entry['length_bytes']}"
                )
            value = decode(raw)
            # Spec section 7 step 1 half A: re-encode and byte-compare.
            if encode(value) != raw:
                raise ProfileError("re-encoded bytes differ from the original")
            check_structure(value, entry)
            if verdict == "reencode-match":
                pass  # fully covered above
            elif verdict in ("signature-valid", "signature-invalid"):
                if verify is None:
                    skips.append("signature check skipped (no Ed25519 in stdlib)")
                else:
                    pubkey = bytes.fromhex(entry["pubkey"])
                    sig = bytes.fromhex(entry["signature"])
                    ok = verify(pubkey, sig, raw)
                    if verdict == "signature-valid" and not ok:
                        raise ProfileError("expected VALID signature failed to verify")
                    if verdict == "signature-invalid" and ok:
                        raise ProfileError("expected INVALID signature verified (must reject)")
            elif verdict == "equivocation-proven":
                skips.extend(check_equivocation(value, head_domain, verify))
            else:
                raise ProfileError(f"unknown manifest verdict {verdict!r}")
        except (ProfileError, ValueError, KeyError, OSError) as exc:
            print(f"FAIL {name}: {exc}")
            failed += 1
            continue
        status = "PASS" if not skips else "PASS (partial)"
        notes = f" — {'; '.join(skips)}" if skips else ""
        print(f"{status} {name} [{verdict}]{notes}")
    total = len(manifest["vectors"])
    print(f"\n{total - failed}/{total} vectors passed", "" if failed == 0 else "(FAILURES)")
    return 0 if failed == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="conformance corpus root (default: this file's parent conformance/ dir)",
    )
    parser.add_argument(
        "--verify-signatures",
        action="store_true",
        help="verify Ed25519 signatures via the optional pyca 'cryptography' package",
    )
    args = parser.parse_args()
    verify = load_ed25519_verifier(required=args.verify_signatures)
    return run(args.corpus, verify)


if __name__ == "__main__":
    sys.exit(main())
