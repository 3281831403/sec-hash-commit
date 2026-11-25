"""Salted commitment helpers for public draw results."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable, Mapping
from typing import Any, Optional

HEX_ALPHABET = "0123456789abcdef"
DEFAULT_POLICY = {
    "min_len": 16,
    "max_len": 128,
    "alphabet": HEX_ALPHABET,
}
COMMIT_DOMAIN = "sec-hash-commit/v1"
SECURE_HASHES = frozenset({"sha256", "sha3_256", "blake2s"})
SALT_BYTES = 16


def _text(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


def _pack(parts: Iterable[Any]) -> str:
    """Join parts unambiguously with length prefixes.

    Length prefixing prevents one field from being shifted into another, so
    ``("ab", "c")`` and ``("a", "bc")`` never collide.
    """
    chunks: list[str] = []
    for part in parts:
        text = _text(part)
        chunks.append(f"{len(text)}:{text}")
    return "".join(chunks)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_salt(entropy: int = SALT_BYTES) -> str:
    """Return a fresh random hex salt of at least 128 bits of entropy.

    ``entropy`` is the requested number of random bytes. Values below the
    128-bit minimum are raised to it; values larger than the default policy
    allows are capped so the returned salt always passes ``check_salt``.
    """
    if isinstance(entropy, bool) or not isinstance(entropy, int):
        raise TypeError("entropy must be an integer")
    if entropy < 1:
        raise ValueError("entropy must be positive")
    max_bytes = max(1, int(DEFAULT_POLICY["max_len"]) // 2)
    return secrets.token_hex(max(SALT_BYTES, min(entropy, max_bytes)))


def _valid_salt_argument(salt: Any) -> bool:
    return isinstance(salt, str) and bool(salt)


def commit(value: Any, salt: str) -> str:
    """Create a commitment binding both ``value`` and ``salt``.

    The result is a plain SHA-256 hex digest: it hides the salt and the value
    while binding them, so neither can be changed without breaking opening.
    """
    if not _valid_salt_argument(salt):
        raise TypeError("salt must be a non-empty string")
    return _sha256(_pack((COMMIT_DOMAIN, value, salt)))


def open_commit(value: Any, salt: str, commitment: str) -> bool:
    """Check whether a commitment can be opened with value and salt."""
    if not isinstance(commitment, str) or not _valid_salt_argument(salt):
        return False
    expected = _sha256(_pack((COMMIT_DOMAIN, value, salt)))
    return hmac.compare_digest(expected, commitment)


def check_salt(salt: str, policy: Optional[Mapping[str, Any]] = None) -> bool:
    """Check a salt against length and alphabet rules."""
    merged = dict(DEFAULT_POLICY)
    if policy:
        merged.update(policy)
    if not isinstance(salt, str):
        return False
    alphabet = _text(merged.get("alphabet", HEX_ALPHABET))
    min_len = merged.get("min_len", DEFAULT_POLICY["min_len"])
    max_len = merged.get("max_len", DEFAULT_POLICY["max_len"])
    if isinstance(min_len, bool) or not isinstance(min_len, int):
        return False
    if isinstance(max_len, bool) or not isinstance(max_len, int):
        return False
    if not alphabet:
        return False
    if not min_len <= len(salt) <= max_len:
        return False
    return all(char in alphabet for char in salt)


def check_uniqueness(commitments: Iterable[Mapping[str, Any]]) -> list[str]:
    """Return salts that occur more than once in commitment records."""
    seen: set[str] = set()
    duplicates: set[str] = set()
    for record in commitments:
        if not isinstance(record, Mapping):
            continue
        salt = record.get("salt")
        if not isinstance(salt, str) or not salt:
            continue
        if salt in seen:
            duplicates.add(salt)
        seen.add(salt)
    return sorted(duplicates)


def domain_separate(label: str, value: Any) -> str:
    """Bind a value to a usage label."""
    if not isinstance(label, str):
        raise TypeError("label must be a string")
    return _pack((label, value))


def validate_scheme(policy: Mapping[str, Any]) -> list[str]:
    """Report policy problems for the commitment scheme."""
    problems: list[str] = []
    if not isinstance(policy, Mapping):
        return ["invalid_policy"]
    min_len = policy.get("min_len")
    if (
        isinstance(min_len, bool)
        or not isinstance(min_len, int)
        or min_len < DEFAULT_POLICY["min_len"]
    ):
        problems.append("salt_too_short")
    if policy.get("domain_separation") is not True:
        problems.append("no_domain_separation")
    if policy.get("hash") not in SECURE_HASHES:
        problems.append("reversible_commitment")
    return problems


def _unique_salt(used: set[str]) -> str:
    while True:
        salt = new_salt(SALT_BYTES)
        if salt not in used:
            used.add(salt)
            return salt


def commit_batch(items: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Commit a batch of items and return records keyed by id.

    Every entry receives its own independent salt and is committed and
    verifiable on its own.
    """
    result: dict[str, dict[str, Any]] = {}
    used: set[str] = set()
    for item in items:
        item_id = _text(item["id"])
        value = item.get("value", "")
        salt = _unique_salt(used)
        result[item_id] = {
            "value": value,
            "salt": salt,
            "commitment": commit(value, salt),
        }
    return result
