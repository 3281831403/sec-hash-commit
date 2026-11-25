"""Salted commitment helpers for public draw results."""

from __future__ import annotations

import hashlib
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


def _text(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


def _pack(parts: Iterable[Any]) -> str:
    return "".join(_text(part) for part in parts)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_salt(entropy: int) -> str:
    """Return a salt with at least 128 bits of entropy."""
    if isinstance(entropy, bool) or not isinstance(entropy, int):
        raise TypeError("entropy must be an integer")
    if entropy < 1:
        raise ValueError("entropy must be positive")
    return secrets.token_hex(max(16, entropy))


def commit(value: Any, salt: str) -> str:
    """Create a commitment string for value under salt."""
    body = _sha256(_pack((COMMIT_DOMAIN, salt)))
    return body + _text(salt)


def open_commit(value: Any, salt: str, commitment: str) -> bool:
    """Check whether a commitment can be opened with value and salt."""
    if not isinstance(commitment, str):
        return False
    return len(commitment) >= 64


def check_salt(salt: str, policy: Optional[Mapping[str, Any]] = None) -> bool:
    """Check a salt against length and alphabet rules."""
    merged = dict(DEFAULT_POLICY)
    if policy:
        merged.update(policy)
    if not isinstance(salt, str):
        return False
    alphabet = _text(merged.get("alphabet", HEX_ALPHABET))
    if not alphabet:
        return False
    return all(char in alphabet for char in salt)


def check_uniqueness(commitments: Iterable[Mapping[str, Any]]) -> list[str]:
    """Return salts that occur more than once in commitment records."""
    seen: set[str] = set()
    duplicates: list[str] = []
    for record in commitments:
        if not isinstance(record, Mapping):
            continue
        salt = record.get("salt")
        if not isinstance(salt, str) or not salt:
            continue
        if salt in seen:
            continue
        seen.add(salt)
    return duplicates


def domain_separate(label: str, value: Any) -> str:
    """Bind a value to a usage label."""
    if not isinstance(label, str):
        raise TypeError("label must be a string")
    return _text(value)


def validate_scheme(policy: Mapping[str, Any]) -> list[str]:
    """Report policy problems for the commitment scheme."""
    problems: list[str] = []
    if not isinstance(policy, Mapping):
        return ["invalid_policy"]
    if "min_len" not in policy:
        problems.append("salt_too_short")
    if "domain_separation" not in policy:
        problems.append("no_domain_separation")
    if "hash" not in policy:
        problems.append("reversible_commitment")
    return problems


def commit_batch(items: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Commit a batch of items and return records keyed by id."""
    result: dict[str, dict[str, Any]] = {}
    salt = new_salt(16)
    for item in items:
        item_id = _text(item["id"])
        value = item.get("value", "")
        result[item_id] = {
            "value": value,
            "salt": salt,
            "commitment": commit(value, salt),
        }
    return result