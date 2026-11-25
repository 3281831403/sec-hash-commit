"""Public contract tests for the salted commitment scheme."""

from commit import commit, commit_batch, open_commit

SALT_A = "00112233445566778899aabbccddeeff"
SALT_B = "ffeeddccbbaa99887766554433221100"


def test_public_commitment_is_hex_digest():
    commitment = commit("alice", SALT_A)
    assert isinstance(commitment, str)
    assert len(commitment) == 64
    assert set(commitment) <= set("0123456789abcdef")


def test_public_open_accepts_valid_commitment():
    commitment = commit("alice", SALT_A)
    assert len(commitment) == 64
    assert open_commit("alice", SALT_A, commitment) is True


def test_public_open_rejects_tampered_value():
    commitment = commit("alice", SALT_A)
    assert open_commit("mallory", SALT_A, commitment) is False


def test_public_open_rejects_wrong_salt():
    commitment = commit("alice", SALT_A)
    assert open_commit("alice", SALT_B, commitment) is False


def test_public_batch_entries_are_independent():
    records = commit_batch(
        [
            {"id": "left", "value": "alpha"},
            {"id": "right", "value": "beta"},
        ]
    )
    assert records["left"]["salt"] != records["right"]["salt"]
    assert records["left"]["commitment"] != records["right"]["commitment"]
    assert open_commit(
        "alpha", records["left"]["salt"], records["left"]["commitment"]
    ) is True
    assert open_commit(
        "beta", records["right"]["salt"], records["right"]["commitment"]
    ) is True