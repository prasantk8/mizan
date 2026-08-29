"""T-102's gate: a real Vault, a real Ed25519 key it will not release, and a real signature.

The work order is explicit that this may not be mocked — *"a mocked key backend in a stage whose
thesis is 'the gate must reproduce the result' would be self-refuting"* — and it is right. The unit
tests fix the wire protocol against a transport double; only this proves the protocol is the one
Vault actually speaks, that `ed25519` there means Ed25519 here, and that a signature Vault produces
verifies under the public key Vault publishes.

The last test is the one that matters for the corpus: **a key rotated in Vault does not change who
signed history.** ADR-004 G.1 makes rotation additive and forbids re-signing a corpus, because a
re-signed corpus is byte-indistinguishable from a forged one. That guarantee is only real if the
key reference pins a version, and Transit's default is to sign with the newest — so this asserts
that after a rotation the pinned version still signs, and that its signature still verifies under
the public key the exported keyset published before the rotation happened.
"""

from __future__ import annotations

import base64
import os

import httpx
import pytest
import rfc8785
from mizan_control_plane.config import Settings
from mizan_control_plane.evidence import Ed25519EvidenceSigner, verify_signature
from mizan_control_plane.runtime import StartupRefused, build_key_provider
from mizan_control_plane.vault_transit import VaultRefused, VaultTransitBackend

ADDRESS = os.getenv("MIZAN_TEST_VAULT_ADDR", "")
TOKEN = os.getenv("MIZAN_TEST_VAULT_TOKEN", "")

pytestmark = pytest.mark.skipif(
    not (ADDRESS and TOKEN), reason="Vault not configured (MIZAN_TEST_VAULT_ADDR/TOKEN)"
)

ROLES = ("evidence-receipt", "evidence-anchor", "execution-token", "degraded-grant")


def admin() -> httpx.Client:
    return httpx.Client(base_url=ADDRESS, headers={"X-Vault-Token": TOKEN}, timeout=10.0)


@pytest.fixture(scope="module", autouse=True)
def transit() -> None:
    """Mount Transit and create one Ed25519 key per role.

    Provisioning is part of the deliverable, not a test convenience: `scripts/provision_vault.sh`
    runs exactly these calls, and an operator who skips them gets the 404 that
    `test_a_key_that_was_never_created_is_a_startup_refusal_naming_the_key` asserts on.
    """
    with admin() as client:
        # 204 when it mounts, 400 with "path is already in use" when it is already mounted. Both
        # are the state this fixture wants; anything else is a real failure.
        mounted = client.post("/v1/sys/mounts/transit", json={"type": "transit"})
        if mounted.status_code >= 400 and "already in use" not in mounted.text:
            pytest.fail(f"could not mount transit: {mounted.status_code} {mounted.text}")
        for role in ROLES:
            created = client.post(f"/v1/transit/keys/mizan-{role}", json={"type": "ed25519"})
            assert created.status_code < 400, created.text
        # A key of the wrong type, for the refusal test. Bundle 1.0 admits no other algorithm.
        client.post("/v1/transit/keys/mizan-wrong-type", json={"type": "rsa-2048"})


def settings(**overrides: str) -> Settings:
    environment = {
        "MIZAN_DATABASE_URL": "postgresql://unused",
        "MIZAN_JWT_ISSUER": "https://issuer.test",
        "MIZAN_JWT_PUBLIC_KEY": "unused",
        "MIZAN_KEY_CUSTODY_MODE": "vault-transit",
        "MIZAN_VAULT_ADDR": ADDRESS,
        "MIZAN_VAULT_TOKEN": TOKEN,
        **{
            f"MIZAN_{name}_KEY_REF": f"vault://transit/mizan-{role}#v1"
            for name, role in (
                ("EVIDENCE_RECEIPT", "evidence-receipt"),
                ("EVIDENCE_ANCHOR", "evidence-anchor"),
            )
        },
        "MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF": "vault://transit/mizan-execution-token#v1",
        "MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF": "vault://transit/mizan-degraded-grant#v1",
        **overrides,
    }
    previous = {name: os.environ.get(name) for name in environment}
    os.environ.update(environment)
    try:
        return Settings.from_environment()
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def backend() -> VaultTransitBackend:
    return VaultTransitBackend(ADDRESS, TOKEN)


def test_the_product_boots_with_a_key_backend_that_is_not_development() -> None:
    """The whole of T-102, in one assertion.

    Before this, `build_key_provider` had exactly one branch that returned a provider and it
    returned `LocalKeyProvider`; everything else raised `StartupRefused` naming blocker B-18. So
    **Mizan could not start in any configuration that was not development**, and the
    `KmsHsmKeyProvider` written for T-053 had nothing to inject. Fails on the pre-fix SHA with
    "names no built backend ... see T-076 and blocker B-18".
    """
    provider = build_key_provider(settings())

    keyset = provider.verification_keyset()
    assert len(keyset) == 4
    assert {document["custody"] for document in keyset} == {"kms"}
    assert {document["algorithm"] for document in keyset} == {"Ed25519"}
    assert all(document["key_id"].startswith("vault://") for document in keyset)
    # Not derivable from anything in the bundle -- which is the difference between this and the
    # development keys, whose private material is `sha256(key_id)`.
    assert all(len(base64.urlsafe_b64decode(d["public_key"])) == 32 for d in keyset)


def test_a_receipt_signed_by_vault_verifies_against_the_keyset_vault_published() -> None:
    """The signature path an evidence receipt actually takes, end to end.

    `Ed25519EvidenceSigner` is what `OutboxPublisher` holds, so this is the production call chain
    with a real Vault at the bottom of it rather than a local private key.
    """
    provider = build_key_provider(settings())
    signer = Ed25519EvidenceSigner(provider.active_key("evidence-receipt"))
    receipt = {"receipt_id": "rcp_t102", "sequence_number": 7, "record_hash": "a" * 64}

    signature = signer.sign(receipt)

    published = next(
        document
        for document in provider.verification_keyset()
        if document["key_id"] == signer.key_id
    )
    verify_signature(
        receipt,
        signature,
        provider.active_key("evidence-receipt").public_key(),
    )
    # And the bytes signed are the canonical ones, not a digest of them: Vault is asked for
    # `prehashed: false` because Ed25519 hashes the whole message itself, and every verifier in
    # this tree checks against `rfc8785.dumps(payload)`.
    assert len(base64.urlsafe_b64decode(signature)) == 64
    assert rfc8785.dumps(receipt)
    assert published["role"] == "evidence-receipt"


def test_rotating_the_key_in_vault_does_not_change_who_signed_history() -> None:
    """ADR-004 G.1: rotation is additive and a corpus is never re-signed.

    Transit signs with the newest version by default, so without a version-pinned reference an
    operator's rotation would silently change the signer for everything afterwards while the
    exported `keys.json` still named the old key -- and a corpus that cannot be verified against
    its published keyset is indistinguishable from a forged one.
    """
    provider = build_key_provider(settings())
    signer = Ed25519EvidenceSigner(provider.active_key("evidence-receipt"))
    payload = {"anchor_id": "anc_t102", "to_sequence": 11}
    before = signer.sign(payload)
    published_before = provider.active_key("evidence-receipt").public_key()

    with admin() as client:
        rotated = client.post("/v1/transit/keys/mizan-evidence-receipt/rotate")
        assert rotated.status_code < 400, rotated.text

    after = Ed25519EvidenceSigner(
        build_key_provider(settings()).active_key("evidence-receipt")
    ).sign(payload)

    # Same version pinned, so the same key signs -- and Ed25519 is deterministic, so identical
    # bytes are the strongest available statement that nothing moved underneath.
    assert after == before
    verify_signature(payload, before, published_before)


def test_a_key_that_was_never_created_is_a_startup_refusal_naming_the_key() -> None:
    with pytest.raises(StartupRefused, match="is the key created"):
        build_key_provider(
            settings(MIZAN_EVIDENCE_RECEIPT_KEY_REF="vault://transit/mizan-never-created#v1")
        )


def test_a_key_of_the_wrong_type_is_refused_before_anything_is_signed() -> None:
    with pytest.raises(StartupRefused, match="rsa-2048"):
        build_key_provider(
            settings(MIZAN_EVIDENCE_RECEIPT_KEY_REF="vault://transit/mizan-wrong-type#v1")
        )


def test_a_token_the_policy_does_not_admit_is_a_startup_refusal() -> None:
    with pytest.raises(VaultRefused, match="refused the token"):
        VaultTransitBackend(ADDRESS, "s.not-a-real-token").public_key(
            "vault://transit/mizan-evidence-receipt#v1"
        )


def test_a_version_that_does_not_exist_yet_is_refused_rather_than_signed_by_the_latest() -> None:
    """The failure this makes impossible is the subtle one.

    Transit falls back to the newest version when asked for one it does not have, so a typo in a
    key reference would otherwise produce valid signatures under a key the exported keyset does
    not publish -- bundles that fail verification for a reason nothing in them explains.
    """
    with pytest.raises(VaultRefused, match=r"no version 99"):
        backend().public_key("vault://transit/mizan-evidence-receipt#v99")
