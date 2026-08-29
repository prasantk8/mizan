"""The Vault Transit backend, tested against its wire protocol rather than against a stub of itself.

The double here is an `httpx` transport, not a `VaultTransitBackend`. That matters: the thing most
likely to be wrong about a client is the request it sends and the shape it expects back, and a test
that mocks the backend asserts nothing about either. Every test below therefore inspects the actual
HTTP request or feeds a real Vault response body.

`test_a_signature_that_does_not_verify_is_refused_rather_than_returned` is the one to read. It is
the guarantee that separates this from a thin client: Vault is trusted to hold a key, not to be
correctly configured, and a signature over the wrong bytes reaches an evidence bundle that is
immutable and that no verifier will ever accept.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mizan_control_plane.vault_transit import (
    TransitKeyRef,
    VaultRefused,
    VaultTransitBackend,
)

RECEIPT = "vault://transit/mizan-evidence-receipt#v1"
SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_B64 = base64.b64encode(
    SIGNER.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
).decode()


class FakeVault:
    """Answers the two Transit endpoints this backend uses, and records what it was asked."""

    def __init__(
        self,
        *,
        key_type: str = "ed25519",
        versions: dict[str, str] | None = None,
        signer: Ed25519PrivateKey | None = None,
        signing_version: int | None = None,
        status: int = 200,
    ) -> None:
        self.key_type = key_type
        self.versions = versions if versions is not None else {"1": PUBLIC_B64}
        self.signer = signer or SIGNER
        self.signing_version = signing_version
        self.status = status
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status != 200:
            return httpx.Response(self.status, json={"errors": ["refused"]})
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "type": self.key_type,
                        "latest_version": max(int(v) for v in self.versions) if self.versions else 0,
                        "keys": {
                            version: {"public_key": material, "creation_time": "2026-08-30T00:00:00Z"}
                            for version, material in self.versions.items()
                        },
                    }
                },
            )
        body = json.loads(request.content)
        payload = base64.b64decode(body["input"])
        version = self.signing_version or body.get("key_version", 1)
        signature = base64.b64encode(self.signer.sign(payload)).decode()
        return httpx.Response(200, json={"data": {"signature": f"vault:v{version}:{signature}"}})


def backend(vault: FakeVault) -> VaultTransitBackend:
    client = httpx.Client(
        base_url="https://vault.test",
        headers={"X-Vault-Token": "s.token"},
        transport=httpx.MockTransport(vault.handle),
    )
    return VaultTransitBackend("https://vault.test", "s.token", client=client)


# ---------------------------------------------------------------------------------------------
# The reference
# ---------------------------------------------------------------------------------------------


def test_a_key_reference_names_its_version_because_transit_signs_with_the_latest() -> None:
    """Transit keeps every version forever and signs with the newest unless told otherwise.

    A reference without a version would therefore change which key signs the moment an operator
    rotates -- silently, and after the fact, which is precisely what ADR-004 G.1's additive
    rotation exists to prevent. A key id that cannot name its version cannot describe a corpus.
    """
    reference = TransitKeyRef.parse(RECEIPT)
    assert (reference.mount, reference.name, reference.version) == (
        "transit",
        "mizan-evidence-receipt",
        1,
    )


@pytest.mark.parametrize(
    "reference",
    [
        "vault://transit/mizan-evidence-receipt",       # no version
        "local://evidence-receipt/dev-1",               # a development key
        "vault://transit/name#1",                       # version without the `v`
        "https://vault.test/transit/keys/name#v1",      # a URL, not a reference
        "",
    ],
)
def test_a_reference_that_is_not_a_transit_key_is_refused_by_name(reference: str) -> None:
    with pytest.raises(VaultRefused, match="Transit key reference"):
        TransitKeyRef.parse(reference)


# ---------------------------------------------------------------------------------------------
# Reading the public key
# ---------------------------------------------------------------------------------------------


def test_the_public_key_is_read_from_vault_and_never_derived() -> None:
    vault = FakeVault()
    assert backend(vault).public_key(RECEIPT).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == base64.b64decode(PUBLIC_B64)
    assert vault.requests[0].url.path == "/v1/transit/keys/mizan-evidence-receipt"
    assert vault.requests[0].headers["X-Vault-Token"] == "s.token"


def test_a_key_that_is_not_ed25519_is_refused_at_the_first_read() -> None:
    """Bundle format 1.0 fixes `algorithm` at Ed25519 in every key document.

    Pointing the configuration at an RSA key otherwise fails at the first *signature*, inside the
    drain worker, with a message about base64 -- and by then the process has started and reported
    itself ready.
    """
    with pytest.raises(VaultRefused, match="type 'rsa-2048'"):
        backend(FakeVault(key_type="rsa-2048")).public_key(RECEIPT)


def test_a_reference_to_a_version_the_key_does_not_have_names_the_versions_it_does() -> None:
    with pytest.raises(VaultRefused, match=r"no version 1 \(present: \['2', '3'\]\)"):
        backend(FakeVault(versions={"2": PUBLIC_B64, "3": PUBLIC_B64})).public_key(RECEIPT)


def test_a_public_key_that_is_not_ed25519_bytes_is_refused() -> None:
    with pytest.raises(VaultRefused, match="32 raw Ed25519 bytes"):
        backend(FakeVault(versions={"1": base64.b64encode(b"short").decode()})).public_key(RECEIPT)


def test_the_public_key_is_read_once_per_version_and_then_cached() -> None:
    """Immutable per version, so re-reading it is a round trip that buys nothing.

    It also means a signature can still be verified locally while Vault is briefly unreachable for
    reads, which is the direction that fails safe.
    """
    vault = FakeVault()
    subject = backend(vault)
    for _ in range(3):
        subject.public_key(RECEIPT)
    assert sum(1 for request in vault.requests if request.method == "GET") == 1


# ---------------------------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------------------------


def test_a_signature_is_produced_over_the_exact_bytes_and_verifies() -> None:
    vault = FakeVault()
    payload = b'{"canonical":"json"}'
    signature = backend(vault).sign(RECEIPT, payload)

    SIGNER.public_key().verify(signature, payload)
    signing = next(r for r in vault.requests if r.method == "POST")
    assert signing.url.path == "/v1/transit/sign/mizan-evidence-receipt"
    body = json.loads(signing.content)
    assert base64.b64decode(body["input"]) == payload
    assert body["key_version"] == 1
    # Ed25519 hashes internally over the whole message. Pre-hashing would sign a digest, and every
    # verifier in this tree checks the signature against the canonical bytes.
    assert body["prehashed"] is False


def test_a_signature_that_does_not_verify_is_refused_rather_than_returned() -> None:
    """The guarantee that makes this more than an HTTP client.

    Vault is trusted to hold the key, not to be correctly configured. A `prehashed` setting, a key
    rotated between the read and the sign, or a proxy that re-encodes the body all produce a
    well-formed signature over the wrong bytes. Caught here it is a refused request; caught later
    it is a signed evidence bundle that no verifier will accept and that we produced ourselves --
    and the corpus is immutable, so it cannot be re-signed.
    """
    imposter = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    with pytest.raises(VaultRefused, match="does not verify under the public key"):
        backend(FakeVault(signer=imposter)).sign(RECEIPT, b"payload")


def test_a_signature_from_a_different_key_version_is_refused() -> None:
    """Transit falls back to the latest version rather than failing on an unknown one.

    A signature from a version the key id does not name is one the exported keyset cannot describe:
    `keys.json` would publish version 1's public key beside a signature made by version 2.
    """
    with pytest.raises(VaultRefused, match="signed .* with key version 2, not 1"):
        backend(FakeVault(signing_version=2)).sign(RECEIPT, b"payload")


def test_an_unrecognised_signature_envelope_is_refused() -> None:
    vault = FakeVault()
    client = httpx.Client(
        base_url="https://vault.test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"data": {"signature": "not-a-vault-envelope"}})
            if request.method == "POST"
            else vault.handle(request)
        ),
    )
    subject = VaultTransitBackend("https://vault.test", "s.token", client=client)
    with pytest.raises(VaultRefused, match="unrecognised signature envelope"):
        subject.sign(RECEIPT, b"payload")


# ---------------------------------------------------------------------------------------------
# Failure modes an operator will actually hit
# ---------------------------------------------------------------------------------------------


def test_a_policy_that_forbids_the_operation_says_so(monkeypatch) -> None:
    with pytest.raises(VaultRefused, match="refused the token"):
        backend(FakeVault(status=403)).public_key(RECEIPT)


def test_a_missing_key_says_so_rather_than_reporting_a_protocol_error() -> None:
    with pytest.raises(VaultRefused, match="is the key created"):
        backend(FakeVault(status=404)).public_key(RECEIPT)


def test_an_unreachable_vault_names_the_address_and_not_the_token() -> None:
    """A token in an exception message is a token in a log, in a ticket, and in a screenshot."""

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.Client(
        base_url="https://vault.test",
        headers={"X-Vault-Token": "s.super-secret"},
        transport=httpx.MockTransport(refuse),
    )
    subject = VaultTransitBackend("https://vault.test", "s.super-secret", client=client)
    with pytest.raises(VaultRefused) as refused:
        subject.public_key(RECEIPT)
    assert "vault.test" in str(refused.value)
    assert "s.super-secret" not in str(refused.value)


def test_a_backend_without_an_address_or_a_token_is_refused_at_construction() -> None:
    with pytest.raises(VaultRefused, match="MIZAN_VAULT_ADDR"):
        VaultTransitBackend("", "s.token")
    with pytest.raises(VaultRefused, match="MIZAN_VAULT_TOKEN"):
        VaultTransitBackend("https://vault.test", "")
