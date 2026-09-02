"""HashiCorp Vault Transit as the signing backend — B-18's ruling, delivered.

Until this module existed, `build_key_provider` had exactly one branch that returned a provider,
and it returned `LocalKeyProvider`. Every other configuration raised `StartupRefused` naming
"blocker B-18", so **the product could not boot in any mode that was not development**, and the
`KmsHsmKeyProvider` written for T-053 had nothing to inject. That is the whole of T-102.

Why Transit and not a cloud KMS. Bundle format 1.0 fixes `algorithm` at `Ed25519` in every key
document, and AWS KMS, GCP Cloud KMS and Azure Key Vault do not sign Ed25519 at all. Choosing one
would have meant either a second signature algorithm in the format — reopening a ratified spec and
every verifier written against it — or signing evidence with a key whose custody we could not
describe. Vault Transit signs Ed25519 natively and never releases the private key, so `custody`
stays `kms` and the format does not move. PKCS#11 is the second backend and is not in this stage.

Three things this does that a thin HTTP client would not, each because of a way it can go wrong:

  * **Every signature is verified locally before it is returned.** Vault is trusted to hold the
    key, not to be correctly configured: a `prehashed` setting, a key rotated between the read and
    the sign, or a proxy that re-encodes a body all produce a well-formed signature over the wrong
    bytes. A bad signature caught here is a refused request; a bad signature caught later is a
    signed evidence bundle that no verifier will ever accept and that we produced ourselves. One
    Ed25519 verification costs microseconds against an HTTP round trip.
  * **A key whose type is not `ed25519` is refused by name.** Pointing the configuration at an RSA
    key otherwise fails at the first signature, in the drain worker, at three in the morning.
  * **The public key is read from Vault and pinned per version**, never derived and never taken
    from configuration, because `verification_keyset()` is copied verbatim into every exported
    bundle. A wrong public key there does not fail loudly; it produces bundles that verify against
    nothing, and the corpus is immutable.
"""

from __future__ import annotations

import base64
import re
import ssl
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# `vault://<mount>/<key-name>#<version>`. The version is explicit and required: Transit keeps every
# version of a key forever and signs with the latest by default, so a reference without one would
# silently change which key signs the moment an operator rotates -- and ADR-004 G.1's additive
# rotation exists precisely so that history is never re-signed. A key id that does not name its
# version cannot describe a corpus.
KEY_REF = re.compile(r"^vault://(?P<mount>[\w-]+)/(?P<name>[\w.-]+)#v(?P<version>\d+)$")

# Vault returns `vault:v<n>:<standard base64 signature>`.
SIGNATURE = re.compile(r"^vault:v(?P<version>\d+):(?P<signature>[A-Za-z0-9+/=]+)$")

# The HMAC endpoint uses the same envelope for a digest rather than a signature.
HMAC_ENVELOPE = re.compile(r"^vault:v(?P<version>\d+):(?P<digest>[A-Za-z0-9+/=]+)$")


class VaultRefused(RuntimeError):
    """Vault could not be used as configured. Always a startup or request refusal, never a warning."""


@dataclass(frozen=True, slots=True)
class TransitKeyRef:
    mount: str
    name: str
    version: int

    @classmethod
    def parse(cls, key_ref: str) -> TransitKeyRef:
        matched = KEY_REF.match(key_ref)
        if not matched:
            raise VaultRefused(
                f"{key_ref!r} is not a Transit key reference; expected "
                "vault://<mount>/<key-name>#v<version>"
            )
        return cls(matched["mount"], matched["name"], int(matched["version"]))


class VaultTransitBackend:
    """A `KmsHsmBackend` over Vault's Transit secrets engine.

    Holds no private material and cannot: Transit signs in place and has no export path for an
    `ed25519` key created without `exportable`, which is the property that makes `custody=kms`
    a true statement rather than a label.
    """

    def __init__(
        self,
        address: str,
        token: str,
        *,
        namespace: str | None = None,
        ca_certificate: str | None = None,
        timeout: float = 5.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not address:
            raise VaultRefused("MIZAN_VAULT_ADDR is required for the vault-transit key backend")
        if not token:
            raise VaultRefused(
                "no Vault token was supplied; set MIZAN_VAULT_TOKEN or MIZAN_VAULT_TOKEN_FILE"
            )
        headers = {"X-Vault-Token": token}
        if namespace:
            headers["X-Vault-Namespace"] = namespace
        self.address = address.rstrip("/")
        # An `ssl.SSLContext` rather than `verify=<path>`: httpx deprecated the string form, and
        # the deprecation is the polite version of a real hazard -- this repository has already
        # been bitten once by httpx quietly not doing what a TLS keyword appeared to say, when
        # `verify=<ca path>` beside `cert=(cert, key)` silently declined to present the client
        # certificate and every mTLS request failed with a protocol error (T-103).
        self._client = client or httpx.Client(
            base_url=self.address,
            headers=headers,
            timeout=timeout,
            verify=(
                ssl.create_default_context(cafile=ca_certificate)
                if ca_certificate
                else ssl.create_default_context()
            ),
        )
        # Public keys are immutable per version, so one read each is enough -- and caching them
        # means a signature can still be verified locally while Vault is briefly unreachable for
        # reads, which is the direction that fails safe.
        self._public_keys: dict[str, Ed25519PublicKey] = {}
        # Key type is a property of the key, not of one version, and `mac()` checks it on every
        # call. Without this cache the audit write path would make two round trips per commitment
        # instead of one, and the ruling already accepts N+1 as its stated cost.
        self._key_types: dict[str, str] = {}

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            response = self._client.request(method, path, json=body)
        except httpx.HTTPError as error:
            # The message names the address and not the token, and `httpx` does not put headers in
            # its exception text -- but a token in a log is a token in a log, so this is explicit.
            raise VaultRefused(f"Vault at {self.address} is unreachable: {type(error).__name__}") from error
        if response.status_code == 403:
            raise VaultRefused(
                f"Vault refused the token for {path}; the policy must allow it (403)"
            )
        if response.status_code == 404:
            raise VaultRefused(f"Vault has no object at {path} (404); is the key created?")
        if response.status_code >= 400:
            raise VaultRefused(f"Vault returned {response.status_code} for {path}")
        try:
            return dict(response.json())
        except ValueError as error:
            raise VaultRefused(f"Vault returned a non-JSON body for {path}") from error

    def public_key(self, key_ref: str) -> Ed25519PublicKey:
        cached = self._public_keys.get(key_ref)
        if cached is not None:
            return cached
        reference = TransitKeyRef.parse(key_ref)
        document = self._request("GET", f"/v1/{reference.mount}/keys/{reference.name}")
        data = document.get("data") or {}
        key_type = data.get("type")
        if key_type != "ed25519":
            raise VaultRefused(
                f"Transit key {reference.name!r} is of type {key_type!r}; bundle format 1.0 fixes "
                "algorithm at Ed25519 in every key document, so no other type can sign evidence"
            )
        versions = data.get("keys") or {}
        material = versions.get(str(reference.version))
        if material is None:
            raise VaultRefused(
                f"Transit key {reference.name!r} has no version {reference.version} "
                f"(present: {sorted(versions)})"
            )
        encoded = material.get("public_key") if isinstance(material, dict) else None
        if not isinstance(encoded, str):
            raise VaultRefused(
                f"Transit key {reference.name!r} version {reference.version} published no public key"
            )
        try:
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded, validate=True))
        except (ValueError, TypeError) as error:
            raise VaultRefused(
                f"Transit key {reference.name!r} version {reference.version} published a public key "
                "that is not 32 raw Ed25519 bytes"
            ) from error
        self._public_keys[key_ref] = public
        return public

    def sign(self, key_ref: str, payload: bytes) -> bytes:
        reference = TransitKeyRef.parse(key_ref)
        document = self._request(
            "POST",
            f"/v1/{reference.mount}/sign/{reference.name}",
            {
                "input": base64.b64encode(payload).decode(),
                "key_version": reference.version,
                # Ed25519 hashes internally over the whole message. Asking Vault to pre-hash would
                # produce a signature over a digest, which every verifier in this tree -- and the
                # standalone one, and `verifier-two` -- would reject, because they verify against
                # the canonical bytes.
                "prehashed": False,
            },
        )
        stated = ((document.get("data") or {}).get("signature")) or ""
        matched = SIGNATURE.match(stated)
        if not matched:
            raise VaultRefused(f"Vault returned an unrecognised signature envelope for {key_ref}")
        if int(matched["version"]) != reference.version:
            # Transit signs with the latest version when asked for one it no longer has. A
            # signature from a version the key id does not name is a signature the exported keyset
            # cannot describe.
            raise VaultRefused(
                f"Vault signed {key_ref} with key version {matched['version']}, not "
                f"{reference.version}"
            )
        signature = base64.b64decode(matched["signature"], validate=True)
        try:
            self.public_key(key_ref).verify(signature, payload)
        except InvalidSignature as error:
            raise VaultRefused(
                f"Vault returned a signature for {key_ref} that does not verify under the public "
                "key it publishes for that version. Refusing to emit it: an unverifiable signature "
                "inside signed evidence is indistinguishable from a forgery, and the corpus is "
                "immutable."
            ) from error
        return signature

    def mac(self, key_ref: str, payload: bytes) -> bytes:
        """HMAC-SHA256 in place, for the audit commitment key (T-054, B-30 ruled).

        **The safety net that `sign()` has does not exist here, and pretending otherwise would be
        worse than saying so.** `sign()` verifies every signature locally before returning it,
        because a misconfigured Transit mount can produce a well-formed signature over the wrong
        bytes. A MAC cannot be checked that way: verifying it requires the secret, and the secret is
        in Vault precisely so that this process never holds it. So a Vault that MACs the wrong bytes
        is undetectable here by construction.

        What is left is everything that *can* be checked, and each of these is a way it has already
        been possible to go wrong on the signing path:

          * **The key type must be `hmac`.** Transit will happily HMAC under an `ed25519` key, which
            would quietly use an evidence *signing* key as the audit commitment key -- exactly the
            key separation ADR-004 G.1 exists to enforce, defeated by a copy-pasted key name.
          * **The returned version must be the version the reference names.** Transit uses the
            latest version when asked for one it no longer has, and a commitment under a version the
            record does not cite cannot be resolved by the operator later.
          * **The digest must be 32 bytes**, so a mount configured for another algorithm is a
            refusal rather than a short commitment nobody looks at again.
        """
        reference = TransitKeyRef.parse(key_ref)
        if self._key_type(reference) != "hmac":
            raise VaultRefused(
                f"Transit key {reference.name!r} is not of type 'hmac'; the audit commitment key "
                "must be a separate MAC key (ADR-004 G.1, four signing roles plus one MAC). "
                "Refusing to authenticate a commitment under an evidence signing key."
            )
        document = self._request(
            "POST",
            f"/v1/{reference.mount}/hmac/{reference.name}",
            {
                "input": base64.b64encode(payload).decode(),
                "key_version": reference.version,
                "algorithm": "sha2-256",
            },
        )
        stated = ((document.get("data") or {}).get("hmac")) or ""
        matched = HMAC_ENVELOPE.match(stated)
        if not matched:
            raise VaultRefused(f"Vault returned an unrecognised HMAC envelope for {key_ref}")
        if int(matched["version"]) != reference.version:
            raise VaultRefused(
                f"Vault MACed {key_ref} with key version {matched['version']}, not "
                f"{reference.version}"
            )
        digest = base64.b64decode(matched["digest"], validate=True)
        if len(digest) != 32:
            raise VaultRefused(
                f"Vault returned a {len(digest)}-byte digest for {key_ref}; HMAC-SHA256 is 32"
            )
        return digest

    def _key_type(self, reference: TransitKeyRef) -> str:
        cached = self._key_types.get(reference.name)
        if cached is not None:
            return cached
        document = self._request("GET", f"/v1/{reference.mount}/keys/{reference.name}")
        key_type = str((document.get("data") or {}).get("type") or "")
        self._key_types[reference.name] = key_type
        return key_type

    def close(self) -> None:
        self._client.close()
