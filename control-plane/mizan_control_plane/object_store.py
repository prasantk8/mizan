"""S3-compatible object storage with Object Lock — B-21's ruling, delivered.

The chart mounted an `emptyDir` at `/app/var/evidence` with `replicaCount: 2`. Three things follow
and all of them are worse than they look: a bundle exported by pod A cannot read the segments pod B
published, a rollout destroys the corpus, and `LocalImmutableObjectStore` — whose docstring calls
itself a *"development WORM analogue"* — was the only thing standing behind the string
`"retention_class": "regulatory_7y"` that this system writes into records it then signs. That claim
was already inside signed evidence. A PVC cannot support it and an `emptyDir` contradicts it.

B-21 chose S3-compatible object storage with Object Lock, which is the only substrate here where
"immutable" is enforced by something other than our own code being careful. Under COMPLIANCE mode
**no principal can delete or overwrite an object before its retention date — including the account
root, including us.** That is the difference between evidence and a file we promise not to edit.

Two properties are asserted at startup rather than trusted, for the same reason the Vault backend
reads every public key before it reports ready:

  * **The bucket really has Object Lock enabled.** It can only be turned on when a bucket is
    *created*, so a deployment pointed at an ordinary bucket cannot be repaired later — and it
    would publish evidence that says `regulatory_7y` into storage where anything with write access
    can remove it. Refused by name at startup.
  * **Writes are create-only.** Versioning is mandatory under Object Lock, so an ordinary PUT to an
    existing key succeeds and quietly creates a second version. `put_once` uses a conditional write
    and, on conflict, compares bytes — identical content returns the existing version, different
    content raises. Without that, "immutable object collision" would never fire on S3 and a
    re-published segment would shadow the original in every listing.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .canonical import canonical_hash


class ObjectStoreRefused(RuntimeError):
    """Storage that would accept writes, but not with the durability Mizan claims."""


class ImmutableObjectStore(Protocol):
    def put_once(self, key: str, payload: bytes) -> str: ...

    def get(self, key: str) -> bytes: ...


def object_version(key: str, payload: bytes) -> str:
    """The version identifier a receipt binds to.

    Content-addressed and computed here rather than taken from the store, so a bundle written to S3
    and a bundle written to a local directory carry the same `object_version` for the same bytes.
    An S3 `VersionId` would be a different identifier per backend, and a verifier holding a bundle
    has no way to ask which backend produced it.
    """
    return canonical_hash({"key": key, "payload_sha256": hashlib.sha256(payload).hexdigest()})


class S3ObjectLockStore:
    """Create-only writes into a bucket whose immutability is enforced by the storage layer."""

    def __init__(
        self,
        bucket: str,
        *,
        client: Any,
        retention_years: int = 7,
        prefix: str = "",
    ) -> None:
        if not bucket:
            raise ObjectStoreRefused("MIZAN_AUDIT_ANCHOR_BUCKET is required for the s3 object store")
        if retention_years < 1:
            raise ObjectStoreRefused(
                "object lock retention must be at least one year; a retention of zero is an "
                "ordinary bucket wearing the word COMPLIANCE"
            )
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.retention_years = retention_years
        self._client = client

    # -- startup honesty -----------------------------------------------------------------------

    def assert_object_lock_enabled(self) -> None:
        """Refuse a bucket that cannot hold evidence, at startup, by name.

        Object Lock can only be enabled when a bucket is *created*. A deployment pointed at an
        ordinary bucket therefore cannot be repaired in place, and until it is replaced every
        record it writes claiming `regulatory_7y` is a false statement about where that record
        lives. Checked once, loudly, rather than discovered during an audit.
        """
        try:
            configuration = self._client.get_object_lock_configuration(Bucket=self.bucket)
        except Exception as error:
            # botocore raises a generic `ClientError` and puts the real name in the response, so
            # the code is what has to be read -- matching on the exception type would have made
            # every failure here report the same unhelpful message.
            name = _error_code(error) or type(error).__name__
            if "ObjectLockConfigurationNotFound" in name or "NoSuchObjectLockConfiguration" in name:
                raise ObjectStoreRefused(
                    f"bucket {self.bucket!r} has no Object Lock configuration. Object Lock can only "
                    "be enabled when a bucket is created, so this cannot be fixed in place -- and "
                    "every record written here claims retention this bucket does not enforce."
                ) from error
            raise ObjectStoreRefused(
                f"could not read the Object Lock configuration of {self.bucket!r}: {name}"
            ) from error
        enabled = (configuration.get("ObjectLockConfiguration") or {}).get("ObjectLockEnabled")
        if enabled != "Enabled":
            raise ObjectStoreRefused(
                f"bucket {self.bucket!r} reports ObjectLockEnabled={enabled!r}, not 'Enabled'"
            )

    # -- the store ------------------------------------------------------------------------------

    def _object_key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def put_once(self, key: str, payload: bytes) -> str:
        version = object_version(key, payload)
        retain_until = datetime.now(UTC) + timedelta(days=365 * self.retention_years)
        try:
            self._client.put_object(
                Bucket=self.bucket,
                Key=self._object_key(key),
                Body=payload,
                # COMPLIANCE, not GOVERNANCE: GOVERNANCE mode can be bypassed by a principal
                # holding `s3:BypassGovernanceRetention`, which makes the retention a policy
                # decision rather than a property of the object. Evidence that the operator can
                # delete is evidence the operator can be asked to delete.
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=retain_until,
                ChecksumAlgorithm="SHA256",
                # Conditional create. Versioning is mandatory under Object Lock, so a plain PUT to
                # an existing key succeeds and silently creates a second version -- and the
                # collision this store exists to detect would never be detected.
                IfNoneMatch="*",
            )
        except Exception as error:
            if not _is_precondition_failure(error):
                raise ObjectStoreRefused(
                    f"could not write {key!r} to {self.bucket!r}: {type(error).__name__}"
                ) from error
            # The key exists. Identical bytes are the ordinary case -- a retried drain, a worker
            # that died between writing the object and recording its receipts -- and must be
            # idempotent. Different bytes under the same key is the thing that must never pass.
            existing = self.get(key)
            if existing != payload:
                raise RuntimeError("immutable object collision") from None
        return version

    def get(self, key: str) -> bytes:
        try:
            response = self._client.get_object(Bucket=self.bucket, Key=self._object_key(key))
        except Exception as error:
            name = _error_code(error) or type(error).__name__
            if "NoSuchKey" in name or "404" in str(error):
                raise FileNotFoundError(key) from error
            raise ObjectStoreRefused(
                f"could not read {key!r} from {self.bucket!r}: {name}"
            ) from error
        return response["Body"].read()


def _error_code(error: Exception) -> str:
    """The S3 error code, which botocore carries on the response rather than in the type."""
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        return str((response.get("Error") or {}).get("Code", ""))
    return ""


def _is_precondition_failure(error: Exception) -> bool:
    """`If-None-Match: *` conflicts arrive as 412, spelled differently by each implementation."""
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        code = (response.get("Error") or {}).get("Code", "")
        status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        if code in ("PreconditionFailed", "412") or status == 412:
            return True
    return "PreconditionFailed" in type(error).__name__


def build_s3_client(
    endpoint_url: str, region: str, access_key: str, secret_key: str
) -> Any:
    """Construct a boto3 S3 client, or refuse with the reason.

    `boto3` is an optional extra rather than a hard dependency: a development install signs into a
    local directory and has no use for it. An operator who configures the s3 store without the
    extra installed is refused at startup rather than served a process that reports itself ready
    and cannot write evidence -- the same shape as `MIZAN_OTEL_EXPORTER_OTLP_ENDPOINT` without the
    `otel` extra.
    """
    try:
        import boto3
        from botocore.config import Config
    except ImportError as error:
        raise ObjectStoreRefused(
            "MIZAN_EVIDENCE_OBJECT_STORE=s3 needs the 's3' extra: pip install 'mizan-control-plane[s3]'"
        ) from error
    return boto3.client(
        "s3",
        endpoint_url=endpoint_url or None,
        region_name=region,
        aws_access_key_id=access_key or None,
        aws_secret_access_key=secret_key or None,
        config=Config(
            signature_version="s3v4",
            # Path style, because an S3-compatible endpoint reached by IP or by a bare service name
            # has no virtual-host DNS to resolve `<bucket>.<host>`.
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )
