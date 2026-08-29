"""T-104's gate: evidence survives the pod that wrote it, and the storage layer says so.

`"retention_class": "regulatory_7y"` is a string this system writes into records and then signs.
Until this commit the only thing standing behind it was `LocalImmutableObjectStore`, whose own
docstring calls it a *"development WORM analogue"* — mounted by the chart as an `emptyDir` under
`replicaCount: 2`, so a bundle exported by pod A could not read segments published by pod B and a
rollout destroyed the corpus outright.

B-21 chose Object Lock, and the reason to test it against a real S3 implementation rather than a
double is that the guarantee **is** the implementation. A mock that refuses a delete proves that a
mock refuses a delete. `test_the_storage_layer_refuses_to_delete_what_it_has_locked` asks the real
server to remove an object and requires it to say no — that assertion is the whole difference
between evidence and a file we have promised not to edit.

Two pods are simulated by two independent clients against one bucket, because that is the failure
the `emptyDir` produced and the one a shared substrate has to make impossible.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from mizan_control_plane.object_store import (
    ObjectStoreRefused,
    S3ObjectLockStore,
    build_s3_client,
    object_version,
)

ENDPOINT = os.getenv("MIZAN_TEST_S3_ENDPOINT_URL", "")
ACCESS_KEY = os.getenv("MIZAN_TEST_S3_ACCESS_KEY_ID", "")
SECRET_KEY = os.getenv("MIZAN_TEST_S3_SECRET_ACCESS_KEY", "")

pytestmark = pytest.mark.skipif(
    not (ENDPOINT and ACCESS_KEY and SECRET_KEY),
    reason="object storage not configured (MIZAN_TEST_S3_ENDPOINT_URL/ACCESS_KEY_ID/SECRET)",
)

LOCKED = "mizan-evidence-locked"
PLAIN = "mizan-evidence-plain"


def client():
    return build_s3_client(ENDPOINT, "us-east-1", ACCESS_KEY, SECRET_KEY)


@pytest.fixture(scope="module", autouse=True)
def buckets() -> None:
    """One bucket with Object Lock and one without — the second is what must be refused.

    Object Lock is settable only at creation, which is exactly why the refusal has to happen at
    startup: there is no repair path, so a deployment that gets this wrong stays wrong.
    """
    api = client()
    for name, locked in ((LOCKED, True), (PLAIN, False)):
        try:
            if locked:
                api.create_bucket(Bucket=name, ObjectLockEnabledForBucket=True)
            else:
                api.create_bucket(Bucket=name)
        except Exception as error:  # already created by an earlier run
            if "BucketAlreadyOwnedByYou" not in str(error) and "BucketAlreadyExists" not in str(error):
                raise


def store(bucket: str = LOCKED, **overrides) -> S3ObjectLockStore:
    return S3ObjectLockStore(bucket, client=client(), **overrides)


def unique(name: str) -> str:
    """A key per test. Objects written here cannot be deleted, so reuse would collide for years."""
    return f"segments/t104/{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}-{name}.json"


# ---------------------------------------------------------------------------------------------
# The bucket has to be able to hold evidence before anything is written to it
# ---------------------------------------------------------------------------------------------


def test_a_bucket_without_object_lock_is_refused_by_name() -> None:
    with pytest.raises(ObjectStoreRefused, match="no Object Lock configuration"):
        store(PLAIN).assert_object_lock_enabled()


def test_a_bucket_with_object_lock_is_accepted() -> None:
    store().assert_object_lock_enabled()


def test_a_retention_of_zero_years_is_refused() -> None:
    """COMPLIANCE with no retention is an ordinary bucket wearing the word."""
    with pytest.raises(ObjectStoreRefused, match="at least one year"):
        store(retention_years=0)


# ---------------------------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------------------------


def test_an_object_is_written_under_compliance_retention_a_reader_can_see() -> None:
    subject, key, payload = store(), unique("written"), b'{"sequence_number":1}'

    version = subject.put_once(key, payload)

    assert subject.get(key) == payload
    # The version a receipt binds to is content-addressed, so the same bytes produce the same
    # identifier whether they were written to S3 or to a directory. An S3 `VersionId` would be a
    # different identifier per backend, and a verifier holding a bundle cannot ask which wrote it.
    assert version == object_version(key, payload)

    head = client().head_object(Bucket=LOCKED, Key=key)
    assert head["ObjectLockMode"] == "COMPLIANCE"
    assert head["ObjectLockRetainUntilDate"] > datetime.now(UTC).replace(year=datetime.now(UTC).year + 6)


def test_the_storage_layer_refuses_to_delete_what_it_has_locked() -> None:
    """The assertion the whole task exists for, made against a real server.

    Under COMPLIANCE no principal can remove or overwrite the object before its retention date --
    including the account root, including us. A mock refusing a delete would prove that a mock
    refuses a delete; this asks the server.
    """
    subject, key = store(), unique("undeletable")
    subject.put_once(key, b'{"anchor":true}')
    version_id = client().head_object(Bucket=LOCKED, Key=key)["VersionId"]

    with pytest.raises(Exception) as refused:
        client().delete_object(Bucket=LOCKED, Key=key, VersionId=version_id)

    assert "InvalidRequest" in type(refused.value).__name__ or "AccessDenied" in str(refused.value)
    assert subject.get(key) == b'{"anchor":true}'


def test_rewriting_a_key_with_identical_bytes_is_idempotent() -> None:
    """A drainer that died between writing the object and recording its receipts retries.

    `put_once` is called again with the same segment; it must return the same version rather than
    raise, or the recovery path becomes a permanent failure.
    """
    subject, key, payload = store(), unique("idempotent"), b'{"retry":"safe"}'
    assert subject.put_once(key, payload) == subject.put_once(key, payload)


def test_rewriting_a_key_with_different_bytes_is_a_collision() -> None:
    """Versioning is mandatory under Object Lock, so an ordinary PUT would have *succeeded*.

    It would have created a second version, shadowed the first in every listing, and left the
    original reachable only by `VersionId` -- which no receipt records. This is the case that
    makes the conditional write load-bearing rather than tidy.
    """
    subject, key = store(), unique("collision")
    subject.put_once(key, b'{"original":true}')
    with pytest.raises(RuntimeError, match="immutable object collision"):
        subject.put_once(key, b'{"tampered":true}')
    assert subject.get(key) == b'{"original":true}'


# ---------------------------------------------------------------------------------------------
# The failure the emptyDir produced
# ---------------------------------------------------------------------------------------------


def test_a_segment_written_by_one_replica_is_readable_by_another() -> None:
    """The chart mounted an `emptyDir` with `replicaCount: 2`.

    A bundle exported by pod A therefore could not read the segments pod B had published, and the
    export failed on an object the receipts said existed. Two independent clients here stand in for
    two pods: they share nothing but the bucket, which is the point.
    """
    writer, reader = store(), store()
    key, payload = unique("cross-replica"), b'{"written":"by A"}'

    writer.put_once(key, payload)

    assert reader.get(key) == payload


def test_a_key_that_was_never_written_is_a_missing_file_not_a_protocol_error() -> None:
    """`ObjectEvidenceVerifier.verify` catches `FileNotFoundError` to report a missing object.

    Returning something else would turn "this segment is gone" -- a real and reportable evidence
    failure -- into an unhandled exception in the verifier.
    """
    with pytest.raises(FileNotFoundError):
        store().get("segments/t104/never-written.json")
