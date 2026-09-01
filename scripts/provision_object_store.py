#!/usr/bin/env python3
"""Create and verify the Object Lock bucket used by production evidence."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any


def provision(client: Any, bucket: str, region: str, retention_days: int) -> dict[str, Any]:
    request: dict[str, Any] = {"Bucket": bucket, "ObjectLockEnabledForBucket": True}
    if region != "us-east-1":
        request["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        client.create_bucket(**request)
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            raise
    configuration = {
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": retention_days}},
    }
    client.put_object_lock_configuration(
        Bucket=bucket, ObjectLockConfiguration=configuration
    )
    observed = client.get_object_lock_configuration(Bucket=bucket)["ObjectLockConfiguration"]
    if observed.get("ObjectLockEnabled") != "Enabled":
        raise RuntimeError(f"bucket {bucket!r} does not have Object Lock enabled")
    retention = observed.get("Rule", {}).get("DefaultRetention", {})
    if retention.get("Mode") != "COMPLIANCE" or int(retention.get("Days", 0)) < retention_days:
        raise RuntimeError(
            f"bucket {bucket!r} default retention is {retention!r}, expected COMPLIANCE "
            f"for at least {retention_days} days"
        )
    return observed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", default=os.getenv("MIZAN_AUDIT_ANCHOR_BUCKET", ""))
    parser.add_argument("--endpoint-url", default=os.getenv("MIZAN_S3_ENDPOINT_URL") or None)
    parser.add_argument("--region", default=os.getenv("MIZAN_S3_REGION", "us-east-1"))
    parser.add_argument("--retention-years", type=int, default=7)
    arguments = parser.parse_args(argv)
    if not arguments.bucket or arguments.retention_years < 1:
        parser.error("--bucket is required and --retention-years must be positive")
    try:
        from mizan_control_plane.object_store import build_s3_client

        client = build_s3_client(
            arguments.endpoint_url or "",
            arguments.region,
            os.getenv("MIZAN_S3_ACCESS_KEY_ID", ""),
            os.getenv("MIZAN_S3_SECRET_ACCESS_KEY", ""),
        )
        observed = provision(
            client, arguments.bucket, arguments.region, arguments.retention_years * 365
        )
    except Exception as error:
        print(f"Object Lock provisioning failed: {error}", file=sys.stderr)
        return 1
    retention = observed["Rule"]["DefaultRetention"]
    print(
        f"PASS: {arguments.bucket} has Object Lock {observed['ObjectLockEnabled']} with "
        f"{retention['Mode']} retention for {retention['Days']} days"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

