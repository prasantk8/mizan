from __future__ import annotations

from pathlib import Path

from scripts.provision_object_store import provision
from scripts.validate_installation import validate


class ObjectLockClient:
    def __init__(self) -> None:
        self.configuration = {}
        self.created = None

    def create_bucket(self, **request):
        self.created = request

    def put_object_lock_configuration(self, **request):
        self.configuration = request["ObjectLockConfiguration"]

    def get_object_lock_configuration(self, **_request):
        return {"ObjectLockConfiguration": self.configuration}


def test_repository_installation_surface_names_every_production_bootstrap_step() -> None:
    assert validate(Path(__file__).resolve().parents[2]) == []


def test_object_store_provisioning_enables_compliance_retention() -> None:
    client = ObjectLockClient()
    observed = provision(client, "mizan-evidence", "eu-west-1", 2555)

    assert client.created == {
        "Bucket": "mizan-evidence",
        "ObjectLockEnabledForBucket": True,
        "CreateBucketConfiguration": {"LocationConstraint": "eu-west-1"},
    }
    assert observed["ObjectLockEnabled"] == "Enabled"
    assert observed["Rule"]["DefaultRetention"] == {"Mode": "COMPLIANCE", "Days": 2555}

