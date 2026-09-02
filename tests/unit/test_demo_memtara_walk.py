from __future__ import annotations

import json
from pathlib import Path

import scripts.demo_memtara_walk as demo


def test_reference_transcript_is_diff_clean(tmp_path: Path) -> None:
    generated = tmp_path / "transcript.txt"
    demo.write_reference_transcript(generated)
    committed = Path("tests/fixtures/demo_memtara/transcript.txt")
    assert generated.read_bytes() == committed.read_bytes()


def test_reference_prover_is_invoked_as_an_opaque_subprocess(monkeypatch, tmp_path: Path) -> None:
    prover = tmp_path / "clients" / "prover" / "memtara-prove"
    prover.parent.mkdir(parents=True)
    prover.write_text("reference client", encoding="utf-8")
    vault = tmp_path / "vault.json"
    vault.write_text("{}", encoding="utf-8")
    observed = {}

    def run(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "proof_token": "header.payload.signature",
                        "product_isin": demo.PRODUCT_ISIN,
                        "suitable": True,
                    }
                ),
                "stderr": "",
            },
        )()

    monkeypatch.setattr(demo.subprocess, "run", run)
    result = demo.run_reference_prover(
        memtara_repo=tmp_path,
        base_url="http://memtara.test",
        org_api_key="secret-key",
        user_id="user-1",
        product_isin=demo.PRODUCT_ISIN,
        vault_path=vault,
    )
    assert result["suitable"] is True
    assert str(prover) in observed["command"]
    assert "secret-key" in observed["command"]
    assert observed["kwargs"]["capture_output"] is True


def test_recommendation_context_binds_product_isin() -> None:
    sent = demo.recommendation_context(demo.PRODUCT_ISIN)
    assert sent["tool"]["arguments"]["product_isin"] == demo.PRODUCT_ISIN
    assert sent["tool"]["binding_profile"]["profile_id"] == "bp_product-recommendation-v1"
    assert len(sent["tool"]["parameters_hash"]) == 64
