"""Managed acceptance of trusted wheel baselines. Offline: PyPI is replaced by a fake fetch."""
from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from integrityguard import baseline_acceptance as ba
from integrityguard.provenance import file_sha256
from integrityguard.wheel_scan import inspect_wheel


def _record_line(name: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def _make_wheel(path: Path, name: str, version: str, body: str) -> Path:
    dist = f"{name}-{version}.dist-info"
    files = {
        f"{name}/__init__.py": body.encode(),
        f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record_lines = [_record_line(n, d) for n, d in files.items()]
    record_name = f"{dist}/RECORD"
    record_lines.append(f"{record_name},,")
    files[record_name] = ("\n".join(record_lines) + "\n").encode()
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in files.items():
            archive.writestr(member, data)
    return path


def _fake_fetch(wheel_path, facts, *, status="pypi_hash_verified", sha=None):
    return {"status": status, "artifact_sha256": sha or facts["sha256"],
            "metadata_url": "https://pypi.org/pypi/x/1/json", "metadata_sha256": "m" * 64,
            "uploaded_at": "2026-01-01T00:00:00Z", "yanked": False,
            "publisher_signature_verified": False}


def _propose(wheel, registry, fetch=_fake_fetch):
    return ba.propose(wheel, registry, source_url="https://pypi.org/project/demo/",
                      provenance_ref="PyPI record", fetch=fetch)


def _baseline_count(registry, name="demo"):
    root = Path(registry) / "wheel_baselines" / name
    return len(list(root.glob("*.json"))) if root.is_dir() else 0


@pytest.fixture
def wheels(tmp_path):
    v1 = _make_wheel(tmp_path / "demo-1.0-py3-none-any.whl", "demo", "1.0", "VALUE = 1\n")
    v2 = _make_wheel(tmp_path / "demo-2.0-py3-none-any.whl", "demo", "2.0", "VALUE = 2\n")
    assert inspect_wheel(v1)["record"]["complete"] is True
    return v1, v2


def test_verified_file_is_accepted_and_audited(tmp_path, wheels):
    v1, _ = wheels
    registry = tmp_path / "reg"
    proposal = _propose(v1, registry)
    assert proposal["can_accept"] is True and proposal["reasons"] == []
    assert _baseline_count(registry) == 0  # proposing writes nothing to the trust registry
    manifest = ba.accept(proposal, v1, registry, operator="reviewer-a", decision="accept",
                         fetch=_fake_fetch)
    assert manifest["version"] == "1.0"
    assert manifest["source_verification"]["status"] == "pypi_hash_verified"
    assert _baseline_count(registry) == 1
    ok, count = ba.verify_audit(registry)
    assert ok and count == 1


def test_failed_pypi_check_grants_no_trust(tmp_path, wheels):
    v1, _ = wheels
    registry = tmp_path / "reg"

    def unavailable(path, facts):
        raise OSError("network down")

    proposal = _propose(v1, registry, fetch=unavailable)
    assert proposal["can_accept"] is False
    assert any("PyPI" in reason for reason in proposal["reasons"])
    with pytest.raises(ba.AcceptanceError):
        ba.accept(proposal, v1, registry, operator="reviewer-a", decision="accept", fetch=unavailable)
    assert _baseline_count(registry) == 0
    assert ba.verify_audit(registry)[1] == 1  # the refusal itself is recorded


def test_hash_mismatch_from_pypi_is_refused(tmp_path, wheels):
    v1, _ = wheels
    proposal = _propose(v1, tmp_path / "reg",
                        fetch=lambda p, f: _fake_fetch(p, f, sha="0" * 64))
    assert proposal["can_accept"] is False


def test_file_changed_after_proposal_is_refused(tmp_path, wheels):
    v1, _ = wheels
    registry = tmp_path / "reg"
    proposal = _propose(v1, registry)
    (tmp_path / "swap").mkdir()
    other = _make_wheel(tmp_path / "swap" / "demo-1.0-py3-none-any.whl", "demo", "1.0", "VALUE = 9\n")
    with pytest.raises(ba.AcceptanceError):
        ba.accept(proposal, other, registry, operator="reviewer-a", decision="accept", fetch=_fake_fetch)
    assert _baseline_count(registry) == 0


def test_reject_is_recorded_and_registers_nothing(tmp_path, wheels):
    v1, _ = wheels
    registry = tmp_path / "reg"
    proposal = _propose(v1, registry)
    assert ba.accept(proposal, v1, registry, operator="reviewer-a", decision="reject") is None
    assert _baseline_count(registry) == 0
    entry = json.loads((registry / ba.AUDIT_FILE).read_text(encoding="utf-8").splitlines()[-1])
    assert entry["outcome"] == "rejected" and entry["operator"] == "reviewer-a"


def test_update_to_new_version_needs_explicit_replacement(tmp_path, wheels):
    v1, v2 = wheels
    registry = tmp_path / "reg"
    ba.accept(_propose(v1, registry), v1, registry, operator="a", decision="accept", fetch=_fake_fetch)
    proposal = _propose(v2, registry)
    assert proposal["replaces_versions"] == ["1.0"]
    with pytest.raises(ba.AcceptanceError):
        ba.accept(proposal, v2, registry, operator="a", decision="accept", fetch=_fake_fetch)
    ba.accept(proposal, v2, registry, operator="a", decision="accept", replace_existing=True, fetch=_fake_fetch)
    assert _baseline_count(registry) == 2
    ok, count = ba.verify_audit(registry)
    assert ok and count == 3


def test_audit_chain_detects_tampering(tmp_path, wheels):
    v1, _ = wheels
    registry = tmp_path / "reg"
    ba.accept(_propose(v1, registry), v1, registry, operator="a", decision="accept", fetch=_fake_fetch)
    ba.append_audit(registry, {"kind": "baseline_decision", "decision": "reject", "operator": "b"})
    path = registry / ba.AUDIT_FILE
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0]); tampered["operator"] = "someone-else"
    lines[0] = json.dumps(tampered, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert ba.verify_audit(registry)[0] is False


def test_operator_is_required(tmp_path, wheels):
    v1, _ = wheels
    registry = tmp_path / "reg"
    proposal = _propose(v1, registry)
    with pytest.raises(ba.AcceptanceError):
        ba.accept(proposal, v1, registry, operator="  ", decision="accept", fetch=_fake_fetch)
    assert _baseline_count(registry) == 0
