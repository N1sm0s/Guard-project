import copy
import json
from pathlib import Path

from integrityguard.collect import save_package
from integrityguard.corpus import gen_project
from integrityguard.spec import Module
from integrityguard.system import IntegrityGuard
from integrityguard.report import generate


MODEL = Path(__file__).resolve().parents[1] / "models" / "detector.pt"


def package_spec(seed=4102):
    generated = gen_project(seed, with_specs=True, class_name="clean")
    assert generated is not None
    return copy.deepcopy(generated[1]["ref"])


def test_unbaselined_package_is_reviewed_without_becoming_a_baseline(tmp_path):
    package = tmp_path / "unknown"
    save_package(package_spec(), package)
    guard = IntegrityGuard(tmp_path / "registry", MODEL, key=b"test-signing-key", public_intel_enabled=False)

    event = guard.check(package)
    guard.respond(event)

    assert event["verdict"] == "REVIEW"
    assert event["analysis_mode"] == "reference_missing"
    assert event["baseline_version"] is None
    assert event["hash_control"] is None
    assert event["model_score"] is None
    assert event["score"] is None and event["risk_score"] is None
    assert event["comparison_performed"] is False
    assert "unknown" not in [p.name for p in (tmp_path / "registry" / "baselines").glob("*")]
    stored = json.loads((tmp_path / "registry" / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert stored["analysis_mode"] == "reference_missing"
    report = generate(event, tmp_path / "report.pdf")
    assert report.is_file() and report.read_bytes().startswith(b"%PDF-")

    strict = guard.check(package, strict=True)
    assert strict["verdict"] == "BLOCK"
    assert any("строгий режим" in rule for rule in strict["rules"])


def test_unbaselined_package_does_not_receive_a_heuristic_score(tmp_path):
    spec = package_spec(4103)
    dep = spec.deps[0]
    dep.name = "reqeusts"
    dep.source = "url"
    spec.modules.append(Module("loader", "import subprocess\neval('1')\n"))
    package = tmp_path / "suspicious"
    save_package(spec, package)
    guard = IntegrityGuard(tmp_path / "registry", MODEL, key=b"test-signing-key", public_intel_enabled=False)

    event = guard.assess_unbaselined(package)

    assert event["verdict"] == "REVIEW"
    assert event["score"] is None and event["risk_score"] is None
    assert "доверенный эталон не найден" in event["rules"][0]
    assert event["objective_facts"]["manifest_parsed"] is True


def test_unbaselined_unsafe_model_is_blocked_without_loading_pickle(tmp_path):
    spec = package_spec(4104)
    spec.unsafe_format = True
    package = tmp_path / "unsafe"
    save_package(spec, package)
    guard = IntegrityGuard(tmp_path / "registry", MODEL, key=b"test-signing-key", public_intel_enabled=False)

    event = guard.assess_unbaselined(package)

    assert event["verdict"] == "BLOCK"
    assert event["risk_score"] is None
    assert any("pickle" in rule for rule in event["rules"])
    assert event["score"] is None


def test_unreadable_incoming_package_is_recorded_as_incomplete_review(tmp_path):
    invalid = tmp_path / "invalid"
    invalid.mkdir()
    (invalid / "manifest.json").write_text("{", encoding="utf-8")
    guard = IntegrityGuard(tmp_path / "registry", MODEL, key=b"test-signing-key", public_intel_enabled=False)

    event = guard.assessment_error(invalid, "manifest.json повреждён")
    guard.respond(event)

    assert event["verdict"] == "REVIEW"
    assert event["assessment_complete"] is False
    assert event["analysis_mode"] == "intake_validation_error"
    assert event["score"] is None and event["risk_score"] is None
    assert json.loads((tmp_path / "registry" / "events.jsonl").read_text(encoding="utf-8"))[
        "analysis_mode"] == "intake_validation_error"
