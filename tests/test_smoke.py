"""Проверки: сканер, согласованность «корпус в памяти» <-> «пакет на диске», сквозной цикл."""
import json

import torch

from integrityguard.collect import export_corpus, load_control, load_package
from integrityguard.corpus import gen_project
from integrityguard.features import BEHAV_DIM, PARAM_DIM, STRUCT_DIM, BehaviorProbe, extract
from integrityguard.scan import scan_code, scan_pickle, typosquat_score
from integrityguard.spec import CLASSES
from integrityguard.recall import class_metric_values


def test_scan_code():
    caps, imps = scan_code("import subprocess, requests\nopen('f', 'w')\neval('1')\n")
    assert {"process", "network", "file_write", "dynamic_exec"} <= caps and "requests" in imps
    assert scan_code("x = 1\nopen('f')\n")[0] == frozenset()
    assert "obfuscation" in scan_code("def (:")[0]


def test_scan_pickle(tmp_path):
    import os
    torch.save({"w": torch.zeros(2)}, tmp_path / "ok.pt")
    torch.save({"w": torch.zeros(2), "f": os.path.join}, tmp_path / "bad.pt")
    assert not scan_pickle((tmp_path / "ok.pt").read_bytes())[0]
    assert scan_pickle((tmp_path / "bad.pt").read_bytes())[0]


def test_typosquat():
    known = frozenset({"requests", "numpy"})
    assert typosquat_score("requests", known) == 0 and typosquat_score("reqeusts", known) > 0.8


def test_legacy_recall_report_missing_new_threat_class():
    legacy = {"per_class": {"dependency": {"recall": 0.75}}, "overall": {"recall": 0.75}}
    values = class_metric_values(legacy, "recall", ["dependency", "adversarial"])
    assert values == [0.75, None]


def test_pdf_report_supports_cyrillic_and_unicode_font(tmp_path):
    from datetime import datetime

    from integrityguard.report import _format_event_time, generate

    output = tmp_path / "Папка отчётов" / "проверка_целостности.pdf"
    event = {
        "verdict": "REVIEW", "package": "пример-пакета", "version": "1.0",
        "baseline_version": "0.9", "stage": "build", "score": 0.42,
        "time": "2026-11-10T14:51:02+00:00",
        "threat": "dependency", "rules": ["Изменена зависимость — требуется проверка"],
        "actions": ["Проверьте контрольный список"], "levels": {"structural": 0.42},
        "suspects": [{"component": "модуль", "score": 0.42}],
        "hash_control": True, "timing_ms": {"total": 12.3},
    }
    assert generate(event, output) == output
    assert output.is_file() and output.read_bytes().startswith(b"%PDF-")
    utc_time = datetime.fromisoformat(event["time"]).astimezone()
    expected = utc_time.strftime("%d.%m.%Y %H:%M:%S")
    assert _format_event_time(event["time"]).startswith(expected)
    assert "UTC" in _format_event_time(event["time"])


def test_external_evaluator_scoped_dependency_pair(tmp_path):
    import json
    from pathlib import Path

    from integrityguard.collect import save_package
    from integrityguard.corpus import gen_project
    from tools.eval_external_packages import evaluate

    generated = gen_project(712, with_specs=True, class_name="dependency")
    assert generated is not None
    samples, project = generated
    reference, candidate = tmp_path / "reference", tmp_path / "candidate"
    save_package(project["ref"], reference)
    save_package(samples[0]["spec"], candidate)
    manifest = tmp_path / "pairs.json"
    manifest.write_text(json.dumps({"pairs": [{"id": "synthetic-smoke", "reference": "reference",
        "candidate": "candidate", "label": "dependency", "evidence": "test fixture only"}]}), encoding="utf-8")
    report = evaluate(manifest, Path(__file__).resolve().parents[1] / "models" / "detector.pt", tmp_path / "out.json")
    assert report["scope"].endswith("dependency only")
    assert report["metrics"]["dependency_n"] == 1
    assert (tmp_path / "out.json").is_file()


def test_disk_roundtrip_matches_memory(tmp_path):
    """Признаки, извлечённые из каталогов на диске, совпадают с признаками корпуса."""
    key = b"k"
    export_corpus(tmp_path, 1, seed=5, key=key)
    samples, _ = gen_project(5, with_specs=True)
    proj = tmp_path / "project_000"
    ref = load_package(proj / "reference", key)
    assert ref.signed_ok
    probe = BehaviorProbe(ref.state, *load_control(proj / "control.npz"), seed=5)
    labels = json.loads((tmp_path / "labels.json").read_text(encoding="utf-8"))
    assert len(labels) == len(samples)
    checked = 0
    for lb, s in zip(labels, samples):
        cdir = proj / "candidates" / lb["candidate"]
        cand = load_package(cdir, key)
        assert cand.signed_ok == s["spec"].signed_ok and cand.unsafe_format == s["spec"].unsafe_format
        if cand.unsafe_format:
            continue
        f = extract(ref, cand, json.loads((proj / "candidates" / f"{lb['candidate']}.index.json").read_text(encoding="utf-8")), probe)
        assert f["keys"] == s["keys"]
        assert f["x"].shape[1] == STRUCT_DIM and f["layers"].shape[1] == PARAM_DIM and f["behav"].shape[0] == BEHAV_DIM
        assert torch.allclose(f["x"], s["x"], atol=1e-5) and torch.equal(f["adj"], s["adj"])
        assert torch.allclose(f["layers"], s["layers"], atol=1e-4)
        assert torch.allclose(f["behav"], s["behav"], atol=1e-3)
        checked += 1
    assert checked == len(labels) and checked >= 1


def test_end_to_end(tmp_path):
    from integrityguard.corpus import build_corpus
    from integrityguard.system import IntegrityGuard
    from integrityguard.train import run_experiment
    samples = build_corpus(60, seed=3)
    assert {s["y"] for s in samples} == set(range(len(CLASSES)))
    assert len({s["pid"] for s in samples}) == len(samples)
    _, rep = run_experiment(samples, tmp_path / "run", epochs=25, ablation=False, log=lambda s: None)
    assert rep["hybrid"]["binary"]["auc"] > 0.9
    export_corpus(tmp_path / "pk", 1, seed=42)
    proj = tmp_path / "pk" / "project_000"
    g = IntegrityGuard(tmp_path / "reg", tmp_path / "run" / "detector.pt", (tmp_path / "pk" / "signing.key").read_bytes())
    g.register_baseline(proj / "reference", proj / "control.npz")
    ev = g.check(proj / "reference", index_path=proj / "trusted_index.json")
    assert ev["verdict"] == "ALLOW"                      # эталон против самого себя
    assert g.respond(ev) == 0 and (tmp_path / "reg" / "events.jsonl").exists()
    for bad in sorted(p for p in (proj / "candidates").iterdir() if p.is_dir()):
        if "pickle" in bad.name or "reinit" in bad.name:
            assert g.check(bad, index_path=f"{bad}.index.json")["verdict"] != "ALLOW"


def test_clean_updates_overlap_risky_capabilities():
    """Benign generator controls must overlap suspicious APIs and URL sources."""
    import numpy as np

    from integrityguard.corpus import legit_update
    from integrityguard.scan import scan_code
    from integrityguard.spec import Dep, PackageSpec

    state = {"net.0.weight": torch.ones(4, 4), "net.0.bias": torch.ones(4)}
    deps = [Dep(f"dependency-{i}", "1.0.0", str(i)) for i in range(8)]
    ref = PackageSpec("control", "1.0.0", deps, [], state)
    seen_caps = set()
    seen_sources = set()
    for seed in range(512):
        rng = np.random.default_rng(seed)
        g = torch.Generator().manual_seed(seed)
        cand = legit_update(ref, rng, g)
        seen_caps.update(c for module in cand.modules for c in scan_code(module.code)[0])
        seen_sources.update(d.source for d in cand.deps if ref.dep(d.name) is None)
    assert {"dynamic_exec", "unsafe_deser", "obfuscation"} <= seen_caps
    assert "url" in seen_sources


def test_opaque_python_payload_forces_review(tmp_path):
    """A binary blob disguised as new Python source is reviewed even if ML allows it."""
    import shutil

    from integrityguard.collect import export_corpus
    from integrityguard.model import HybridDetector, save_detector
    from integrityguard.system import IntegrityGuard, opaque_source_anomalies

    from types import SimpleNamespace

    ref_module = SimpleNamespace(name="mod", code="print('ok')\n")
    cand_module = SimpleNamespace(name="mod", code="print('ok')\n" + "\ufffd" * 1024)
    ref_spec = SimpleNamespace(modules=[ref_module])
    cand_spec = SimpleNamespace(modules=[cand_module])
    assert opaque_source_anomalies(ref_spec, cand_spec)
    assert not opaque_source_anomalies(ref_spec, ref_spec)

    export_corpus(tmp_path / "pk", 1, seed=27)
    proj = tmp_path / "pk" / "project_000"
    candidate = tmp_path / "opaque"
    shutil.copytree(proj / "reference", candidate)
    manifest = json.loads((candidate / "manifest.json").read_text(encoding="utf-8"))
    manifest["version"] = "1.0.1"
    (candidate / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    source_file = next((candidate / "src").glob("*.py"))
    source_file.write_bytes(source_file.read_bytes() + b"\xff" * 2048)

    detector_path = tmp_path / "always_allow.pt"
    save_detector(HybridDetector(), detector_path, {"threshold": 1.1, "block_threshold": 1.2})
    guard = IntegrityGuard(tmp_path / "registry", detector_path)
    guard.register_baseline(proj / "reference")
    event = guard.check(candidate)
    assert event["neural_verdict"] == "ALLOW"
    assert event["verdict"] == "REVIEW"
    assert event["policy_finding"] == "opaque_source_format"
    assert event["risk_score"] >= 30
    assert event["source_anomalies"]


def test_policy_rules_and_bad_input(tmp_path):
    """Модель с NaN не допускается; повреждённый манифест и выход за каталог дают понятную ошибку."""
    import shutil

    import pytest

    from integrityguard.collect import sign_package
    from integrityguard.model import HybridDetector, save_detector
    from integrityguard.system import IntegrityGuard
    key = b"demo-signing-key"
    export_corpus(tmp_path / "pk", 1, seed=7, key=key)
    proj = tmp_path / "pk" / "project_000"
    save_detector(HybridDetector(), tmp_path / "d.pt", {"threshold": 0.5, "block_threshold": 0.9})
    g = IntegrityGuard(tmp_path / "reg", tmp_path / "d.pt", key)
    g.register_baseline(proj / "reference", proj / "control.npz")
    g.register_baseline(g._base(load_package(proj / "reference", key).name) / "package")   # сам в себя — без потери данных
    assert (g._base(load_package(proj / "reference", key).name) / "package" / "manifest.json").exists()

    bad = tmp_path / "nan"
    shutil.copytree(proj / "reference", bad)
    st = torch.load(bad / "model.pt", weights_only=True)
    next(iter(st.values()))[0, 0] = float("nan")
    torch.save(st, bad / "model.pt")
    sign_package(bad, key)
    ev = g.check(bad)
    assert ev["verdict"] == "BLOCK" and ev["threat"] == "weights"

    esc = tmp_path / "esc"
    shutil.copytree(proj / "reference", esc)
    man = json.loads((esc / "manifest.json").read_text(encoding="utf-8"))
    man["model"] = "../nan/model.pt"
    (esc / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    with pytest.raises(ValueError):
        load_package(esc, key)
    (esc / "manifest.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError):
        load_package(esc, key)
    with pytest.raises(ValueError):
        g.check(tmp_path)                                   # не каталог пакета

    nokey = IntegrityGuard(tmp_path / "reg2", tmp_path / "d.pt")
    nokey.register_baseline(proj / "reference", proj / "control.npz")
    ev = nokey.check(proj / "reference")
    assert any("ключ подписи" in r for r in ev["rules"]) and not ev["hash_control"]
