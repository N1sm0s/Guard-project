"""Evaluate dependency-threat decisions on externally labelled IntegrityGuard package pairs.

Inputs must be pre-converted IntegrityGuard packages (manifest.json + model.pt),
from a verified clean reference and a candidate. Archives are unpacked with path,
symlink, file-count, and expanded-size checks. No package code is imported or run.

Manifest JSON format:
{"pairs": [{"id":"case-1", "reference":"clean.zip",
            "candidate":"compromised.zip", "label":"dependency",
            "evidence":"advisory or dataset URL"}]}

Only labels "clean" and "dependency" are accepted. This is a scoped pairwise
package-integrity evaluation, not a general malware benchmark or a test of the
other threat classes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ALLOWED_LABELS = {"clean", "dependency"}
MAX_FILES = 100_000
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024


def _safe_extract(archive: Path, destination: Path) -> Path:
    """Extract a package archive without traversal, links, or unbounded expansion."""
    total = 0
    count = 0
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            count += 1
            if count > MAX_FILES:
                raise ValueError(f"{archive}: превышен предел числа файлов ({MAX_FILES})")
            member = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if (member.is_absolute() or ".." in member.parts or "\\" in info.filename
                    or any(":" in part for part in member.parts)):
                raise ValueError(f"{archive}: небезопасный путь внутри ZIP: {info.filename!r}")
            if stat.S_ISLNK(mode):
                raise ValueError(f"{archive}: символические ссылки запрещены: {info.filename!r}")
            if info.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"{archive}: файл превышает лимит: {info.filename!r}")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError(f"{archive}: превышен суммарный лимит распаковки")
            target = destination.joinpath(*member.parts).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise ValueError(f"{archive}: путь выходит из каталога распаковки")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
    roots = [p.parent for p in destination.rglob("manifest.json")
             if (p.parent / "model.pt").is_file()]
    if len(roots) != 1:
        raise ValueError(f"{archive}: ожидался ровно один пакет IntegrityGuard с manifest.json и model.pt")
    return roots[0]


def _package(path: Path, scratch: Path, tag: str) -> Path:
    path = path.resolve(strict=True)
    if path.is_dir():
        if not (path / "manifest.json").is_file() or not (path / "model.pt").is_file():
            raise ValueError(f"{path}: ожидался пакет с manifest.json и model.pt")
        return path
    if path.suffix.lower() != ".zip":
        raise ValueError(f"{path}: поддерживаются каталоги и ZIP-архивы")
    dest = scratch / tag
    dest.mkdir(parents=True, exist_ok=False)
    return _safe_extract(path, dest)


def evaluate_specs(reference, candidate, model_path: Path) -> dict:
    """Evaluate already parsed package specs entirely in memory (no source files written)."""
    import torch
    from integrityguard.features import extract
    from integrityguard.model import collate, load_detector
    from integrityguard.spec import CLASSES
    from integrityguard.system import BLOCK, REVIEW, _risk_score, opaque_source_anomalies

    model_path = model_path.resolve(strict=True)
    model, ck = load_detector(model_path)
    index = {d.name: {d.version: d.sha256} for d in reference.deps}
    sample = extract(reference, candidate, index, probe=None)
    with torch.no_grad():
        out = model(collate([sample]))
    probs = torch.softmax(out["logits"][0], -1)
    score = float(1 - probs[0])
    threshold, block_threshold = float(ck["threshold"]), float(ck["block_threshold"])
    neural_verdict = BLOCK if score >= block_threshold else REVIEW if score >= threshold else "ALLOW"
    anomalies = opaque_source_anomalies(reference, candidate)
    verdict = REVIEW if anomalies and neural_verdict == "ALLOW" else neural_verdict
    neural_class = CLASSES[int(probs[1:].argmax()) + 1]
    predicted = neural_class if neural_verdict != "ALLOW" else "clean"
    final_class = "dependency" if anomalies and neural_verdict == "ALLOW" else predicted
    risk_score = _risk_score(score, threshold, block_threshold)
    if anomalies:
        risk_score = max(risk_score, 70 if verdict == BLOCK else 30 if verdict == REVIEW else 0)
    return {"model": str(model_path),
            "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
            "evaluator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "torch_version": str(torch.__version__),
            "score": score, "risk_score": risk_score,
            "verdict": verdict, "neural_verdict": neural_verdict, "neural_class": neural_class,
            "predicted_class": final_class, "policy_finding": "opaque_source_format" if anomalies else None,
            "source_anomalies": anomalies,
            "probabilities": {c: round(float(p), 6) for c, p in zip(CLASSES, probs)},
            "threshold": threshold, "block_threshold": block_threshold,
            "source_files_written": False}


def evaluate(manifest_path: Path, model_path: Path, out_path: Path) -> dict:
    from integrityguard.system import IntegrityGuard

    manifest_path = manifest_path.resolve(strict=True)
    model_path = model_path.resolve(strict=True)
    data = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    pairs = data.get("pairs") if isinstance(data, dict) else None
    if not isinstance(pairs, list) or not pairs:
        raise ValueError("manifest должен содержать непустой массив pairs")
    checked = []
    with tempfile.TemporaryDirectory(prefix="ig_external_eval_") as temp_name:
        temp = Path(temp_name)
        for i, row in enumerate(pairs):
            if not isinstance(row, dict) or row.get("label") not in ALLOWED_LABELS:
                raise ValueError(f"pairs[{i}]: label должен быть clean или dependency")
            if not row.get("evidence"):
                raise ValueError(f"pairs[{i}]: укажите evidence для проверяемой разметки")
            ref_path = Path(row["reference"])
            cand_path = Path(row["candidate"])
            if not ref_path.is_absolute():
                ref_path = manifest_path.parent / ref_path
            if not cand_path.is_absolute():
                cand_path = manifest_path.parent / cand_path
            reference = _package(ref_path, temp / "archives", f"ref_{i}")
            candidate = _package(cand_path, temp / "archives", f"cand_{i}")
            registry = temp / f"registry_{i}"
            guard = IntegrityGuard(registry, model_path, key=None)
            guard.register_baseline(reference)
            event = guard.check(candidate, stage="build", strict=False)
            checked.append({
                "id": row.get("id", f"pair-{i + 1}"),
                "label": row["label"],
                "detected": event["verdict"] != "ALLOW",
                "predicted_class": event.get("threat"),
                "verdict": event["verdict"],
                "risk_score": event.get("risk_score"),
                "evidence": row["evidence"],
            })
    per_class = {}
    for label in sorted(ALLOWED_LABELS):
        rows = [x for x in checked if x["label"] == label]
        tp = sum(x["detected"] for x in rows)
        per_class[label] = {"n": len(rows), "detected": tp,
                            "recall": tp / len(rows) if rows else None}
    bad = [x for x in checked if x["label"] == "dependency"]
    clean = [x for x in checked if x["label"] == "clean"]
    tp = sum(x["detected"] for x in bad)
    fp = sum(x["detected"] for x in clean)
    result = {
        "scope": "external package-pair evaluation; clean vs dependency only",
        "model": str(model_path.resolve()),
        "sample_count": len(checked),
        "metrics": {
            "dependency_recall": tp / len(bad) if bad else None,
            "clean_false_positive_rate": fp / len(clean) if clean else None,
            "dependency_n": len(bad), "clean_n": len(clean),
            "per_class": per_class,
        },
        "limits": [
            "Results apply only to externally labelled IntegrityGuard package pairs and the dependency class.",
            "This adapter does not establish performance on model-weight or runtime attack classes.",
            "Reference/candidate identity and label evidence must be independently verified.",
            "No source is imported or executed; model.pt is loaded with the application's weights_only policy.",
        ],
        "results": checked,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="JSON-реестр проверенных пар")
    parser.add_argument("--model", required=True, type=Path, help="detector.pt")
    parser.add_argument("--out", required=True, type=Path, help="путь JSON-отчёта")
    args = parser.parse_args()
    result = evaluate(args.manifest, args.model, args.out)
    print(json.dumps(result["metrics"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
