"""Convert a clean PyPI wheel and DataDog compromised-package archive to IG pairs.

Reads archive members as bytes only. It never installs, imports, or executes package
code, and writes no package source. It reports predictions from in-memory package
specs. The converter currently supports the DataDog PyPI archive's preserved tree.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MAX_FILES = 100_000
MAX_BYTES = 1024 * 1024 * 1024
EVIDENCE = "https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3"
REF_URL = "https://files.pythonhosted.org/packages/9a/df/4b34e86f447d1f8f9aa9991e6fdb877030c8e3b633283ab37f5a616f6a24/elementary_data-0.23.2-py3-none-any.whl"
CAND_URL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/compromised_lib/elementary-data/0.23.3/2026-04-24-elementary-data-v0.23.3.zip"


def _read_zip(zf: zipfile.ZipFile, password: bytes | None = None, package_prefix: str | None = None):
    files, total = {}, 0
    for info in zf.infolist():
        p = PurePosixPath(info.filename)
        if (p.is_absolute() or ".." in p.parts or "\\" in info.filename
                or any(":" in part for part in p.parts)):
            raise ValueError(f"Небезопасный путь архива: {info.filename!r}")
        if info.is_dir():
            continue
        if len(files) >= MAX_FILES or info.file_size > MAX_BYTES:
            raise ValueError("Архив превышает ограничения по числу или размеру файлов")
        total += info.file_size
        if total > MAX_BYTES:
            raise ValueError("Архив превышает общий лимит распаковки 1 GiB")
        parts = p.parts
        if package_prefix:
            try:
                pos = parts.index(package_prefix)
            except ValueError:
                continue
            rel = PurePosixPath(*parts[pos + 1:])
        else:
            rel = p
        keep = rel.suffix.lower() in {".py", ".pth"} or rel.name in {"METADATA", "PKG-INFO"}
        if not keep:
            continue
        data = zf.read(info, pwd=password) if info.flag_bits & 1 else zf.read(info)
        files[str(rel)] = data
    if not any(k.endswith((".dist-info/METADATA", ".egg-info/PKG-INFO")) or k == "PKG-INFO"
               for k in files):
        raise ValueError("В архиве нет dist-info/METADATA или egg-info/PKG-INFO")
    return files


def _to_spec(files: dict[str, bytes], state):
    meta_bytes = next(v for k, v in files.items()
                      if k.endswith((".dist-info/METADATA", ".egg-info/PKG-INFO")) or k == "PKG-INFO")
    metadata = BytesParser().parsebytes(meta_bytes)
    name = (metadata.get("Name") or "").lower().replace("_", "-")
    version = metadata.get("Version") or ""
    if not name or not version:
        raise ValueError("METADATA должен содержать Name и Version")
    deps = []
    for req in metadata.get_all("Requires-Dist", []):
        match = re.match(r"\s*([A-Za-z0-9_.-]+)", req)
        if match:
            dep = match.group(1).lower().replace("_", "-")
            deps.append({"name": dep, "version": "unspecified", "sha256": hashlib.sha256(req.encode()).hexdigest()})
    from integrityguard.spec import Dep, Module, PackageSpec
    deps = [Dep(d["name"], d["version"], d["sha256"], "pypi") for d in deps]
    modules = [Module("src_" + hashlib.sha256(path.encode()).hexdigest()[:16], value.decode("utf-8", "replace"))
               for path, value in sorted(files.items()) if PurePosixPath(path).suffix.lower() in {".py", ".pth"}]
    spec = PackageSpec(name, version, deps, modules, state, True, False, "")
    return spec, metadata.get("License-Expression") or metadata.get("License") or ""


def convert(reference_wheel: Path, compromised_archive: Path, model_paths: list[Path], out: Path,
            evidence: str = EVIDENCE, package_prefix: str = "elementary-data",
            case_id: str = "elementary-data-0.23.2-to-0.23.3",
            candidate_format: str = "datadog", label: str = "dependency", seed: int = 260424,
            reference_url: str = REF_URL, candidate_url: str = CAND_URL):
    from integrityguard.corpus import gen_project
    from tools.eval_external_packages import evaluate_specs

    with zipfile.ZipFile(reference_wheel) as zf:
        reference_files = _read_zip(zf)
    with zipfile.ZipFile(compromised_archive) as zf:
        if candidate_format == "datadog":
            candidate_files = _read_zip(zf, password=b"infected", package_prefix=package_prefix)
        elif candidate_format == "wheel":
            candidate_files = _read_zip(zf)
        else:
            raise ValueError("candidate_format должен быть datadog или wheel")
    generated = gen_project(seed, with_specs=True, class_name="clean")
    if generated is None:
        raise RuntimeError("Не удалось создать нейтральные state_dict для формата IntegrityGuard")
    _, project = generated
    reference, ref_license = _to_spec(reference_files, project["ref"].state)
    candidate, cand_license = _to_spec(candidate_files, project["ref"].state)
    expected_name = package_prefix.lower().replace("_", "-")
    if reference.name != candidate.name or reference.name != expected_name:
        raise ValueError(f"Имена эталона и кандидата не совпадают с {expected_name}")
    predictions = [evaluate_specs(reference, candidate, model) for model in model_paths]
    return {"scope": "one externally labelled PyPI package pair; static package-delta only",
            "id": case_id, "label": label,
            "conversion": {"seed": seed, "candidate_format": candidate_format,
                           "package_prefix": package_prefix,
                           "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
            "reference": {"name": reference.name, "version": reference.version,
                          "modules": len(reference.modules), "dependencies": len(reference.deps), "license": ref_license},
            "candidate": {"name": candidate.name, "version": candidate.version,
                          "modules": len(candidate.modules), "dependencies": len(candidate.deps), "license": cand_license},
            "reference_url": reference_url, "candidate_dataset_url": candidate_url,
            "label_evidence": evidence,
            "sha256": {"reference_wheel": hashlib.sha256(reference_wheel.read_bytes()).hexdigest(),
                       "candidate_artifact": hashlib.sha256(compromised_archive.read_bytes()).hexdigest()},
            "safety": {"source_imported_or_executed": False, "source_files_written_in_this_run": False,
                       "model_weights": "same fixed synthetic state_dict attached to both sides; not a model-weight test"},
            "predictions": predictions, "report_path": str(out.resolve())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-wheel", required=True, type=Path)
    parser.add_argument("--datadog-archive", required=True, type=Path,
                        help="candidate archive; encrypted DataDog ZIP or candidate wheel")
    parser.add_argument("--model", required=True, type=Path, action="append", help="повторить для каждой модели")
    parser.add_argument("--out", required=True, type=Path, help="JSON отчёт; пакеты/исходники не сохраняются")
    parser.add_argument("--evidence", default=EVIDENCE)
    parser.add_argument("--package-prefix", default="elementary-data",
                        help="каталог пакета внутри DataDog ZIP")
    parser.add_argument("--candidate-format", choices=("datadog", "wheel"), default="datadog")
    parser.add_argument("--case-id", default="elementary-data-0.23.2-to-0.23.3")
    parser.add_argument("--label", choices=("clean", "dependency"), default="dependency")
    parser.add_argument("--seed", type=int, default=260424)
    parser.add_argument("--reference-url", default=REF_URL)
    parser.add_argument("--candidate-url", default=CAND_URL)
    args = parser.parse_args()
    report = convert(args.reference_wheel, args.datadog_archive, args.model, args.out, args.evidence,
                     args.package_prefix, args.case_id, args.candidate_format, args.label, args.seed,
                     args.reference_url, args.candidate_url)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
