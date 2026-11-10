"""Экспорт SBOM (Software Bill of Materials) пакетно-нейросетевой программы.

Формат: JSON, совместимый с CycloneDX 1.5 (упрощённый).
Включает: зависимости, собственные модули, параметры модели, метаданные.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .spec import CLASSES, LEVELS, PackageSpec

_VERSION = "1.5"
_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"


def export_sbom(spec: PackageSpec, pkg_dir: str | Path, out_path: str | Path) -> dict:
    """Формирует SBOM и записывает в файл JSON. Возвращает словарь SBOM."""
    pkg_dir = Path(pkg_dir)
    out_path = Path(out_path)

    # подсчёт SHA-256 файла модели
    model_file = pkg_dir / "model.pt"
    model_sha256 = _sha256_file(model_file) if model_file.exists() else ""

    # компоненты-зависимости
    components: list[dict] = []
    for dep in spec.deps:
        comp: dict = {
            "type": "library",
            "name": dep.name,
            "version": dep.version,
            "purl": f"pkg:pypi/{dep.name.lower().replace('_', '-')}@{dep.version}",
            "hashes": [{"alg": "SHA-256", "content": dep.sha256}] if dep.sha256 else [],
            "source": dep.source,
        }
        if dep.requires:
            comp["dependencies"] = dep.requires
        components.append(comp)

    # собственные модули (исходный код)
    for mod in spec.modules:
        components.append({
            "type": "file",
            "name": mod.name,
            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(mod.code.encode()).hexdigest()}],
        })

    # компонент модели нейросети
    model_comp: dict = {
        "type": "machine-learning-model",
        "name": f"{spec.name}/model",
        "version": spec.version,
        "hashes": [{"alg": "SHA-256", "content": model_sha256}] if model_sha256 else [],
        "properties": [
            {"name": "integrityguard:classes", "value": ", ".join(CLASSES)},
            {"name": "integrityguard:levels", "value": ", ".join(LEVELS)},
            {"name": "integrityguard:unsafe_format", "value": str(spec.unsafe_format)},
        ],
    }
    if spec.dataset_sha256:
        model_comp["properties"].append(
            {"name": "integrityguard:dataset_sha256", "value": spec.dataset_sha256}
        )
    components.append(model_comp)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": _VERSION,
        "$schema": _SCHEMA,
        "version": 1,
        "serialNumber": f"urn:uuid:{_uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": [{"name": "IntegrityGuard", "version": "1.0"}],
            "component": {
                "type": "application",
                "name": spec.name,
                "version": spec.version,
                "properties": [
                    {"name": "integrityguard:signed_ok", "value": str(spec.signed_ok)},
                ],
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": f"pkg:pypi/{dep.name.lower().replace('_', '-')}@{dep.version}",
                "dependsOn": dep.requires,
            }
            for dep in spec.deps
        ],
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8")
    return sbom


def sbom_summary(sbom: dict) -> str:
    """Краткая сводка SBOM в человекочитаемом виде."""
    meta = sbom.get("metadata", {})
    comp_meta = meta.get("component", {})
    comps = sbom.get("components", [])
    libs = [c for c in comps if c.get("type") == "library"]
    files = [c for c in comps if c.get("type") == "file"]
    models = [c for c in comps if c.get("type") == "machine-learning-model"]
    lines = [
        f"SBOM: {comp_meta.get('name', '?')} v{comp_meta.get('version', '?')}",
        f"  Сформирован: {meta.get('timestamp', '?')}",
        f"  Зависимости: {len(libs)} пакетов",
        f"  Модули:      {len(files)} файлов",
        f"  ML-моделей:  {len(models)}",
    ]
    return "\n".join(lines)


# ------------------------------------------------------------------ утилиты

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _uuid4() -> str:
    import uuid
    return str(uuid.uuid4())
