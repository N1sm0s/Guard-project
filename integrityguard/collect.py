"""Сбор состояния ПНП с диска и запись пакетов (формат каталога пакета).

Каталог пакета:
    manifest.json   имя, версия, зависимости (имя, версия, sha256, источник, requires, размер), хеш данных
    manifest.sig    HMAC-SHA256 по всем файлам пакета (подпись выпуска)
    model.pt        веса модели (state_dict, torch.save)
    src/*.py        собственные модули
    vendor/<dep>/   исходный код зависимостей (необязательно; нужен для анализа их возможностей)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections import OrderedDict
from pathlib import Path

import numpy as np
import torch

from .scan import scan_pickle
from .spec import Dep, Module, PackageSpec


def file_sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fingerprint(pkg_dir) -> str:
    """Сводный хеш всех файлов пакета (кроме самой подписи)."""
    root = Path(pkg_dir)
    h = hashlib.sha256()
    for p in sorted(q for q in root.rglob("*") if q.is_file() and q.name != "manifest.sig"):
        h.update(p.relative_to(root).as_posix().encode())
        h.update(file_sha256(p).encode())
    return h.hexdigest()


def sign_package(pkg_dir, key: bytes) -> str:
    sig = hmac.new(key, fingerprint(pkg_dir).encode(), hashlib.sha256).hexdigest()
    (Path(pkg_dir) / "manifest.sig").write_text(sig, encoding="utf-8")
    return sig


def verify_package(pkg_dir, key: bytes | None) -> bool:
    sig = Path(pkg_dir) / "manifest.sig"
    if key is None or not sig.exists():
        return False
    good = hmac.new(key, fingerprint(pkg_dir).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(good, sig.read_text(encoding="utf-8-sig").strip())


def _read(p: Path) -> str:
    return p.read_bytes().decode("utf-8-sig", "replace")       # UTF-8, в том числе с меткой BOM (Блокнот Windows)


def load_package(pkg_dir, key: bytes | None = None) -> PackageSpec:
    """Чтение каталога пакета. Небезопасно сериализованная модель НЕ загружается."""
    root = Path(pkg_dir)
    if not (root / "manifest.json").is_file():
        raise ValueError(f"в каталоге «{root}» нет manifest.json — это не каталог пакета")
    try:
        man = json.loads(_read(root / "manifest.json"))
        name, version = str(man["name"]), str(man["version"])
        dep_list = [dict(d, name=str(d["name"]), version=str(d["version"])) for d in man.get("dependencies", [])]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise ValueError(f"manifest.json повреждён или неполон: {e}") from e
    model_path = (root / str(man.get("model", "model.pt"))).resolve()
    if root.resolve() not in model_path.parents:
        raise ValueError("manifest.json: путь к модели выходит за пределы каталога пакета")
    if not model_path.is_file():
        raise ValueError(f"файл модели не найден: {model_path.name}")
    if any(not d["name"] or set(d["name"]) & set('/\\:') or d["name"].startswith(".") for d in dep_list) \
            or set(name) & set('/\\:') or name.startswith("."):
        raise ValueError("manifest.json: недопустимое имя пакета или зависимости")
    deps = []
    for d in dep_list:
        vdir = root / "vendor" / d["name"]
        code = "\n".join(_read(p) for p in sorted(vdir.rglob("*.py"))) if vdir.is_dir() else ""
        deps.append(Dep(d["name"], d["version"], d.get("sha256", ""), d.get("source", "pypi"),
                        list(d.get("requires", [])), int(d.get("size", len(code))), code))
    src = root / "src"
    mods = [Module(p.stem, _read(p)) for p in sorted(src.glob("*.py"))] if src.is_dir() else []
    unsafe, _ = scan_pickle(model_path.read_bytes())
    state: dict = {}
    if not unsafe:
        try:
            obj = torch.load(model_path, map_location="cpu", weights_only=True)
            if isinstance(obj.get("state_dict"), dict):          # распространённая обёртка {"state_dict": ...}
                obj = obj["state_dict"]
            state = OrderedDict((k, v) for k, v in obj.items() if isinstance(v, torch.Tensor))
        except Exception:
            unsafe = True
    return PackageSpec(name, version, deps, mods, state, verify_package(root, key), unsafe,
                       str(man.get("dataset_sha256", "")))


def save_package(spec: PackageSpec, pkg_dir, key: bytes | None = None) -> None:
    """Запись пакета на диск. Если spec.signed_ok ложно — пишется неверная подпись."""
    root = Path(pkg_dir)
    (root / "src").mkdir(parents=True, exist_ok=True)
    for m in spec.modules:
        (root / "src" / f"{m.name}.py").write_bytes(m.code.encode())
    for d in spec.deps:
        if d.code:
            (root / "vendor" / d.name).mkdir(parents=True, exist_ok=True)
            (root / "vendor" / d.name / "__init__.py").write_bytes(d.code.encode())
    if spec.unsafe_format:
        # демонстрационный небезопасный pickle: ссылка на постороннюю функцию (не вызывается при записи)
        torch.save({"state_dict": dict(spec.state), "loader": os.path.join}, root / "model.pt")
    else:
        torch.save(OrderedDict(spec.state), root / "model.pt")
    man = {"name": spec.name, "version": spec.version, "model": "model.pt", "dataset_sha256": spec.dataset_sha256,
           "dependencies": [{"name": d.name, "version": d.version, "sha256": d.sha256, "source": d.source,
                             "requires": d.requires, "size": d.size} for d in spec.deps]}
    (root / "manifest.json").write_bytes(json.dumps(man, ensure_ascii=False, indent=1).encode())
    if key is not None:
        sign_package(root, key if spec.signed_ok else b"wrong-" + key)


def save_control(path, x: torch.Tensor, y: torch.Tensor) -> None:
    np.savez(path, X=x.numpy().astype("float32"), y=y.numpy().astype("int64"))


def load_control(path) -> tuple[torch.Tensor, torch.Tensor]:
    z = np.load(path, allow_pickle=False)
    return torch.from_numpy(z["X"]).float(), torch.from_numpy(z["y"]).long()


def export_corpus(out_dir, n_projects=2, seed=1000, key: bytes = b"demo-signing-key",
                  class_names: list[str] | None = None) -> list[dict]:
    """Выгрузка корпуса примеров нарушений в виде каталогов пакетов с разметкой labels.json."""
    from .corpus import gen_project
    from .spec import CLASSES
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "signing.key").write_bytes(key)
    labels = []
    for p in range(n_projects):
        class_name = class_names[p % len(class_names)] if class_names else None
        generated = gen_project(seed + p * 41, with_specs=True, class_name=class_name)
        if generated is None:
            raise RuntimeError(f"Не удалось сгенерировать демонстрационный проект {p + 1} после 40 попыток")
        samples, proj = generated
        pdir = out / f"project_{p:03d}"
        save_package(proj["ref"], pdir / "reference", key)
        save_control(pdir / "control.npz", proj["x"], proj["y"])
        (pdir / "trusted_index.json").write_text(json.dumps(proj["index"], indent=1), encoding="utf-8")
        for i, s in enumerate(samples):
            cls = CLASSES[s["y"]]
            cdir = pdir / "candidates" / f"{i:02d}_{cls}_{s['variant']}"
            save_package(s["spec"], cdir, key)
            (pdir / "candidates" / f"{cdir.name}.index.json").write_text(json.dumps(s["index"], indent=1), encoding="utf-8")
            labels.append({"project": pdir.name, "candidate": cdir.name, "class": cls, "variant": s["variant"],
                           "compromised": [k for k, v in zip(s["keys"], s["node_y"]) if v > 0],
                           "hash_control_flags": bool(s["hash_flag"])})
    (out / "labels.json").write_text(json.dumps(labels, ensure_ascii=False, indent=1), encoding="utf-8")
    return labels
