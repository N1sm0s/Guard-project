"""Статический анализ артефактов: возможности кода (AST), pickle-опкоды, тайпосквоттинг."""
from __future__ import annotations

import ast
import difflib
import io
import math
import pickletools
import zipfile
from collections import Counter
from functools import lru_cache

POPULAR = [
    "numpy", "pandas", "scipy", "torch", "torchvision", "tensorflow", "keras", "scikit-learn",
    "requests", "urllib3", "certifi", "idna", "charset-normalizer", "setuptools", "wheel", "pip",
    "pyyaml", "protobuf", "grpcio", "pillow", "matplotlib", "tqdm", "click", "jinja2", "markupsafe",
    "flask", "fastapi", "uvicorn", "pydantic", "starlette", "httpx", "aiohttp", "boto3", "botocore",
    "transformers", "tokenizers", "datasets", "huggingface-hub", "safetensors", "onnx", "onnxruntime",
    "joblib", "psutil", "cryptography", "pyjwt", "sqlalchemy", "redis", "celery", "packaging",
    "typing-extensions", "six", "python-dateutil", "pytz", "attrs", "colorama", "regex", "filelock",
    "fsspec", "numba", "llvmlite", "sympy", "networkx", "mlflow", "wandb", "tensorboard", "opencv-python",
]

_NET = {"socket", "urllib", "http", "requests", "httpx", "aiohttp", "ftplib", "smtplib", "paramiko", "websocket"}
_PROC = {"subprocess", "pty"}
_DESER = {"pickle", "dill", "marshal", "shelve", "cloudpickle"}
_NATIVE = {"ctypes", "cffi"}
_PACK = {"base64", "zlib", "marshal", "codecs", "binascii", "lzma"}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


@lru_cache(maxsize=20000)
def scan_code(text: str) -> tuple[frozenset[str], frozenset[str]]:
    """Возвращает (возможности, импортируемые модули верхнего уровня) для исходного текста Python."""
    caps: set[str] = set()
    imports: set[str] = set()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return frozenset({"obfuscation"}), frozenset()   # неразбираемый код — сам по себе признак
    blob = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports.add(a.name.split(".")[0])
                if "setuptools.command" in a.name or "distutils.command" in a.name:
                    caps.add("install_hook")
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
            if "setuptools.command" in node.module or "distutils.command" in node.module:
                caps.add("install_hook")
        elif isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
            owner = f.value.id if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else ""
            if name in {"eval", "exec", "compile", "__import__"} and not owner or name == "import_module":
                caps.add("dynamic_exec")
            if owner == "os" and (name in {"system", "popen"} or name.startswith(("exec", "spawn"))):
                caps.add("process")
            if owner == "os" and name in {"remove", "unlink", "rename"}:
                caps.add("file_write")
            if name == "open" and not owner:
                mode = node.args[1] if len(node.args) > 1 else next(
                    (k.value for k in node.keywords if k.arg == "mode"), None)
                if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and set(mode.value) & set("wax+"):
                    caps.add("file_write")
            if any(k.arg == "cmdclass" for k in node.keywords):
                caps.add("install_hook")
        elif isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)) and len(node.value) >= 200:
            s = node.value if isinstance(node.value, str) else node.value.decode("latin1")
            if " " not in s[:200] and entropy(s) > 4.5:
                blob = True
    if imports & _NET:
        caps.add("network")
    if imports & _PROC:
        caps.add("process")
    if imports & _DESER:
        caps.add("unsafe_deser")
    if imports & _NATIVE:
        caps.add("native")
    if "shutil" in imports:
        caps.add("file_write")
    if blob and imports & _PACK:
        caps.add("obfuscation")
    return frozenset(caps), frozenset(imports)


_SAFE_GLOBAL_ROOTS = ("torch", "collections", "numpy", "_codecs")


def scan_pickle(data: bytes) -> tuple[bool, list[str]]:
    """Проверка сериализованной модели: (подозрительна, список недоверенных GLOBAL-ссылок).

    Формат torch.save — zip с data.pkl; ссылки на объекты вне белого списка означают,
    что при загрузке может быть исполнен произвольный код.
    """
    payloads = []
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            payloads = [z.read(n) for n in z.namelist() if n.endswith(".pkl")]
    else:
        payloads = [data]
    bad: list[str] = []
    for p in payloads:
        strings: list[str] = []
        try:
            for op, arg, _ in pickletools.genops(p):
                if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8"):
                    strings.append(arg)
                ref = None
                if op.name == "GLOBAL":
                    ref = arg.replace(" ", ".")
                elif op.name == "STACK_GLOBAL" and len(strings) >= 2:
                    ref = f"{strings[-2]}.{strings[-1]}"
                if ref and ref.split(".")[0] not in _SAFE_GLOBAL_ROOTS:
                    bad.append(ref)
        except Exception:
            bad.append("<не pickle / повреждён>")
    return bool(bad), bad


def typosquat_score(name: str, known: frozenset[str]) -> float:
    """Сходство неизвестного имени пакета с известными (1.0 — отличается на 1–2 символа)."""
    if name in known:
        return 0.0
    return _typo(name, known)


@lru_cache(maxsize=50000)
def _typo(name: str, known: frozenset[str]) -> float:
    return max((difflib.SequenceMatcher(None, name, k).ratio() for k in known), default=0.0)
