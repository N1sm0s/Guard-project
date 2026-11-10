"""Модель объекта защиты: пакетно-нейросетевая программа (ПНП) и классы угроз."""
from __future__ import annotations

from dataclasses import dataclass, field

import torch

# Классы нарушений целостности (выход детектора)
CLASSES = [
    "clean",
    "dependency",
    "weights",
    "backdoor",
    "poison",
    "label_flip",
    "adversarial",   # угроза 4: состязательные входы / эвазия модели
    "extraction",    # угроза 7: несанкционированное извлечение модели
    "availability",  # угроза 8: нарушение доступности (DoS)
]
CLASS_RU = {
    "clean":        "нарушений нет (легитимное обновление)",
    "dependency":   "компрометация библиотек и компонентов",
    "weights":      "подмена или изменение весов модели",
    "backdoor":     "внедрение триггера (бэкдора)",
    "poison":       "отравление обучающих данных",
    "label_flip":   "подмена меток",
    "adversarial":  "состязательные входы / эвазия модели",
    "extraction":   "несанкционированное извлечение модели",
    "availability": "нарушение доступности (атака типа DoS)",
}
# Уровни целостности и то, какой уровень нарушает каждый класс
LEVELS = ["structural", "parametric", "behavioral"]
LEVEL_RU = {"structural": "структурный", "parametric": "параметрический", "behavioral": "поведенческий"}
CLASS_LEVEL = {
    "clean":        None,
    "dependency":   "structural",
    "weights":      "parametric",
    "backdoor":     "behavioral",
    "poison":       "behavioral",
    "label_flip":   "behavioral",
    "adversarial":  "behavioral",   # проявляется в поведении модели
    "extraction":   "structural",   # видно в структуре запросов / коде
    "availability": "behavioral",   # деградация throughput/latency
}
# Признаки-«возможности» кода, выявляемые статическим анализом
CAPS = ["network", "process", "dynamic_exec", "obfuscation",
        "file_write", "install_hook", "unsafe_deser", "native"]


@dataclass
class Dep:
    """Внешняя зависимость (библиотека) из манифеста/lock-файла."""
    name: str
    version: str
    sha256: str
    source: str = "pypi"            # pypi | internal | url
    requires: list[str] = field(default_factory=list)
    size: int = 0
    code: str = ""                  # исходный текст (если он поставляется вместе с пакетом) — для статического анализа


@dataclass
class Module:
    """Собственный исходный модуль программы."""
    name: str
    code: str


@dataclass
class PackageSpec:
    """Состояние ПНП: граф компонентов + параметры модели."""
    name: str
    version: str
    deps: list[Dep]
    modules: list[Module]
    state: dict[str, torch.Tensor]  # веса модели (state_dict)
    signed_ok: bool = True          # подпись манифеста верна
    unsafe_format: bool = False     # модель сериализована небезопасным pickle
    dataset_sha256: str = ""

    def dep(self, name: str) -> Dep | None:
        return next((d for d in self.deps if d.name == name), None)


def layers_of(state: dict[str, torch.Tensor]) -> list[tuple[torch.Tensor, torch.Tensor]]:
    """Пары (W, b) полносвязных слоёв в порядке следования в state_dict."""
    out, keys = [], list(state.keys())
    for i, k in enumerate(keys):
        w = state[k]
        if w.dim() == 2:
            b = state[keys[i + 1]] if i + 1 < len(keys) and state[keys[i + 1]].dim() == 1 \
                and state[keys[i + 1]].shape[0] == w.shape[0] else torch.zeros(w.shape[0])
            out.append((w.float(), b.float()))
    return out


def mlp_forward(layers, x: torch.Tensor) -> torch.Tensor:
    """Прямой проход MLP (Linear+ReLU ... Linear) по списку слоёв."""
    for i, (w, b) in enumerate(layers):
        x = x @ w.T + b
        if i < len(layers) - 1:
            x = torch.relu(x)
    return x
