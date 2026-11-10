"""Методика обучения и оценки детектора."""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

from .model import HybridDetector, collate, save_detector
from .spec import CLASS_LEVEL, CLASS_RU, CLASSES, LEVEL_RU, LEVELS


def split_by_project(samples, seed=0, frac=(0.7, 0.15)):
    """Stratify project groups while keeping every project's candidates together."""
    rng = np.random.default_rng(seed)
    by_class = {}
    for pid in sorted({s["pid"] for s in samples}):
        rows = [s for s in samples if s["pid"] == pid]
        labels = [s["y"] for s in rows]
        cls = max(set(labels), key=labels.count)
        by_class.setdefault(cls, []).append(pid)
    part = {}
    for pids in by_class.values():
        rng.shuffle(pids)
        n = len(pids)
        a = int(n * frac[0])
        b = int(n * (frac[0] + frac[1]))
        if n >= 3:
            a = max(1, min(a, n - 2))
            b = max(a + 1, min(b, n - 1))
        for p in pids[:a]:
            part[p] = 0
        for p in pids[a:b]:
            part[p] = 1
        for p in pids[b:]:
            part[p] = 2
    return tuple([s for s in samples if part[s["pid"]] == i] for i in range(3))


@torch.no_grad()
def predict(model, samples, bs=256):
    """Вероятности классов, оценки уровней, оценки узлов (по образцам)."""
    model.eval()
    probs, levels, nodes = [], [], []
    for i in range(0, len(samples), bs):
        chunk = samples[i:i + bs]
        out = model(collate(chunk))
        probs.append(F.softmax(out["logits"], -1))
        levels.append(torch.sigmoid(out["levels"]))
        nl = torch.sigmoid(out["node_logits"])
        nodes += [nl[j, : s["x"].shape[0]] for j, s in enumerate(chunk)]
    return torch.cat(probs), torch.cat(levels), nodes


def auc(score, pos):
    """ROC-AUC через ранги (Манна — Уитни), со средними рангами для совпадающих оценок."""
    score, pos = np.asarray(score, float), np.asarray(pos, bool)
    if pos.all() or not pos.any():
        return float("nan")
    order = np.argsort(score, kind="mergesort")
    ranks = np.empty(len(score))
    s = score[order]
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and s[j + 1] == s[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    n1, n0 = pos.sum(), (~pos).sum()
    return float((ranks[pos].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def binary_metrics(flag, y):
    flag, pos = np.asarray(flag, bool), np.asarray(y) != 0
    tp, fp, fn, tn = (flag & pos).sum(), (flag & ~pos).sum(), (~flag & pos).sum(), (~flag & ~pos).sum()
    prec, rec = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    return {"accuracy": float((tp + tn) / len(pos)), "precision": float(prec), "recall": float(rec),
            "f1": float(2 * prec * rec / max(prec + rec, 1e-12)), "fpr": float(fp / max(fp + tn, 1))}


def evaluate(model, samples, threshold):
    """Показатели качества: бинарные (нарушение/норма), по классам, по уровням, локализация."""
    probs, levels, nodes = predict(model, samples)
    y = np.array([s["y"] for s in samples])
    score = (1 - probs[:, 0]).numpy()
    pred = probs.argmax(-1).numpy()
    k = len(CLASSES)
    cm = np.zeros((k, k), int)
    for t, p in zip(y, pred):
        cm[t, p] += 1
    rec = cm.diagonal() / cm.sum(1).clip(min=1)
    prec = cm.diagonal() / cm.sum(0).clip(min=1)
    f1 = 2 * prec * rec / (prec + rec).clip(min=1e-12)
    flag = score >= threshold
    res = {"binary": binary_metrics(flag, y) | {"auc": auc(score, y != 0), "threshold": float(threshold)},
           "multiclass": {"accuracy": float((pred == y).mean()), "macro_precision": float(prec.mean()),
                          "macro_recall": float(rec.mean()), "macro_f1": float(f1.mean())},
           "per_class": {c: {"n": int(cm[i].sum()), "precision": float(prec[i]), "recall": float(rec[i]),
                             "f1": float(f1[i]), "detected": float(flag[y == i].mean()) if (y == i).any() else float("nan")}
                         for i, c in enumerate(CLASSES)},
           "confusion": cm.tolist()}
    # полнота обнаружения по уровням целостности (нарушение уровня помечено как нарушение)
    res["per_level"] = {}
    for lv in LEVELS:
        m = np.array([CLASS_LEVEL[CLASSES[t]] == lv for t in y])
        res["per_level"][lv] = {"n": int(m.sum()), "recall": float(flag[m].mean()) if m.any() else float("nan"),
                                "level_auc": auc(levels[:, LEVELS.index(lv)].numpy(), m)}
    hits = [int(n.argmax()) in torch.nonzero(s["node_y"]).flatten().tolist()
            for n, s in zip(nodes, samples) if s["node_y"].sum() > 0]
    res["localization_top1"] = float(np.mean(hits)) if hits else float("nan")
    return res


def train_detector(train, val, epochs=70, lr=2e-3, hidden=64, use=(True, True, True), seed=0, log=None):
    """Обучение: 1) предобучение автокодировщика на легитимных портретах;
    2) совместное обучение ветвей (класс + уровни + локализация + восстановление)."""
    torch.manual_seed(seed)
    model = HybridDetector(hidden, use)
    model.set_norm(train)
    y = torch.tensor([s["y"] for s in train])
    cw = (len(y) / (len(CLASSES) * torch.bincount(y, minlength=len(CLASSES)).clamp(min=1))).float()
    rng = np.random.default_rng(seed)

    clean = [s for s in train if s["y"] == 0]
    opt = torch.optim.Adam(model.ae.parameters(), lr=3e-3)
    for _ in range(40):
        for i in range(0, len(clean), 64):
            b = collate(clean[i:i + 64])
            loss = model(b)["recon"].mean()
            opt.zero_grad()
            loss.backward()
            opt.step()

    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-3)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, epochs)
    best, best_state = -1.0, None
    for ep in range(epochs):
        model.train()
        order = rng.permutation(len(train))
        for i in range(0, len(order), 64):
            b = collate([train[j] for j in order[i:i + 64]])
            out = model(b)
            is_clean = (b["y"] == 0).float()
            loss = F.cross_entropy(out["logits"], b["y"], weight=cw) \
                + 0.5 * F.binary_cross_entropy_with_logits(out["levels"], b["levels"]) \
                + 0.5 * (F.binary_cross_entropy_with_logits(out["node_logits"], b["node_y"], reduction="none",
                                                            pos_weight=torch.tensor(10.0)) * b["mask"]).sum() / b["mask"].sum() \
                + (out["recon"] * is_clean).sum() / is_clean.sum().clamp(min=1)
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            opt.step()
        sched.step()
        if ep % 5 == 4 or ep == epochs - 1:
            m = evaluate(model, val, 0.5)
            score = m["multiclass"]["macro_f1"] + float(np.nan_to_num(m["binary"]["auc"]))
            if score > best or best_state is None:
                best, best_state = score, {k: v.clone() for k, v in model.state_dict().items()}
            if log:
                log(f"  эпоха {ep + 1:3d}: val macro-F1 {m['multiclass']['macro_f1']:.3f}  AUC {m['binary']['auc']:.3f}")
    model.load_state_dict(best_state)
    return model.eval()


def calibrate(model, val, fpr=0.02):
    """Порог решения по допустимой доле ложных срабатываний на легитимных обновлениях."""
    probs, _, _ = predict(model, val)
    clean = np.sort(1 - probs[[i for i, s in enumerate(val) if s["y"] == 0], 0].numpy())
    if len(clean) == 0:
        return 0.5
    k = int(np.ceil(len(clean) * (1 - fpr))) - 1
    return float(min(max(clean[min(max(k, 0), len(clean) - 1)] + 1e-4, 0.05), 0.95))


def run_experiment(samples, out_dir, epochs=70, fpr=0.02, seed=0, ablation=True, log=print):
    """Полный цикл методики: разбиение, обучение, калибровка, оценка, сравнение с базовыми методами."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    train, val, test = split_by_project(samples, seed)
    if not train or not val or not test or not any(s["y"] == 0 for s in train):
        raise ValueError("корпус слишком мал: нужно не менее 10 проектов, чтобы выделить обучение, валидацию и тест")
    log(f"Корпус: {len(samples)} образцов; обучение {len(train)}, валидация {len(val)}, тест {len(test)}")
    log("Обучение гибридного детектора (граф + автокодировщик + поведение)")
    t0 = time.perf_counter()
    model = train_detector(train, val, epochs, seed=seed, log=log)
    train_time = time.perf_counter() - t0
    thr = calibrate(model, val, fpr)
    report = {"hybrid": evaluate(model, test, thr)}
    # вычислительные затраты анализа
    t0 = time.perf_counter()
    for s in test[:200]:
        predict(model, [s])
    report["cost"] = {"params": sum(p.numel() for p in model.parameters()),
                      "inference_ms": 1000 * (time.perf_counter() - t0) / min(len(test), 200),
                      "train_time_s": train_time}
    y = np.array([s["y"] for s in test])
    hb = np.array([s["hash_flag"] for s in test])
    report["hash_baseline"] = {"binary": binary_metrics(hb, y),
                               "per_class_detected": {c: float(hb[y == i].mean()) for i, c in enumerate(CLASSES) if (y == i).any()}}
    if ablation:
        for name, use in (("only_graph", (1, 0, 0)), ("only_autoencoder", (0, 1, 0)), ("only_behavior", (0, 0, 1))):
            log(f"Абляция: {name}")
            m = train_detector(train, val, epochs, use=use, seed=seed)
            report[name] = evaluate(m, test, calibrate(m, val, fpr))
    report["split"] = {"train": len(train), "val": len(val), "test": len(test), "target_fpr": fpr,
                       "projects": len({s["pid"] for s in samples})}
    save_detector(model, out / "detector.pt", {"threshold": thr, "block_threshold": max(thr, 0.9)})
    (out / "metrics.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "report.md").write_text(render_report(report), encoding="utf-8")
    _plots(report, out)
    return model, report


def render_report(r) -> str:
    """Отчёт об оценке на русском языке (Markdown)."""
    h, b, mc = r["hybrid"], r["hybrid"]["binary"], r["hybrid"]["multiclass"]
    L = ["# Оценка детектора нарушений целостности ПНП", "",
         f"Проектов: {r['split']['projects']}; образцов: обучение {r['split']['train']}, валидация {r['split']['val']}, "
         f"тест {r['split']['test']}. Разбиение по проектам (эталоны теста в обучении не встречались). "
         f"Порог откалиброван на валидации под долю ложных срабатываний {r['split']['target_fpr']:.0%}.", "",
         "## Обнаружение нарушения (нарушение / норма), тестовая выборка", "",
         "| Метод | Accuracy | Precision (точность) | Recall (полнота) | F1 | FPR | AUC |", "|---|---|---|---|---|---|---|"]

    def row(name, m):
        return (f"| {name} | {m['accuracy']:.3f} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | "
                f"{m['fpr']:.3f} | {m.get('auc', float('nan')):.3f} |").replace("nan", "—")
    L.append(row("Гибридный детектор", b))
    for key, name in (("only_graph", "Только граф (GNN)"), ("only_autoencoder", "Только автокодировщик весов"),
                      ("only_behavior", "Только поведенческий классификатор")):
        if key in r:
            L.append(row(name, r[key]["binary"]))
    L.append(row("Контроль подписи и хешей", r["hash_baseline"]["binary"]))
    L += ["", "## Полнота обнаружения по классам угроз", "",
          "| Класс | N | Гибридный: обнаружено | Гибридный: верно назван класс | Хеш-контроль: обнаружено |", "|---|---|---|---|---|"]
    for c in CLASSES[1:]:
        pc = h["per_class"][c]
        L.append(f"| {CLASS_RU[c]} | {pc['n']} | {pc['detected']:.3f} | {pc['recall']:.3f} | "
                 f"{r['hash_baseline']['per_class_detected'].get(c, float('nan')):.3f} |")
    pc = h["per_class"]["clean"]
    L += ["", f"Легитимные обновления (N={pc['n']}): ложно помечено гибридным детектором "
              f"{b['fpr']:.3f}, хеш-контролем {r['hash_baseline']['binary']['fpr']:.3f}.", "",
          "## По уровням целостности", "", "| Уровень | N | Полнота | AUC выхода уровня |", "|---|---|---|---|"]
    for lv in LEVELS:
        pl = h["per_level"][lv]
        L.append(f"| {LEVEL_RU[lv]} | {pl['n']} | {pl['recall']:.3f} | {pl['level_auc']:.3f} |")
    L += ["", f"Классификация на {len(CLASSES)} классов: accuracy {mc['accuracy']:.3f}, macro-F1 {mc['macro_f1']:.3f}. "
              f"Локализация скомпрометированного компонента (top-1): {h['localization_top1']:.3f}.", "",
          "## Вычислительные затраты", "",
          f"Параметров сети: {r['cost']['params']}; нейросетевой анализ одного пакета: {r['cost']['inference_ms']:.1f} мс; "
          f"обучение: {r['cost']['train_time_s']:.0f} с (CPU).", "",
          "## Матрица ошибок (строки — истинный класс, столбцы — предсказанный)", "",
          "| | " + " | ".join(CLASSES) + " |", "|---|" + "---|" * len(CLASSES)]
    for c, rowv in zip(CLASSES, h["confusion"]):
        L.append(f"| {c} | " + " | ".join(str(v) for v in rowv) + " |")
    return "\n".join(L) + "\n"


def _plots(r, out: Path):
    """Диаграммы для отчёта (если установлен matplotlib)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return
    names = [c for c in CLASSES[1:]]
    w = 0.38
    fig, ax = plt.subplots(1, 2, figsize=(13, 4.6))
    x = np.arange(len(names))
    ax[0].bar(x - w / 2, [r["hybrid"]["per_class"][c]["detected"] for c in names], w, label="Гибридный детектор", color="#3b82f6")
    ax[0].bar(x + w / 2, [r["hash_baseline"]["per_class_detected"].get(c, 0) for c in names], w, label="Контроль подписи и хешей", color="#eb6834")
    ax[0].set_xticks(x, ["зависим.", "веса", "бэкдор", "отравл.", "метки", "состяз.", "извлеч.", "доступн."], rotation=20, ha='right')
    ax[0].set_ylim(0, 1.22)
    ax[0].set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax[0].set_ylabel("Полнота обнаружения")
    ax[0].set_title("Полнота по классам угроз (тест)")
    ax[0].legend(loc="upper center", ncols=2, frameon=False)
    ax[0].spines[["top", "right"]].set_visible(False)
    cm = np.array(r["hybrid"]["confusion"], float)
    cmn = cm / cm.sum(1, keepdims=True).clip(min=1)
    ax[1].imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            ax[1].text(j, i, int(cm[i, j]), ha="center", va="center", color="white" if cmn[i, j] > 0.5 else "#333", fontsize=9)
    ax[1].set_xticks(range(len(CLASSES)), CLASSES, rotation=30, ha="right")
    ax[1].set_yticks(range(len(CLASSES)), CLASSES)
    ax[1].set_xlabel("предсказано")
    ax[1].set_ylabel("истинный класс")
    ax[1].set_title("Матрица ошибок гибридного детектора")
    fig.tight_layout()
    fig.savefig(out / "metrics.png", dpi=150)
    plt.close(fig)
