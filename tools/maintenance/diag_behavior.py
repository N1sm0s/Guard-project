# -*- coding: utf-8 -*-
"""Диагностика поведенческой ветви: несёт ли behav реальный сигнал по классам."""
import sys
sys.path.insert(0, r'F:\New\integrityguard')
import torch
import numpy as np
from collections import defaultdict

from integrityguard.corpus import build_corpus
from integrityguard.spec import CLASSES

samples = build_corpus(60, seed=3)
by_cls = defaultdict(list)
for s in samples:
    by_cls[s["cls"]].append(s["behav"])

print("=== behav stats per class (mean abs, std) ===")
for cls in CLASSES:
    if cls not in by_cls:
        continue
    t = torch.stack(by_cls[cls])
    print(f"{cls:14s} n={len(by_cls[cls]):3d}  mean(|behav|)={t.abs().mean():.4f}  std={t.std():.4f}  "
          f"behav[0] (probe failed flag) mean={t[:,0].mean():.4f}")

# Проверка: сколько образцов имеют behav[0]==1 (поведенческий контроль недоступен)
flagged = sum(1 for s in samples if float(s["behav"][0]) == 1.0)
print(f"\nОбразцов с behav[0]==1 (probe failed/unavailable): {flagged} из {len(samples)}")

# Межклассовое расстояние: clean vs behavioral-level classes
clean = torch.stack(by_cls["clean"]) if "clean" in by_cls else None
for cls in ("backdoor", "poison", "label_flip", "adversarial", "availability"):
    if cls in by_cls and clean is not None:
        c = torch.stack(by_cls[cls])
        dist = (c.mean(0) - clean.mean(0)).abs().mean()
        print(f"mean|behav({cls}) - behav(clean)| = {dist:.5f}")
