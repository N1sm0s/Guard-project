# -*- coding: utf-8 -*-
"""Извлечение признаков из raw корпуса и сохранение в обучающий формат."""
import sys, copy, torch
sys.path.insert(0, r'F:\New\integrityguard')

from integrityguard.features import BehaviorProbe, extract, hash_baseline
from integrityguard.spec import CLASSES, CLASS_LEVEL, LEVELS

import argparse
p = argparse.ArgumentParser()
p.add_argument('--inp', default=r'F:\New\integrityguard\corpus\corpus500.pt')
p.add_argument('--out', default=r'F:\New\integrityguard\corpus\corpus500_feat.pt')
a = p.parse_args()

CORPUS_IN  = a.inp
CORPUS_OUT = a.out

print("[ВНИМАНИЕ] Этот скрипт устарел и не может построить поведенческие признаки "
      "(probe всегда None, т.к. «сырой» корпус не хранит контрольные данные эталона). "
      "Для обучения используйте integrityguard.corpus.build_corpus() напрямую "
      "(команда `python -m integrityguard corpus`), она строит поведенческую ветвь корректно.")
print(f"Загружаем raw корпус {CORPUS_IN}…")
raw = torch.load(CORPUS_IN, weights_only=False)
print(f"  {len(raw)} образцов")

samples = []
for i, entry in enumerate(raw):
    spec  = entry['spec']
    cls   = entry['cls']
    label = entry['label']
    meta  = entry['meta']
    pid   = meta.get('pid', i)

    ref = copy.deepcopy(spec)
    index = {d.name: {d.version: d.sha256} for d in ref.deps}
    # ВНИМАНИЕ: «сырой» корпус (corpus/corpus*.pt, собранный отдельным экспортёром без
    # сохранения контрольного набора эталона x/y) не содержит данных, нужных для
    # BehaviorProbe, поэтому probe здесь всегда None и признак behav вырождается в
    # одну и ту же константу для всех образцов (features.extract: probe is None ->
    # behav[0]=1, остальное 0) — поведенческая ветвь детектора при обучении на таком
    # корпусе не получает никакого сигнала и её AUC не отличается от случайного.
    # ЭТОТ СКРИПТ УСТАРЕЛ: integrityguard.corpus.build_corpus() уже строит настоящий
    # BehaviorProbe на контрольных данных эталона и возвращает полностью готовые
    # признаки (x/adj/layers/behav/...) за один шаг — используйте его напрямую
    # (`python -m integrityguard corpus --out corpus.pt`), а не этот скрипт.
    probe = None

    try:
        feat = extract(ref, spec, index, probe)
    except Exception as e:
        print(f"  [!] skip {i}: {e}")
        continue

    lvl_vec = torch.zeros(len(LEVELS))
    if CLASS_LEVEL.get(cls):
        idx = LEVELS.index(CLASS_LEVEL[cls])
        lvl_vec[idx] = 1.0

    node_y = torch.zeros(feat['x'].shape[0])
    if cls != 'clean' and feat['x'].shape[0] > 1:
        node_y[1] = 1.0

    sample = {**feat,
              'y': label,
              'pid': pid,
              'cls': cls,
              'levels': lvl_vec,
              'node_y': node_y,
              'hash_flag': int(hash_baseline(ref, spec, index))}
    samples.append(sample)
    if (i+1) % 100 == 0:
        print(f"  [{i+1}/{len(raw)}] …")

print(f"Извлечено {len(samples)} образцов из {len(raw)}")
torch.save(samples, CORPUS_OUT)
print(f"Сохранено -> {CORPUS_OUT}")
