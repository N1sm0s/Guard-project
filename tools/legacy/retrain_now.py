"""
retrain_now.py  --  быстрый перезапуск обучения классификатора.
Использование: python retrain_now.py [--force]
"""
import sys, pathlib, sqlite3, json, argparse, datetime

ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(ROOT))

parser = argparse.ArgumentParser()
parser.add_argument("--force", action="store_true")
args = parser.parse_args()

from integrityguard.network_classifier import (
    FEATURE_VERSION, ARCH_WIDE, LABEL_SOURCE,
    extract_features, FEATURE_NAMES,
)
print(f"[retrain] FEATURE_VERSION={FEATURE_VERSION}, ARCH={ARCH_WIDE}")
print(f"[retrain] LABEL_SOURCE={LABEL_SOURCE}")

checkpoint = ROOT / "data" / "models" / f"network_classifier_v{FEATURE_VERSION}.pt"
checkpoint.parent.mkdir(parents=True, exist_ok=True)

if checkpoint.exists() and not args.force:
    print(f"[retrain] Чекпойнт уже есть: {checkpoint}. Используйте --force.")
    sys.exit(0)

db_path = ROOT / "data" / "online" / "network_events.sqlite"
if not db_path.exists():
    print(f"[retrain] БД не найдена: {db_path}")
    sys.exit(1)

con = sqlite3.connect(str(db_path))
rows = con.execute(
    "SELECT snapshot_json, assessment_json FROM events WHERE assessment_json IS NOT NULL"
).fetchall()
con.close()
print(f"[retrain] Загружено {len(rows)} записей из БД")

import torch
import torch.nn as nn

samples, labels = [], []

for snap_json, assess_json in rows:
    try:
        snap = json.loads(snap_json)
        assess = json.loads(assess_json) if assess_json else {}
    except Exception:
        continue

    verdict = assess.get("verdict") or assess.get("decision") or snap.get("flow_label")
    if verdict in ("ALLOW", "allow", "ДОПУСТИТЬ"):
        label = 0
    elif verdict in ("BLOCK", "block", "ЗАБЛОКИРОВАТЬ"):
        label = 1
    else:
        continue

    try:
        feats = extract_features(snap)
        vec = [feats[k] for k in FEATURE_NAMES]
        if len(vec) != 26:
            continue
        samples.append(vec)
        labels.append(label)
    except Exception:
        continue

n_allow = labels.count(0)
n_block = labels.count(1)
print(f"[retrain] Образцов: {len(samples)} (ALLOW={n_allow}, BLOCK={n_block})")

if len(samples) < 10:
    print("[retrain] Недостаточно образцов (нужно >= 10).")
    sys.exit(1)

X = torch.tensor(samples, dtype=torch.float32)
y = torch.tensor(labels, dtype=torch.long)

x_mean = X.mean(0)
x_std  = X.std(0).clamp(min=1e-6)
X_norm = (X - x_mean) / x_std

model = nn.Sequential(
    nn.Linear(26, 64), nn.ReLU(), nn.Dropout(0.3),
    nn.Linear(64, 32), nn.ReLU(), nn.Dropout(0.2),
    nn.Linear(32, 16), nn.ReLU(),
    nn.Linear(16, 2),
)

optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
criterion = nn.CrossEntropyLoss()

EPOCHS = 200
model.train()
for epoch in range(1, EPOCHS + 1):
    optimizer.zero_grad()
    logits = model(X_norm)
    loss = criterion(logits, y)
    loss.backward()
    optimizer.step()
    if epoch % 50 == 0:
        acc = (logits.argmax(1) == y).float().mean().item()
        print(f"  Epoch {epoch:4d}  loss={loss.item():.4f}  acc={acc:.3f}")

now_utc = datetime.datetime.utcnow().isoformat() + "Z"

torch.save({
    "feature_version": FEATURE_VERSION,
    "arch": ARCH_WIDE,
    "label_source": LABEL_SOURCE,
    "feature_names": list(FEATURE_NAMES),
    "classes": ["ALLOW", "BLOCK"],
    "state_dict": model.state_dict(),
    "mean": x_mean.tolist(),
    "std": x_std.tolist(),
    "n_samples": len(samples),
    "class_counts": {"ALLOW": n_allow, "BLOCK": n_block},
    "allow_threshold": 0.10,
    "block_threshold": 0.90,
    "trained_at_utc": now_utc,
    "caveat": "" if n_block > 0 else "Обучено только на ALLOW-трафике; BLOCK не представлен.",
}, str(checkpoint))

print(f"\n[retrain] Чекпойнт сохранён: {checkpoint}")
