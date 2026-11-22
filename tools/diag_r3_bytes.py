"""Проверяем bytes_lo у CTU-53 R3-атак"""
import csv, sys, torch
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import from_ctu_row

DATA = ROOT / "outputs" / "network-eval"
IDX_BYTES=2; IDX_SUSTAINED=13; IDX_NO_RESP=16

ckpt = torch.load(DATA / "ctu13-v10-gate5-run26.pt", map_location="cpu")
q25, iqr = ckpt["q25"], ckpt["iqr"]

xs = []
with open(DATA / "official-ctu13" / "capture20110819_ctu53.binetflow", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        if not row.get("Label","").startswith("flow=From-Botnet-"): continue
        if str(row.get("Proto","")).lower() != "udp": continue
        try: feat = list(from_ctu_row(row))
        except: continue
        xs.append(feat)

X = np.array(xs, dtype=np.float32)
sc = (X - q25) / iqr
sust = sc[:,IDX_SUSTAINED] > 0.5
noresp = sc[:,IDX_NO_RESP] > 0.5
blo = sc[:,IDX_BYTES] < -0.5
r3 = sust & noresp
print(f"CTU-53 атаки: {len(X)} UDP")
print(f"R3 (sust+noresp): {r3.sum()}")
print(f"R3 & bytes_lo: {(r3 & blo).sum()}")
print(f"R3 & ~bytes_lo: {(r3 & ~blo).sum()}")
print(f"\nB4 кандидат (sust+noresp+~blo) защита бенигнных:")
print(f"  Это НЕ задет CTU-53 атак через B4: {(r3 & ~blo).sum()} атак становятся ben_locked!")
print(f"  Это задет CTU-54 бенигнных: 3 (все bytes_lo=False)")
