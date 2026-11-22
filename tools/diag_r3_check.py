"""Проверяем ценность R3 на обоих датасетах"""
from __future__ import annotations
import csv, sys, torch
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import from_ctu_row

DATA = ROOT / "outputs" / "network-eval"
IDX_UDP=5; IDX_PKTS=1; IDX_BYTES=2; IDX_DIR_ASYM=10; IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_NO_RESP=16

ckpt = torch.load(DATA / "ctu13-v10-gate5-run26.pt", map_location="cpu")
q25, iqr = ckpt["q25"], ckpt["iqr"]

def load_udp(cid, label_filter):
    paths = {
        "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
        "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
    }
    xs = []
    with open(paths[cid], encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label", "")
            if label_filter == 1 and not lbl.startswith("flow=From-Botnet-"): continue
            if label_filter == 0 and not lbl.startswith("flow=From-Normal-"): continue
            if str(row.get("Proto","")).lower() != "udp": continue
            try: feat = list(from_ctu_row(row))
            except: continue
            xs.append(feat)
    return np.array(xs, dtype=np.float32) if xs else np.zeros((0,17), dtype=np.float32)

for cid in ["53","54"]:
    atk = load_udp(cid, 1)
    ben = load_udp(cid, 0)
    for name, X in [("ATTACK", atk), ("BENIGN", ben)]:
        if len(X) == 0: continue
        sc = (X - q25) / iqr
        sust = sc[:,IDX_SUSTAINED] > 0.5
        noresp = sc[:,IDX_NO_RESP] > 0.5
        veph = sc[:,IDX_VERY_EPH] > 0.5
        blo = sc[:,IDX_BYTES] < -0.5
        r3 = sust & noresp
        b4_candidate = sust & noresp & ~blo  # новое бенигн-правило
        print(f"CTU-{cid} {name}: n={len(X)}, R3(sust+noresp)={r3.sum()}, B4_candidate(sust+noresp+~blo)={b4_candidate.sum()}")
