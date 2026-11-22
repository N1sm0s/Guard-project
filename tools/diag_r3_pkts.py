"""Проверяем pkts_hi у CTU-53 R3-атак и CTU-54 R3-бенигнных"""
import csv, sys, torch
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import from_ctu_row

DATA = ROOT / "outputs" / "network-eval"
IDX_PKTS=1; IDX_BYTES=2; IDX_DIR_ASYM=10; IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_NO_RESP=16

ckpt = torch.load(DATA / "ctu13-v10-gate5-run26.pt", map_location="cpu")
q25, iqr = ckpt["q25"], ckpt["iqr"]

files = {
    "53_ATK": (DATA / "official-ctu13" / "capture20110819_ctu53.binetflow", "botnet"),
    "54_BEN": (DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow", "normal"),
}

for label, (path, kind) in files.items():
    xs = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label","")
            if kind == "botnet" and not lbl.startswith("flow=From-Botnet-"): continue
            if kind == "normal" and not lbl.startswith("flow=From-Normal-"): continue
            if str(row.get("Proto","")).lower() != "udp": continue
            try: feat = list(from_ctu_row(row))
            except: continue
            xs.append(feat)
    X = np.array(xs, dtype=np.float32)
    sc = (X - q25) / iqr
    sust = sc[:,IDX_SUSTAINED] > 0.5
    noresp = sc[:,IDX_NO_RESP] > 0.5
    pkts_hi = sc[:,IDX_PKTS] > 0.603
    r3 = sust & noresp
    print(f"\n{label} (n={len(X)}):")
    print(f"  R3 total: {r3.sum()}")
    if r3.sum() > 0:
        r3_pkts_raw = X[r3, IDX_PKTS]
        r3_pkts_sc = sc[r3, IDX_PKTS]
        print(f"  R3 pkts_hi=True:  {(r3 & pkts_hi).sum()}")
        print(f"  R3 pkts_hi=False: {(r3 & ~pkts_hi).sum()}")
        print(f"  R3 raw pkts range: {r3_pkts_raw.min():.1f} - {r3_pkts_raw.max():.1f} (median={np.median(r3_pkts_raw):.1f})")
        # Новые кандидаты на B4
        b4_cand1 = r3 & ~pkts_hi  # sust+noresp+~pkts_hi -> benign
        print(f"  B4(sust+noresp+~pkts_hi): {b4_cand1.sum()}")
