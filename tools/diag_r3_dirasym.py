"""Проверяем dir_asym у CTU-53 R3-атак vs CTU-54 R3-бенигнных"""
import csv, sys, torch
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import from_ctu_row, FEATURE_NAMES

DATA = ROOT / "outputs" / "network-eval"
IDX_PKTS=1; IDX_BYTES=2; IDX_DIR_ASYM=10; IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_NO_RESP=16

ckpt = torch.load(DATA / "ctu13-v10-gate5-run26.pt", map_location="cpu")
q25, iqr = ckpt["q25"], ckpt["iqr"]

files = {
    "53_ATK": (DATA / "official-ctu13" / "capture20110819_ctu53.binetflow", "botnet"),
    "54_BEN": (DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow", "normal"),
}

for label, (path, kind) in files.items():
    xs, raw_rows = [], []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            lbl = row.get("Label","")
            if kind == "botnet" and not lbl.startswith("flow=From-Botnet-"): continue
            if kind == "normal" and not lbl.startswith("flow=From-Normal-"): continue
            if str(row.get("Proto","")).lower() != "udp": continue
            try: feat = list(from_ctu_row(row))
            except: continue
            xs.append(feat)
            raw_rows.append(row)
    X = np.array(xs, dtype=np.float32)
    sc = (X - q25) / iqr
    sust = sc[:,IDX_SUSTAINED] > 0.5
    noresp = sc[:,IDX_NO_RESP] > 0.5
    r3 = sust & noresp
    r3_idx = np.where(r3)[0]
    print(f"\n{label}: R3={r3.sum()}")
    if len(r3_idx) == 0:
        continue
    r3_dirasym_sc = sc[r3_idx, IDX_DIR_ASYM]
    r3_dirasym_raw = X[r3_idx, IDX_DIR_ASYM]
    print(f"  dir_asym SC: min={r3_dirasym_sc.min():.3f} max={r3_dirasym_sc.max():.3f} mean={r3_dirasym_sc.mean():.3f}")
    print(f"  dir_asym RAW: min={r3_dirasym_raw.min():.3f} max={r3_dirasym_raw.max():.3f}")
    # Порог dir_asym_ok > -0.40 (SC)
    dir_asym_ok = sc[:,IDX_DIR_ASYM] > -0.40
    dir_asym_hi = sc[:,IDX_DIR_ASYM] > 0.5  # высокая асимметрия
    print(f"  R3 & dir_asym_ok (>-0.40): {(r3 & dir_asym_ok).sum()}")
    print(f"  R3 & dir_asym_hi (>0.5):   {(r3 & dir_asym_hi).sum()}")
    print(f"  R3 & ~dir_asym_ok (<=−0.40): {(r3 & ~dir_asym_ok).sum()}")
    
    # Все признаки для CTU-54 бенигнных
    if kind == "normal" and r3.sum() > 0:
        print(f"\n  === Детали CTU-54 бенигнных R3 ===")
        for i in r3_idx[:5]:
            row = raw_rows[i]
            print(f"  Sport={row.get('Sport','?')} Dport={row.get('Dport','?')} Dur={row.get('Dur','?')}")
            feat_names = FEATURE_NAMES[:len(X[i])]
            for fi, fn in enumerate(feat_names):
                if abs(X[i,fi]) > 0.01 or abs(sc[i,fi]) > 0.01:
                    print(f"    {fn}: raw={X[i,fi]:.4f} sc={sc[i,fi]:.4f}")
