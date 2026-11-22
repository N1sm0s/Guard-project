"""
Диагностика: CTU-54 rule_bad=3
Находит бенигнные UDP потоки, которые попадают под атакующие правила R2/R3
и показывает их точные признаки для разработки нового бенигн-правила.
"""
from __future__ import annotations
import csv, gzip, sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

DATA = ROOT / "outputs" / "network-eval"
CTU54 = DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow"

IDX_UDP        = 5
IDX_PKTS       = 1
IDX_BYTES      = 2
IDX_DIR_ASYM   = 10
IDX_VERY_EPH   = 11
IDX_SUSTAINED  = 13
IDX_NO_RESP    = 16

def class_for_label(label):
    if label.startswith("flow=From-Botnet-"): return 1
    if label.startswith("flow=From-Normal-"): return 0
    return -1

def load_capture(path):
    xs, ys, raw_rows = [], [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            y = class_for_label(row.get("Label", ""))
            if y < 0: continue
            proto = str(row.get("Proto", "")).lower()
            if proto != "udp": continue
            if y != 0: continue  # только бенигнные UDP
            try:
                feat = list(from_ctu_row(row))
            except Exception:
                continue
            xs.append(feat)
            ys.append(y)
            raw_rows.append(row)
    return np.array(xs, dtype=np.float32), np.array(ys), raw_rows

print("Загружаем CTU-54 бенигнные UDP...")
X_raw, Y, rows = load_capture(CTU54)
print(f"Всего бенигнных UDP: {len(X_raw)}")

# Подгружаем скейлер из чекпоинта run26
import torch
ckpt_path = DATA / "ctu13-v10-gate5-run26.pt"
if not ckpt_path.exists():
    print("ОШИБКА: чекпоинт run26.pt не найден!")
    sys.exit(1)

ckpt = torch.load(ckpt_path, map_location="cpu")
q25 = ckpt["q25"]
iqr = ckpt["iqr"]
X_sc = (X_raw - q25) / iqr
print(f"Скейлер загружен из run26.pt")

# Применяем правила
is_udp       = X_sc[:, IDX_UDP]       > 0.5
is_very_eph  = X_sc[:, IDX_VERY_EPH]  > 0.5
is_sustained = X_sc[:, IDX_SUSTAINED] > 0.5
is_no_resp   = X_sc[:, IDX_NO_RESP]   > 0.5
pkts_hi      = X_sc[:, IDX_PKTS]      > 0.603
dir_asym_ok  = X_sc[:, IDX_DIR_ASYM]  > -0.40
bytes_lo     = X_sc[:, IDX_BYTES]     < -0.5

# Бенигн-правила
score = np.full(len(X_raw), np.nan)
b1 = is_udp & is_very_eph & ~is_sustained & ~is_no_resp
score[b1] = 0.0
b2 = is_udp & is_very_eph & ~is_sustained & ~pkts_hi
score[b2] = 0.0
b3 = is_udp & ~is_sustained & ~is_no_resp
score[b3] = 0.0
ben_locked = ~np.isnan(score) & (score < 0.5)

# Атака-правила
r2 = is_udp & is_very_eph & is_no_resp & bytes_lo & ~ben_locked
score[r2] = 1.0
r3 = is_udp & is_sustained & is_no_resp & ~ben_locked
score[r3] = 1.0

rule_bad_mask = ~np.isnan(score) & (score > 0.5)  # бенигнные под атака-правилами
bad_indices = np.where(rule_bad_mask)[0]
print(f"\nrule_bad = {len(bad_indices)}")

for idx in bad_indices:
    row = rows[idx]
    print(f"\n--- Поток #{idx} ---")
    print(f"  SrcAddr: {row.get('SrcAddr','?')}  DstAddr: {row.get('DstAddr','?')}")
    print(f"  Sport:   {row.get('Sport','?')}     Dport:   {row.get('Dport','?')}")
    print(f"  Dur:     {row.get('Dur','?')}       TotPkts: {row.get('TotPkts','?')}")
    print(f"  TotBytes:{row.get('TotBytes','?')}  SrcBytes:{row.get('SrcBytes','?')}")
    print(f"  Label:   {row.get('Label','?')}")
    xr = X_raw[idx]
    xs = X_sc[idx]
    print(f"  RAW: pkts={xr[IDX_PKTS]:.1f} bytes={xr[IDX_BYTES]:.1f} dir_asym={xr[IDX_DIR_ASYM]:.3f}")
    print(f"  SC:  pkts={xs[IDX_PKTS]:.3f} bytes={xs[IDX_BYTES]:.3f} dir_asym={xs[IDX_DIR_ASYM]:.3f}")
    print(f"  Flags: very_eph={is_very_eph[idx]} sustained={is_sustained[idx]} no_resp={is_no_resp[idx]}")
    print(f"         pkts_hi={pkts_hi[idx]} bytes_lo={bytes_lo[idx]} dir_asym_ok={dir_asym_ok[idx]}")
    print(f"  Rule triggered: {'R2' if r2[idx] else ''} {'R3' if r3[idx] else ''}")

# Статистика всех бенигнных UDP
print(f"\n=== Статистика всех {len(X_raw)} бенигнных UDP в CTU-54 ===")
print(f"very_eph=1:  {is_very_eph.sum()} ({100*is_very_eph.mean():.1f}%)")
print(f"sustained=1: {is_sustained.sum()} ({100*is_sustained.mean():.1f}%)")
print(f"no_resp=1:   {is_no_resp.sum()} ({100*is_no_resp.mean():.1f}%)")
print(f"pkts_hi=1:   {pkts_hi.sum()} ({100*pkts_hi.mean():.1f}%)")
print(f"bytes_lo=1:  {bytes_lo.sum()} ({100*bytes_lo.mean():.1f}%)")
print(f"ben_locked:  {ben_locked.sum()}")
print(f"net_decides (NaN): {np.isnan(score).sum()}")
print(f"rule_bad:    {rule_bad_mask.sum()}")

# Среди rule_bad — проверяем какой диапазон bytes_raw у R2-плохих
r2_bad = np.where(r2)[0]
r3_bad = np.where(r3)[0]
print(f"\nR2 triggers on benign: {len(r2_bad)}")
print(f"R3 triggers on benign: {len(r3_bad)}")
if len(r2_bad):
    print(f"  R2 raw bytes range: {X_raw[r2_bad, IDX_BYTES].min():.1f} - {X_raw[r2_bad, IDX_BYTES].max():.1f}")
    print(f"  R2 raw pkts range:  {X_raw[r2_bad, IDX_PKTS].min():.1f} - {X_raw[r2_bad, IDX_PKTS].max():.1f}")
if len(r3_bad):
    print(f"  R3 raw bytes range: {X_raw[r3_bad, IDX_BYTES].min():.1f} - {X_raw[r3_bad, IDX_BYTES].max():.1f}")
    print(f"  R3 raw pkts range:  {X_raw[r3_bad, IDX_PKTS].min():.1f} - {X_raw[r3_bad, IDX_PKTS].max():.1f}")

# Смотрим также сколько АТАКУЮЩИХ flows имеют R3-паттерн (sustained + no_resp)
print("\n--- Загружаем атакующие UDP CTU-54 для контраста ---")
xs_atk, ys_atk, rows_atk = [], [], []
with open(CTU54, encoding="utf-8", newline="") as f:
    for row in csv.DictReader(f):
        y = class_for_label(row.get("Label", ""))
        if y != 1: continue
        proto = str(row.get("Proto", "")).lower()
        if proto != "udp": continue
        try:
            feat = list(from_ctu_row(row))
        except Exception:
            continue
        xs_atk.append(feat)
        rows_atk.append(row)

if xs_atk:
    X_atk = np.array(xs_atk, dtype=np.float32)
    X_atk_sc = (X_atk - q25) / iqr
    sust_atk = X_atk_sc[:, IDX_SUSTAINED] > 0.5
    noresp_atk = X_atk_sc[:, IDX_NO_RESP] > 0.5
    veph_atk = X_atk_sc[:, IDX_VERY_EPH] > 0.5
    blo_atk = X_atk_sc[:, IDX_BYTES] < -0.5
    print(f"Атакующих UDP CTU-54: {len(X_atk)}")
    print(f"R3-паттерн (sustained+no_resp): {(sust_atk & noresp_atk).sum()}")
    print(f"R2-паттерн (veph+no_resp+blo):  {(veph_atk & noresp_atk & blo_atk).sum()}")
