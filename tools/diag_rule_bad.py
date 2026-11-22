"""Диагностика 3 бенигнных UDP которые попадают под атак-правила"""
import csv, sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

DATA = ROOT / "outputs" / "network-eval"

IDX_UDP=5; IDX_PKTS=1; IDX_BYTES=2; IDX_DIR_ASYM=10
IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_NO_RESP=16

def load_capture(path):
    xs, ys, raw_rows = [], [], []
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            label = row.get("Label","")
            if label.startswith("flow=From-Botnet-"): y=1
            elif label.startswith("flow=From-Normal-"): y=0
            else: continue
            try:
                feat = list(from_ctu_row(row))
            except: continue
            xs.append(feat); ys.append(y); raw_rows.append(row)
    return np.array(xs, dtype=np.float32), np.array(ys), raw_rows

class IQRScaler:
    def fit(self, X):
        self.q25 = np.percentile(X, 25, axis=0)
        self.iqr = np.percentile(X, 75, axis=0) - self.q25
        self.iqr = np.where(self.iqr < 1e-8, 1.0, self.iqr)
    def transform(self, X): return (X - self.q25) / self.iqr

# Загрузка train для scaler
print("Loading train data...")
all_X = []
for cid, fname in [("42","ctu-42.binetflow"),("43","ctu-43.binetflow")]:
    p = DATA / fname
    if p.exists():
        X, y, _ = load_capture(p)
        all_X.append(X)

# Используем CTU-53 для диагностики
path53 = DATA / "official-ctu13" / "capture20110819_ctu53.binetflow"
X53, y53, rows53 = load_capture(path53)

# Простой scaler на CTU-53 данных
scaler = IQRScaler()
scaler.fit(X53)
X53_sc = scaler.transform(X53)

is_udp = X53_sc[:, IDX_UDP] > 0.5
is_very_eph = X53_sc[:, IDX_VERY_EPH] > 0.5
is_sustained = X53_sc[:, IDX_SUSTAINED] > 0.5
is_no_resp = X53_sc[:, IDX_NO_RESP] > 0.5
pkts_hi = X53_sc[:, IDX_PKTS] > 0.603
dir_asym_ok = X53_sc[:, IDX_DIR_ASYM] > -0.40
bytes_lo = X53_sc[:, IDX_BYTES] < -0.5

is_ben = (y53 == 0)

# Найдём бенигнных UDP которые попадают под атак-правила
# R1: is_sustained & pkts_hi & dir_asym_ok
r1 = is_udp & is_sustained & pkts_hi & dir_asym_ok
r2 = is_udp & is_very_eph & is_no_resp & bytes_lo
r3 = is_udp & is_sustained & is_no_resp

atk_mask = r1 | r2 | r3
ben_atk = is_ben & atk_mask

print(f"\nБенигнных UDP под атак-правилами: {ben_atk.sum()}")
print(f"  R1 (sustained+pkts_hi+dir_asym): {(is_ben & r1).sum()}")
print(f"  R2 (very_eph+no_resp+bytes_lo): {(is_ben & r2).sum()}")
print(f"  R3 (sustained+no_resp): {(is_ben & r3).sum()}")

print("\nДетали этих потоков:")
for i in np.where(ben_atk)[0]:
    row = rows53[i]
    xsc = X53_sc[i]
    print(f"\n  idx={i}")
    print(f"    Label: {row.get('Label','')}")
    print(f"    Proto: {row.get('Proto','')}, Dur: {row.get('Dur','')}")
    print(f"    SrcBytes: {row.get('SrcBytes','')}, Pkts: {row.get('Pkts','')}")
    print(f"    is_udp={is_udp[i]}, is_sustained={is_sustained[i]}, is_very_eph={is_very_eph[i]}")
    print(f"    is_no_resp={is_no_resp[i]}, pkts_hi={pkts_hi[i]}, dir_asym_ok={dir_asym_ok[i]}")
    print(f"    raw features: pkts={X53[i,IDX_PKTS]:.1f}, bytes={X53[i,IDX_BYTES]:.1f}")
    print(f"    scaled: pkts_sc={xsc[IDX_PKTS]:.3f}, dir_asym_sc={xsc[IDX_DIR_ASYM]:.3f}")
    print(f"    Rule fired: R1={r1[i]}, R2={r2[i]}, R3={r3[i]}")

# Также смотрим признаки атакующих UDP
atk_udp = (y53 == 1) & is_udp
print(f"\n\nАтакующих UDP всего: {atk_udp.sum()}")
print(f"  Покрыты правилами: {(atk_udp & atk_mask).sum()}")
print(f"    R1: {(atk_udp & r1).sum()}, R2: {(atk_udp & r2).sum()}, R3: {(atk_udp & r3).sum()}")
print(f"  НЕ покрыты (net_decides): {(atk_udp & ~atk_mask).sum()}")
print(f"\nСтатистика атак UDP по признакам:")
print(f"  sustained: {is_sustained[atk_udp].mean():.2%}")
print(f"  very_eph:  {is_very_eph[atk_udp].mean():.2%}")
print(f"  no_resp:   {is_no_resp[atk_udp].mean():.2%}")
print(f"  pkts_hi:   {pkts_hi[atk_udp].mean():.2%}")
