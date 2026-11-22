"""
Диагностика 12 net_decides FP на CTU-53 и 53 FP на CTU-54.
Находим бенигн-правило для этих flows.
"""
import sys, os, csv, gzip, math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import numpy as np
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, from_ctu_row, FEATURE_VERSION

DATA = ROOT / "outputs" / "network-eval"

IDX_UDP=5; IDX_PKTS=1; IDX_BYTES=2; IDX_DIR_ASYM=10
IDX_VERY_EPH=11; IDX_SUSTAINED=13; IDX_NO_RESP=16

CAPS = {
    "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}

def open_flow(path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return open(path, encoding="utf-8", newline="")

def class_for_label(label):
    if label.startswith("flow=From-Botnet-"): return 1
    if label.startswith("flow=From-Normal-"): return 0
    return -1

def apply_rules(X_sc):
    n = len(X_sc)
    score = np.full(n, np.nan)
    is_udp       = X_sc[:, IDX_UDP]       > 0.5
    is_very_eph  = X_sc[:, IDX_VERY_EPH]  > 0.5
    is_sustained = X_sc[:, IDX_SUSTAINED] > 0.5
    is_no_resp   = X_sc[:, IDX_NO_RESP]   > 0.5
    pkts_hi      = X_sc[:, IDX_PKTS]      > 0.603
    bytes_lo     = X_sc[:, IDX_BYTES]     < -0.5
    b1 = is_udp & is_very_eph & ~is_sustained & ~is_no_resp
    score[b1] = 0.0
    b2 = is_udp & is_very_eph & ~is_sustained & ~pkts_hi
    score[b2] = 0.0
    b3 = is_udp & ~is_sustained & ~is_no_resp
    score[b3] = 0.0
    ben_locked = ~np.isnan(score) & (score < 0.5)
    r2 = is_udp & is_very_eph & is_no_resp & bytes_lo & ~ben_locked
    score[r2] = 1.0
    return score

def diag(cap_id):
    path = CAPS[cap_id]
    rows_raw = []
    xs = []
    with open_flow(path) as f:
        for row in csv.DictReader(f):
            y = class_for_label(row.get("Label", ""))
            if y < 0: continue
            try:
                feat = list(from_ctu_row(row))
            except: continue
            rows_raw.append((y, row))
            xs.append(feat)
    
    X = np.array(xs, dtype=np.float32)
    # IQR scaler (approximate from run27 - use median/IQR)
    q25 = np.percentile(X, 25, axis=0)
    iqr = np.percentile(X, 75, axis=0) - q25
    iqr = np.where(iqr < 1e-8, 1.0, iqr)
    X_sc = (X - q25) / iqr
    
    score = apply_rules(X_sc)
    
    print(f"\n=== CTU-{cap_id}: net_decides FP analysis ===")
    ben_udp_net_fp = []
    for i, (y, row) in enumerate(rows_raw):
        if y != 0: continue
        proto = str(row.get("Proto","")).lower()
        if proto != "udp": continue
        if np.isnan(score[i]):  # net_decides
            sc = X_sc[i]
            sport = row.get("Sport","?")
            dport = row.get("Dport","?")
            dur   = row.get("Dur","?")
            pkts  = row.get("TotPkts","?")
            byt   = row.get("TotBytes","?")
            label = row.get("Label","?")
            very_eph  = int(sc[IDX_VERY_EPH] > 0.5)
            sustained = int(sc[IDX_SUSTAINED] > 0.5)
            no_resp   = int(sc[IDX_NO_RESP] > 0.5)
            sc_pkts   = round(float(sc[IDX_PKTS]), 3)
            sc_bytes  = round(float(sc[IDX_BYTES]), 3)
            ben_udp_net_fp.append({
                "i": i, "sport": sport, "dport": dport,
                "dur": dur, "pkts": pkts, "bytes": byt,
                "eph": very_eph, "sust": sustained, "noresp": no_resp,
                "sc_pkts": sc_pkts, "sc_bytes": sc_bytes,
                "label": label
            })
    
    print(f"net_decides count: {len(ben_udp_net_fp)}")
    
    if not ben_udp_net_fp:
        print("Нет FP!")
        return
    
    # Статистика
    for f in ben_udp_net_fp[:30]:
        print(f"  sp={f['sport']:>5} dp={f['dport']:>5} pkts={f['pkts']:>4} "
              f"bytes={f['bytes']:>7} dur={f['dur']:>7} "
              f"eph={f['eph']} sust={f['sust']} noresp={f['noresp']} "
              f"sc_pkts={f['sc_pkts']:>6} sc_bytes={f['sc_bytes']:>6}"
              f" | {str(f['label'])[:40]}")
    
    dports = Counter(f["dport"] for f in ben_udp_net_fp)
    sports = Counter(f["sport"] for f in ben_udp_net_fp)
    ephs   = Counter(f["eph"] for f in ben_udp_net_fp)
    susts  = Counter(f["sust"] for f in ben_udp_net_fp)
    noresps= Counter(f["noresp"] for f in ben_udp_net_fp)
    
    print(f"\nТоп Dport: {dports.most_common(10)}")
    print(f"Топ Sport: {sports.most_common(10)}")
    print(f"very_eph: {dict(ephs)}  sustained: {dict(susts)}  no_resp: {dict(noresps)}")
    
    sc_pkts_vals = [f["sc_pkts"] for f in ben_udp_net_fp]
    sc_bytes_vals = [f["sc_bytes"] for f in ben_udp_net_fp]
    print(f"sc_pkts: min={min(sc_pkts_vals):.3f} max={max(sc_pkts_vals):.3f} mean={np.mean(sc_pkts_vals):.3f}")
    print(f"sc_bytes: min={min(sc_bytes_vals):.3f} max={max(sc_bytes_vals):.3f} mean={np.mean(sc_bytes_vals):.3f}")
    
    # Pkts в натуральных числах
    pkts_vals = []
    for f in ben_udp_net_fp:
        try: pkts_vals.append(int(f["pkts"]))
        except: pass
    if pkts_vals:
        print(f"TotPkts raw: min={min(pkts_vals)} max={max(pkts_vals)} Counter={Counter(pkts_vals).most_common(10)}")

diag("53")
diag("54")
