import csv, sys
from pathlib import Path
sys.path.insert(0, 'F:/New/integrityguard')
from integrityguard.network_flow_schema import from_ctu_row
import numpy as np

path = Path('F:/New/integrityguard/outputs/network-eval/official-ctu13/capture20110819_ctu53.binetflow')
xs, ys, raw_rows = [], [], []
with open(path, encoding='utf-8', newline='') as f:
    for row in csv.DictReader(f):
        lbl = row.get('Label', '')
        if lbl.startswith('flow=From-Botnet-'): y = 1
        elif lbl.startswith('flow=From-Normal-'): y = 0
        else: continue
        try: v = from_ctu_row(row)
        except: continue
        xs.append(v); ys.append(y); raw_rows.append(row)

x = np.array(xs, np.float32); y = np.array(ys)
q25 = np.array([0.00022,1.0986,5.5013,5.2311,0,0,0,0,4.2437,2.2604,0.3204,0,0.000446,0,0,0,0], np.float32)
iqr = np.array([0.4632,0.8473,1.4713,1.7415,1,1,1,1,1.9820,5.3410,0.6796,1,1.9262,1,1,0.5,1], np.float32)
xn = np.clip((x - q25)/iqr, -10, 10)

IDX_PKTS=1; IDX_SUSTAINED=13; IDX_VERY_EPH=11; IDX_NO_RESP=16; IDX_UDP=5
ben = y==0; atk = y==1
is_sustained = xn[:,IDX_SUSTAINED] > 0.5

# Rule1 FP analysis
fp_idx = np.where(ben & is_sustained & (xn[:,IDX_PKTS] > 0.6))[0]
print("=== Rule1 FP flows (benign sustained UDP pkts>4) ===")
for i in fp_idx:
    r = raw_rows[i]
    dur = r.get('Dur', '?')
    pkts = r.get('TotPkts', '?')
    byt = r.get('TotBytes', '?')
    sb = r.get('SrcBytes', '?')
    proto = r.get('Proto', '?')
    asym_raw = x[i, 10]  # direction_asym
    print(f"  dur={dur} pkts={pkts} bytes={byt} src={sb} proto={proto} asym={asym_raw:.3f} pkts_norm={xn[i,1]:.3f}")

print()
print("=== Pkts threshold search for Rule1 ===")
for thr in [0.6, 0.7, 0.8, 0.9, 1.0, 1.5, 2.0]:
    fp = int((ben & is_sustained & (xn[:,IDX_PKTS] > thr)).sum())
    tp = int((atk & is_sustained & (xn[:,IDX_PKTS] > thr)).sum())
    print(f"  pkts_norm > {thr}: FP={fp} TP={tp}")

print()
print("=== Rule2 (very_eph & no_resp) analysis ===")
is_very_eph = xn[:,IDX_VERY_EPH] > 0.5
is_no_resp = xn[:,IDX_NO_RESP] > 0.5
fp2_idx = np.where(ben & is_very_eph & is_no_resp)[0]
print(f"Rule2 FP: {len(fp2_idx)}")
for i in fp2_idx:
    r = raw_rows[i]
    dur = r.get('Dur', '?')
    pkts = r.get('TotPkts', '?')
    byt = r.get('TotBytes', '?')
    sb = r.get('SrcBytes', '?')
    asym_raw = x[i, 10]
    print(f"  dur={dur} pkts={pkts} bytes={byt} src={sb} asym={asym_raw:.3f}")

tp2 = int((atk & is_very_eph & is_no_resp).sum())
print(f"Rule2 TP: {tp2}")
