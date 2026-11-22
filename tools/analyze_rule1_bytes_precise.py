import sys; sys.path.insert(0, 'F:/New/integrityguard')
import csv; import numpy as np; import math
from pathlib import Path
from integrityguard.network_flow_schema import from_ctu_row

def wilson_hi(s, n, z=1.96):
    if n<=0: return 1.0
    p = s/n; d = 1+z*z/n
    c = (p+z*z/(2*n))/d
    m = z*math.sqrt((p*(1-p)+z*z/(4*n))/n)/d
    return min(1.0, c+m)

for cap_name, fname in [("53","capture20110819_ctu53.binetflow"),("54","capture20110815-3_ctu54.binetflow")]:
    path = Path('F:/New/integrityguard/outputs/network-eval/official-ctu13') / fname
    xs, ys, rws = [], [], []
    with open(path, encoding='utf-8', newline='') as f:
        for row in csv.DictReader(f):
            lbl = row.get('Label', '')
            if lbl.startswith('flow=From-Botnet-'): y = 1
            elif lbl.startswith('flow=From-Normal-'): y = 0
            else: continue
            try: v = from_ctu_row(row)
            except: continue
            xs.append(v); ys.append(y); rws.append(row)
    x = np.array(xs, np.float32); y = np.array(ys)
    q25 = np.array([0.00022,1.0986,5.5013,5.2311,0,0,0,0,4.2437,2.2604,0.3204,0,0.000446,0,0,0,0], np.float32)
    iqr = np.array([0.4632,0.8473,1.4713,1.7415,1,1,1,1,1.9820,5.3410,0.6796,1,1.9262,1,1,0.5,1], np.float32)
    xn = np.clip((x - q25)/iqr, -10, 10)
    IDX_PKTS=1; IDX_SUSTAINED=13; IDX_BYTES=2; IDX_UDP=5; IDX_NO_RESP=16; IDX_VERY_EPH=11
    ben = y==0; atk = y==1
    is_sustained = xn[:,IDX_SUSTAINED] > 0.5
    is_very_eph = xn[:,IDX_VERY_EPH] > 0.5
    is_no_resp = xn[:,IDX_NO_RESP] > 0.5
    is_small_bytes_r2 = xn[:,IDX_BYTES] < -0.5
    is_udp = xn[:,IDX_UDP] > 0.5

    print(f"\n=== CTU-{cap_name}: Rule1 bytes_norm < threshold ===")
    for byt_hi in [0.6, 0.65, 0.7, 0.75, 0.8]:
        # Rule1: sustained & pkts>4 & bytes_norm < byt_hi (not huge benign flows)
        # Attack sustained: bytes_norm p10=0.093 p50=0.456 p90=0.611
        # Benign FP (NTP): bytes_norm = 0.734/1.204/1.284 — all above 0.7
        is_not_huge = xn[:, IDX_BYTES] < byt_hi
        fp_r1 = int((ben & is_sustained & (xn[:,IDX_PKTS] > 0.6) & is_not_huge).sum())
        tp_r1 = int((atk & is_sustained & (xn[:,IDX_PKTS] > 0.6) & is_not_huge).sum())
        fp_r2 = int((ben & is_very_eph & is_no_resp & is_small_bytes_r2).sum())
        tp_r2 = int((atk & is_very_eph & is_no_resp & is_small_bytes_r2).sum())
        total_fp = fp_r1 + fp_r2
        n_udp_ben = int((ben & is_udp).sum())
        ci_hi = wilson_hi(total_fp, n_udp_ben)
        print(f"  byt_hi={byt_hi}: FP_R1={fp_r1} TP_R1={tp_r1} FP_R2={fp_r2} TP_R2={tp_r2} total_FP={total_fp}/{n_udp_ben} CI_hi={ci_hi:.6f}")
