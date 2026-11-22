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

for cap_name, fname in [("53","capture20110819_ctu53.binetflow")]:
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
    IDX_PKTS=1; IDX_SUSTAINED=13; IDX_BYTES=2; IDX_UDP=5; IDX_NO_RESP=16; IDX_VERY_EPH=11; IDX_DUR=0
    ben = y==0; atk = y==1
    is_sustained = xn[:,IDX_SUSTAINED] > 0.5
    is_byt_low = xn[:,IDX_BYTES] < 0.7
    is_pkts = xn[:,IDX_PKTS] > 0.6
    fps3 = ben & is_sustained & is_pkts & is_byt_low
    # 3 FP have dur≈5.01s. What is dur_norm for them?
    print(f"3 FP dur_norm values: {xn[fps3, IDX_DUR]}")
    print(f"3 FP pkts_norm values: {xn[fps3, IDX_PKTS]}")
    print(f"3 FP bytes_norm values: {xn[fps3, IDX_BYTES]}")
    # Attack sustained bytes<0.7, pkts>0.6 — what are their dur_norm?
    fps_atk = atk & is_sustained & is_pkts & is_byt_low
    print(f"\nAttack sustained (pkts>0.6, bytes<0.7): {fps_atk.sum()}")
    dur_atk = xn[fps_atk, IDX_DUR]
    print(f"Attack dur_norm: p0={np.min(dur_atk):.3f} p1={np.percentile(dur_atk,1):.3f} p5={np.percentile(dur_atk,5):.3f} p10={np.percentile(dur_atk,10):.3f} p50={np.percentile(dur_atk,50):.3f} p90={np.percentile(dur_atk,90):.3f}")
    
    # Try dur_norm threshold: FP have dur≈5.01s. If attacks have higher dur, we can filter
    for dur_lo in [5.0, 6.0, 7.0, 8.0, 10.0]:
        is_dur_hi = xn[:,IDX_DUR] > dur_lo
        fp_now = int((ben & is_sustained & is_pkts & is_byt_low & ~is_dur_hi).sum())
        tp_now = int((atk & is_sustained & is_pkts & is_byt_low & ~is_dur_hi).sum())
        fp_lo_dur = int((ben & is_sustained & is_pkts & is_byt_low & is_dur_hi).sum())
        tp_hi_dur = int((atk & is_sustained & is_pkts & is_byt_low & is_dur_hi).sum())
        print(f"  dur_norm<={dur_lo}: FP={fp_now} TP={tp_now}  |  dur_norm>{dur_lo}: FP={fp_lo_dur} TP={tp_hi_dur}")
    
    print(f"\nFP dur raw values:")
    for i in np.where(fps3)[0]:
        r = rws[i]
        print(f"  dur={float(r.get('Dur','0')):.3f}  dur_norm={xn[i,IDX_DUR]:.4f}")
