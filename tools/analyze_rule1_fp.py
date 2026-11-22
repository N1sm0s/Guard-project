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
    is_small_bytes = xn[:,IDX_BYTES] < -0.5
    is_udp = xn[:,IDX_UDP] > 0.5

    print(f"\n=== CTU-{cap_name} ===")
    # Attack sustained bytes distribution
    atk_sust_bytes = x[atk & is_sustained, 2]  # total_bytes_log1p
    if len(atk_sust_bytes) > 0:
        print("Attack sustained bytes(log1p) p10=%.3f p50=%.3f p90=%.3f p99=%.3f" % (
            np.percentile(atk_sust_bytes,10), np.percentile(atk_sust_bytes,50),
            np.percentile(atk_sust_bytes,90), np.percentile(atk_sust_bytes,99)))
        atk_sust_bytes_norm = xn[atk & is_sustained, 2]
        print("Attack sustained bytes_norm p10=%.3f p50=%.3f p90=%.3f" % (
            np.percentile(atk_sust_bytes_norm,10), np.percentile(atk_sust_bytes_norm,50),
            np.percentile(atk_sust_bytes_norm,90)))
    # Benign sustained FP pkts>4
    for i in np.where(ben & is_sustained & (xn[:,IDX_PKTS] > 0.6))[0]:
        r = rws[i]
        dur = r.get("Dur","?"); pkts = r.get("TotPkts","?")
        byt = r.get("TotBytes","?"); sb = r.get("SrcBytes","?")
        print("  BEN_SUST_FP: dur=%s pkts=%s bytes=%s src=%s bytes_norm=%.3f" % (
            dur, pkts, byt, sb, xn[i, IDX_BYTES]))
    # Test different bytes thresholds for Rule1
    print("\nRule1 bytes threshold search:")
    for byt_thr in [-0.6, -0.4, -0.2, 0.0, 0.2, 0.5, 1.0]:
        is_large = xn[:,IDX_BYTES] > byt_thr
        fp = int((ben & is_sustained & (xn[:,IDX_PKTS] > 0.6) & is_large).sum())
        tp = int((atk & is_sustained & (xn[:,IDX_PKTS] > 0.6) & is_large).sum())
        print(f"  bytes_norm > {byt_thr}: FP={fp} TP={tp}")

    # Combined rules FP count
    fp_r1 = int((ben & is_sustained & (xn[:,IDX_PKTS] > 0.6)).sum())
    fp_r2 = int((ben & is_very_eph & is_no_resp & is_small_bytes).sum())
    n_udp_ben = int((ben & is_udp).sum())
    print(f"\nFP Rule1={fp_r1} FP Rule2={fp_r2} Total={fp_r1+fp_r2}")
    print(f"UDP benign={n_udp_ben}, CI_hi(FP total)={wilson_hi(fp_r1+fp_r2, n_udp_ben):.6f}")

    # What if we add bytes_norm > -0.3 for Rule1 (only large-bytes sustained)?
    for byt_thr in [-0.5, -0.3, -0.1, 0.1]:
        is_large = xn[:,IDX_BYTES] > byt_thr
        fp_r1_new = int((ben & is_sustained & (xn[:,IDX_PKTS] > 0.6) & is_large).sum())
        tp_r1_new = int((atk & is_sustained & (xn[:,IDX_PKTS] > 0.6) & is_large).sum())
        total_fp = fp_r1_new + fp_r2
        ci_hi = wilson_hi(total_fp, n_udp_ben)
        print(f"  R1 byt_norm>{byt_thr}: FP_R1={fp_r1_new} TP_R1={tp_r1_new} total_FP={total_fp} CI_hi={ci_hi:.6f}")
