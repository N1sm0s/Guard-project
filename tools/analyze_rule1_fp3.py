import sys; sys.path.insert(0, 'F:/New/integrityguard')
import csv; import numpy as np
from pathlib import Path
from integrityguard.network_flow_schema import from_ctu_row

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
    IDX_PKTS=1; IDX_SUSTAINED=13; IDX_BYTES=2; IDX_UDP=5; IDX_NO_RESP=16; IDX_VERY_EPH=11
    IDX_ASYM=10; IDX_PKTRATE=9; IDX_DUR=0; IDX_UDP_DUR=15
    ben = y==0
    is_sustained = xn[:,IDX_SUSTAINED] > 0.5
    is_byt_low = xn[:,IDX_BYTES] < 0.7
    fps = ben & is_sustained & (xn[:,IDX_PKTS] > 0.6) & is_byt_low
    print(f"CTU-53 Rule1 FP with bytes_norm<0.7: {fps.sum()}")
    print(f"{'dur':>10} {'pkts':>6} {'bytes':>7} {'src':>5} {'asym':>6} {'pktrate':>9} {'dur_norm':>9} {'bytes_n':>8} {'pktr_n':>7} {'asym_n':>7}")
    for i in np.where(fps)[0]:
        r = rws[i]
        dur = float(r.get('Dur','0')); pkts = float(r.get('TotPkts','0'))
        byt = float(r.get('TotBytes','0')); src = float(r.get('SrcBytes','0'))
        asym_raw = abs(src - (byt-src))/(byt+1e-9)
        pktrate_raw = pkts/(dur+1e-9)
        print(f"{dur:>10.2f} {pkts:>6.0f} {byt:>7.0f} {src:>5.0f} {asym_raw:>6.3f} {pktrate_raw:>9.4f} {xn[i,IDX_DUR]:>9.4f} {xn[i,IDX_BYTES]:>8.4f} {xn[i,IDX_PKTRATE]:>7.4f} {xn[i,IDX_ASYM]:>7.4f}")
    print()
    # Compare with attacks sustained bytes_norm < 0.7
    atk = y==1
    fps_atk = atk & is_sustained & (xn[:,IDX_PKTS] > 0.6) & is_byt_low
    print(f"CTU-53 Attack sustained bytes_norm<0.7: {fps_atk.sum()}")
    pktrates_atk = xn[fps_atk, IDX_PKTRATE]
    asym_atk = xn[fps_atk, IDX_ASYM]
    pktrates_fp = xn[fps, IDX_PKTRATE]
    asym_fp = xn[fps, IDX_ASYM]
    if len(pktrates_atk) > 0:
        print(f"  Attack pktrate_norm: p0={np.percentile(pktrates_atk,0):.3f} p10={np.percentile(pktrates_atk,10):.3f} p50={np.percentile(pktrates_atk,50):.3f} p90={np.percentile(pktrates_atk,90):.3f} p100={np.percentile(pktrates_atk,100):.3f}")
        print(f"  Attack asym_norm:    p0={np.percentile(asym_atk,0):.3f} p10={np.percentile(asym_atk,10):.3f} p50={np.percentile(asym_atk,50):.3f} p90={np.percentile(asym_atk,90):.3f} p100={np.percentile(asym_atk,100):.3f}")
    if len(pktrates_fp) > 0:
        print(f"  FP pktrate_norm:     {list(np.round(pktrates_fp,3))}")
        print(f"  FP asym_norm:        {list(np.round(asym_fp,3))}")
