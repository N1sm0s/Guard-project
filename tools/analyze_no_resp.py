import sys; sys.path.insert(0, 'F:/New/integrityguard')
import csv; import numpy as np
from pathlib import Path
from integrityguard.network_flow_schema import from_ctu_row

path = Path('F:/New/integrityguard/outputs/network-eval/official-ctu13/capture20110819_ctu53.binetflow')
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
is_very_eph = x[:,11] > 0.5
is_no_resp = x[:,16] > 0.5
ben = y==0; atk = y==1

print("=== Attack very_eph & no_resp (first 10) ===")
idx = np.where(atk & is_very_eph & is_no_resp)[0][:10]
for i in idx:
    r = rws[i]
    dur = r.get("Dur", "?")
    pkts = r.get("TotPkts", "?")
    byt = r.get("TotBytes", "?")
    sb = r.get("SrcBytes", "?")
    proto = r.get("Proto", "?")
    print("  dur=%s pkts=%s bytes=%s src=%s proto=%s" % (dur, pkts, byt, sb, proto))

print("=== Benign very_eph & no_resp (all 3) ===")
idx2 = np.where(ben & is_very_eph & is_no_resp)[0]
for i in idx2:
    r = rws[i]
    dur = r.get("Dur", "?")
    pkts = r.get("TotPkts", "?")
    byt = r.get("TotBytes", "?")
    sb = r.get("SrcBytes", "?")
    proto = r.get("Proto", "?")
    print("  dur=%s pkts=%s bytes=%s src=%s proto=%s" % (dur, pkts, byt, sb, proto))

print("attack no_resp bytes: total %d" % len(np.where(atk & is_very_eph & is_no_resp)[0]))
atk_nr_byt = []
for i in np.where(atk & is_very_eph & is_no_resp)[0]:
    atk_nr_byt.append(int(rws[i].get("TotBytes", 0)))
arr = np.array(atk_nr_byt)
print("  p0=%d p10=%.0f p50=%.0f p90=%.0f p100=%d" % (
    arr.min(), np.percentile(arr,10), np.percentile(arr,50), np.percentile(arr,90), arr.max()))
