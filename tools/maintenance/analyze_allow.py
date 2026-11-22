import sqlite3, json, collections
import numpy as np

con = sqlite3.connect('F:/New/integrityguard/data/online/network_events.sqlite')
rows = con.execute('SELECT snapshot_json, assessment_json FROM events').fetchall()

FEATURE_NAMES = [
    'active_connection_count','remote_endpoint_count','established_count',
    'listen_count','other_state_count','new_remote_endpoint_count',
    'dshield_match_count','dshield_targets_reported_max',
    'bytes_received_per_second','bytes_sent_per_second',
    'distinct_process_count','suspicious_port_match_count',
    'port_scan_suspected_count','packet_rate_zscore','byte_rate_zscore'
]

by_class = collections.defaultdict(list)
for sj, aj in rows:
    try:
        snap = json.loads(sj)
        label = json.loads(aj).get('model_decision', '?')
        feat = [float(snap.get(f, 0) or 0) for f in FEATURE_NAMES]
        by_class[label].append(feat)
    except:
        pass

print("=== Feature means by class (top-5 discriminating) ===")
class_means = {}
for cls, feats in sorted(by_class.items()):
    arr = np.array(feats)
    class_means[cls] = arr.mean(axis=0)
    print(f"\n{cls} (n={len(feats)}):")
    top = sorted(enumerate(arr.mean(axis=0)), key=lambda x: abs(x[1]), reverse=True)[:5]
    for idx, val in top:
        print(f"  {FEATURE_NAMES[idx]}: {val:.3f}")

print("\n=== Feature comparison: ALLOW vs BLOCK (biggest gaps) ===")
if 'ALLOW' in class_means and 'BLOCK' in class_means:
    diff = class_means['BLOCK'] - class_means['ALLOW']
    top_diff = sorted(enumerate(diff), key=lambda x: abs(x[1]), reverse=True)[:8]
    for idx, d in top_diff:
        a = class_means['ALLOW'][idx]
        b = class_means['BLOCK'][idx]
        print(f"  {FEATURE_NAMES[idx]}: ALLOW={a:.3f}, BLOCK={b:.3f}, diff={d:+.3f}")

print("\n=== ALLOW class: examples where high bytes but classified ALLOW ===")
allow_feats = by_class.get('ALLOW', [])
arr = np.array(allow_feats)
bytes_recv_idx = FEATURE_NAMES.index('bytes_received_per_second')
high_bw = arr[arr[:, bytes_recv_idx] > arr[:, bytes_recv_idx].mean() + arr[:, bytes_recv_idx].std()]
print(f"  ALLOW examples with high bytes_received: {len(high_bw)}/{len(allow_feats)}")
