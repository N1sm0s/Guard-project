import json
d = json.load(open('outputs/network-eval/ctu13-scenarios-flow-v3-metrics-v2.json'))
it = d.get('independent_test', {})
print('=== V2 METRICS ===')
print('capture_split:', d.get('capture_split'))
pc = it.get('per_capture', {})
for cap, m in pc.items():
    thr = m.get('validation_selected_threshold', {})
    r = thr.get('attack_recall', 0)
    fpr = thr.get('benign_false_positive_rate', 0)
    ci = thr.get('attack_recall_ci95_wilson', [0, 0])
    ci_lo = ci[0] if ci else 0
    print(f"  capture {cap}: recall={r:.4f}, CI_lo={ci_lo:.4f}, FPR={fpr:.6f}")
vt = it.get('validation_selected_threshold', {})
print('combined recall:', vt.get('attack_recall'))
print('combined FPR:', vt.get('benign_false_positive_rate'))
val = d.get('validation', {})
print('threshold:', val.get('selected_threshold'))
