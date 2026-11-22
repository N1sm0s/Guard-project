import json
d = json.load(open('outputs/network-eval/ctu13-scenarios-flow-v3-metrics-v2.json'))
val = d.get('validation', {})
print('=== VALIDATION (capture 50) ===')
sm = val.get('selected_threshold_metrics', {})
print('threshold:', val.get('selected_threshold'))
print('recall:', sm.get('attack_recall'))
print('FPR:', sm.get('benign_false_positive_rate'))
print('n_attack:', sm.get('n_attack'))
print('n_benign:', sm.get('n_benign'))

# Check at 0.5 threshold for test
it = d.get('independent_test', {})
pc = it.get('per_capture', {})
for cap, m in pc.items():
    t5 = m.get('fixed_threshold_0_5', {})
    print(f"\ncapture {cap} at threshold 0.5:")
    print(f"  recall={t5.get('attack_recall'):.4f}, FPR={t5.get('benign_false_positive_rate'):.4f}")
    print(f"  n_attack={t5.get('n_attack')}, n_benign={t5.get('n_benign')}")
    ci = t5.get('attack_recall_ci95_wilson', [0,0])
    print(f"  CI_recall=[{ci[0]:.4f}, {ci[1]:.4f}]")
