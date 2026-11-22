"""Check how many TP come from rules vs MLP at various thresholds."""
import numpy as np, sys
sys.path.insert(0,'F:\\New\\integrityguard')
import torch, torch.nn as nn

ckpt = torch.load('F:\\New\\integrityguard\\outputs\\network-eval\\ctu13-v10-gate5-candidate.pt', map_location='cpu')
q25 = np.array(ckpt['q25']); iqr = np.array(ckpt['iqr'])

from tools.train_v7 import load_cap, TEST_CAPS, IDX_UDP, IDX_SUSTAINED, IDX_VERY_EPH, IDX_NO_RESP
IDX_PKTS = 1  # packets feature index (defined locally, not exported from train_v7)

class MLP(nn.Module):
    def __init__(self, n):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n,512), nn.BatchNorm1d(512), nn.GELU(), nn.Dropout(0.3),
            nn.Linear(512,256), nn.BatchNorm1d(256), nn.GELU(), nn.Dropout(0.25),
            nn.Linear(256,128), nn.BatchNorm1d(128), nn.GELU(), nn.Dropout(0.2),
            nn.Linear(128,64), nn.BatchNorm1d(64), nn.GELU(), nn.Dropout(0.1),
            nn.Linear(64,2))
    def forward(self, x): return self.net(x)

model = MLP(17)
model.load_state_dict(ckpt['state_dict'])
model.eval()

x53, y53 = load_cap(TEST_CAPS['53'])
xn = np.clip((x53-q25)/iqr,-10,10)

xt = torch.FloatTensor(xn)
with torch.no_grad():
    raw_scores = torch.softmax(model(xt), dim=1)[:,1].numpy()

# Apply rules manually
IDX_DIR_ASYM=10; IDX_BYTES=2
is_sustained = xn[:,IDX_SUSTAINED]>0.5
is_very_eph = xn[:,IDX_VERY_EPH]>0.5
is_no_resp = xn[:,IDX_NO_RESP]>0.5
has_pkts_gt4 = xn[:,IDX_PKTS]>0.603
has_dir_asym = xn[:,IDX_DIR_ASYM]>-0.25
is_small_bytes = xn[:,IDX_BYTES]<-0.5

r1c_mask = is_sustained & (has_pkts_gt4 | is_no_resp) & has_dir_asym
r2_mask = is_very_eph & is_no_resp & is_small_bytes

y = y53
r1c_tp = (y==1)[r1c_mask].sum(); r1c_fp = (y==0)[r1c_mask].sum()
r2_tp = (y==1)[r2_mask].sum(); r2_fp = (y==0)[r2_mask].sum()
rule_tp = (y==1)[r1c_mask|r2_mask].sum(); rule_fp = (y==0)[r1c_mask|r2_mask].sum()

print(f'R1c: TP={r1c_tp} FP={r1c_fp}')
print(f'R2:  TP={r2_tp} FP={r2_fp}')
print(f'All rules: TP={rule_tp} FP={rule_fp} out of {(y==1).sum()} attacks')

# Scores after rule override
scores = raw_scores.copy()
scores[r1c_mask|r2_mask] = 1.0

# Check: at thr=0.90, how many TP?
tp_90 = int(((y==1)&(scores>=0.90)).sum())
fp_90 = int(((y==0)&(scores>=0.90)).sum())
print(f'\nthr=0.90: TP={tp_90} FP={fp_90} recall={tp_90/(y==1).sum():.4f}')

# Of rule-covered TPs, do they all get score=1.0?
rule_att = (y==1)&(r1c_mask|r2_mask)
rule_att_scores = scores[rule_att]
print(f'Rule-covered attack scores: min={rule_att_scores.min():.3f} max={rule_att_scores.max():.3f}')
print(f'Rule-covered attacks with score>=0.90: {(rule_att_scores>=0.90).sum()}/{rule_att.sum()}')

# MLP-only TPs (not covered by rules)
no_rule_att = (y==1) & ~(r1c_mask|r2_mask)
no_rule_att_mlp = scores[no_rule_att]
print(f'\nMLP-only attacks (not rule covered): {no_rule_att.sum()}')
print(f'MLP-only scores: p50={np.median(no_rule_att_mlp):.3f} p75={np.percentile(no_rule_att_mlp,75):.3f} p90={np.percentile(no_rule_att_mlp,90):.3f} >0.80={(no_rule_att_mlp>0.80).mean():.1%} >0.90={(no_rule_att_mlp>0.90).mean():.1%}')

# Check raw_scores on rule-covered attacks (before override)
rule_att_raw = raw_scores[rule_att]
print(f'\nRaw MLP scores on rule-covered attacks: p10={np.percentile(rule_att_raw,10):.3f} p50={np.median(rule_att_raw):.3f}')
