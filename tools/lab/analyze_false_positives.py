"""Diagnostic: which benign check flows does the v11 full model flag, and what do they look like?
Trains on the lab attack families and training background (as in the v11 cross-family setup, all families),
threshold from calibration background. Reports feature means for flagged benign, unflagged benign, and attacks.
Research-only; uses already-collected shards only; no new data and no threshold change."""
import json, sys
from pathlib import Path
import numpy as np
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]
import loco_ctu13_diagnostic as loco
from integrityguard import network_flow_schema_v11 as v11
S = ROOT / "outputs" / "lab" / "shards_v11"
ATT = ["v11-udp-03", "v11-flood-02", "v11-flood-03", "v11-scan-01", "v11-scan-02", "v11-scan-03", "v11-scan-04", "v11-ssh-01", "v11-ssh-02"]
TRAIN_BG = ["v11-benign-06", "v11-benign-07", "v11-benign-09"]
CAL = ["v11-benign-10", "v11-benign-11"]
CHECK = ["v11-benign-08", "v11-benign-12"]
def load(s):
    with np.load(S / f"{s}.npz") as d: return d["x"], d["y"].astype(np.int64)
xs, ys = zip(*[load(s) for s in ATT + TRAIN_BG])
x_tr, y_tr = np.concatenate(xs), np.concatenate(ys)
model, median, scale = loco.train_model(x_tr, y_tr, epochs=20, device="cpu")
x_cal = np.concatenate([load(s)[0] for s in CAL])
thr = float(np.quantile(loco.score(model, median, scale, x_cal, "cpu"), 1 - 0.0025))
xc, yc = zip(*[load(s) for s in CHECK]); x_chk = np.concatenate(xc)
s_chk = loco.score(model, median, scale, x_chk, "cpu")
flag = s_chk >= thr
names = list(v11.FEATURE_NAMES)
def means(mask): return {n: round(float(x_chk[mask, i].mean()), 3) for i, n in enumerate(names)} if mask.any() else {}
xa = np.concatenate([load(s)[0] for s in ATT]); s_att = loco.score(model, median, scale, xa, "cpu")
ba = {n: round(float(xa[:, i].mean()), 3) for i, n in enumerate(names)}
report = {"threshold": thr, "check_flows": int(len(flag)), "flagged": int(flag.sum()),
          "flagged_by_shard": {s: int(((s_chk >= thr)[np.concatenate([np.full(len(load(s)[0]), k) for k, s in enumerate(CHECK)]) == k]).sum()) for k, s in enumerate(CHECK)},
          "feature_mean_flagged_benign": means(flag), "feature_mean_unflagged_benign": means(~flag),
          "feature_mean_attacks": ba,
          "attack_flows_above_threshold_share": float((s_att >= thr).mean())}
(ROOT / "outputs" / "lab" / "fp-analysis-v11.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
print("threshold", round(thr, 4), "flagged", report["flagged"], "of", report["check_flows"], report["flagged_by_shard"])
key = ["protocol_tcp", "protocol_udp", "protocol_icmp", "duration_log1p", "total_packets_log1p", "total_bytes_log1p", "direction_asym", "originator_flows_10s_log1p", "originator_unique_dest_ports_10s_log1p", "originator_failed_ratio_10s"]
for k in key:
    print(f"{k:42s} flagged={report['feature_mean_flagged_benign'].get(k)}  unflagged={report['feature_mean_unflagged_benign'].get(k)}  attacks={report['feature_mean_attacks'].get(k)}")
