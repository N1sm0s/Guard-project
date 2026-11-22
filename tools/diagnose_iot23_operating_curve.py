"""Diagnostic ROC/PR support on IoT-23 rows with complete feature fields.

IoT-23 has already been used for development, so this output is not a final
independent test or release evidence. The purpose is to distinguish threshold
calibration from ranking/domain-shift failure.
"""
from __future__ import annotations
import json, sys
from pathlib import Path
import numpy as np
import torch
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, FEATURE_VERSION, feature_vector
from tools.train_v9 import MLP, score_curve

DATA = ROOT / "outputs" / "network-eval" / "official-iot23v2"
DIR = ROOT / "outputs" / "network-eval" / "train-ctu13-expanded-groups"
FILES = [
    ("malware_34_1", DATA / "ctu-iot-malware-34-1-zeek-conn.log.labeled", False),
    ("clean_4_1", DATA / "ctu-honeypot-4-1-zeek-conn.log.labeled", True),
    ("clean_5_1", DATA / "ctu-honeypot-5-1-zeek-conn.log.labeled", True),
    ("clean_7_2", DATA / "ctu-honeypot-7-2-zeek-conn.log.labeled", True),
    ("clean_7_3", DATA / "ctu-honeypot-7-3-zeek-conn.log.labeled", True),
    ("clean_7_4", DATA / "ctu-honeypot-7-4-zeek-conn.log.labeled", True),
]


def parse(line):
    c=line.rstrip("\r\n").split("\t")
    if len(c)<21: raise ValueError
    tail=c[-1].strip().split(); label=tail[-2].lower() if len(tail)>=3 else ""
    x=feature_vector(c[8],float(c[16])+float(c[18]),float(c[17])+float(c[19]),c[17],c[19],c[6])
    return label,x


def main():
    ckpt=torch.load(DIR/"expanded_class_balanced.pt",map_location="cpu",weights_only=True)
    model=MLP(len(FEATURE_NAMES)); model.load_state_dict(ckpt["state_dict"]); model.eval()
    mean=np.asarray(ckpt["mean"],np.float32); scale=np.asarray(ckpt["scale"],np.float32)
    ys=[]; xs=[]; excluded={}
    for name,path,clean in FILES:
        yc=[]; xc=[]; nbad=0
        for line in path.open(encoding="utf-8",errors="replace"):
            if not line or line.startswith("#"): continue
            try: label,x=parse(line)
            except (ValueError,TypeError,IndexError): nbad+=1; continue
            if label=="malicious": target=1
            elif label=="benign" or (clean and label==""): target=0
            else: continue
            yc.append(target); xc.append(x)
        ys.extend(yc); xs.extend(xc); excluded[name]=nbad
    y=np.asarray(ys,np.int64); x=np.clip((np.asarray(xs,np.float32)-mean)/scale,-10,10).astype(np.float32)
    with torch.no_grad(): score=torch.softmax(model(torch.from_numpy(x)),dim=1)[:,1].numpy().astype(np.float64)
    thresholds,recall,fpr,fpr_hi,tp,fp=score_curve(score,y)
    ix=np.flatnonzero(fpr_hi<=0.001)
    best=None
    if len(ix):
        j=int(ix[np.argmax(recall[ix])]); best={"threshold":float(thresholds[j]),"recall":float(recall[j]),
            "fpr":float(fpr[j]),"fpr_ci95_upper":float(fpr_hi[j]),"tp":int(tp[j]),"fp":int(fp[j])}
    output={"data_status":"development diagnostic; IoT-23 is not a pristine final holdout",
        "rows_scored":len(y),"attack":int((y==1).sum()),"benign":int((y==0).sum()),
        "rows_excluded_for_missing_or_invalid_required_fields":excluded,
        "roc_auc":float(roc_auc_score(y,score)),"average_precision":float(average_precision_score(y,score)),
        "validation_fixed_threshold":float(ckpt["threshold_selected_on_validation"]),
        "fixed_threshold_metrics":{
          "recall":float(recall[np.argmin(abs(thresholds-ckpt["threshold_selected_on_validation"]))]),
          "fpr":float(fpr[np.argmin(abs(thresholds-ckpt["threshold_selected_on_validation"]))])},
        "best_operating_point_diagnostic_only_at_wilson_fpr_upper_le_0_1_percent":best,
        "warning":"Do not use diagnostic-selected threshold for release. No complete-field coverage claim; do not count missing rows as safe."}
    out=DIR/"iot23_operating_curve_diagnostic.json"
    out.write_text(json.dumps(output,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(output,ensure_ascii=False,indent=2))


if __name__=="__main__": main()
