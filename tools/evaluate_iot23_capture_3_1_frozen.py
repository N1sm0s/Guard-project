"""One-shot external source test for the frozen expanded CTU candidate.

This script must not be used to tune model weights or thresholds. It scores one
new publisher-labeled IoT-23 v2 capture at the threshold frozen on CTU-45.
Incomplete feature rows remain excluded and are reported, never treated benign.
"""
from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from pathlib import Path
import sys
import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrityguard.network_flow_schema import FEATURE_NAMES, FEATURE_VERSION, feature_vector
from tools.train_v9 import MLP

DATA = ROOT / "outputs" / "network-eval" / "official-iot23v2"
CAPTURE = DATA / "ctu-iot-malware-3-1-zeek-conn.log.labeled"
MODEL = ROOT / "outputs" / "network-eval" / "train-ctu13-expanded-groups" / "expanded_class_balanced.pt"
METRICS = ROOT / "outputs" / "network-eval" / "train-ctu13-expanded-groups" / "iot23_capture_3_1_independent_test.json"
SOURCE_URL = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/"


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()


def wilson(success,total,z=1.959963984540054):
    if total<=0:return None
    p=success/total; d=1+z*z/total; c=p+z*z/(2*total)
    m=z*((p*(1-p)+z*z/(4*total))/total)**0.5
    return [max(0,(c-m)/d),min(1,(c+m)/d)]


def main():
    if METRICS.exists(): raise FileExistsError(f"Refusing to overwrite one-shot test evidence: {METRICS}")
    if not CAPTURE.is_file() or not MODEL.is_file(): raise FileNotFoundError("Capture or frozen checkpoint missing")
    frozen=datetime.now(timezone.utc).isoformat()
    capture_hash,model_hash=sha256(CAPTURE),sha256(MODEL)
    ckpt=torch.load(MODEL,map_location="cpu",weights_only=True)
    if ckpt.get("feature_version")!=FEATURE_VERSION or ckpt.get("feature_names")!=list(FEATURE_NAMES):
        raise RuntimeError("Checkpoint/feature schema mismatch")
    model=MLP(len(FEATURE_NAMES)); model.load_state_dict(ckpt["state_dict"]); model.eval()
    threshold=float(ckpt["threshold_selected_on_validation"])
    mean=np.asarray(ckpt["mean"],np.float32); scale=np.asarray(ckpt["scale"],np.float32)
    vectors=[]; labels=[]
    counts={"malicious":0,"benign":0,"unknown_excluded":0,"incomplete_excluded":0}
    for line in CAPTURE.open("r",encoding="utf-8",errors="replace"):
        if not line or line.startswith("#"):continue
        try:
            c=line.rstrip("\r\n").split("\t")
            if len(c)<21:raise ValueError("short row")
            tail=c[-1].strip().split(); label=tail[-2].lower() if len(tail)>=3 else ""
            x=feature_vector(c[8],float(c[16])+float(c[18]),float(c[17])+float(c[19]),
                             c[17],c[19],c[6])
        except (ValueError,TypeError,IndexError):
            counts["incomplete_excluded"]+=1;continue
        if label=="malicious":target=1;counts["malicious"]+=1
        elif label=="benign":target=0;counts["benign"]+=1
        else:counts["unknown_excluded"]+=1;continue
        vectors.append(x);labels.append(target)
    if not labels:raise RuntimeError("No complete, publisher-labeled flows to score")
    x=np.clip((np.asarray(vectors,np.float32)-mean)/scale,-10,10).astype(np.float32)
    with torch.no_grad():scores=torch.softmax(model(torch.from_numpy(x)),dim=1)[:,1].numpy()
    y=np.asarray(labels,np.int64); pred=scores>=threshold
    tp=int(((y==1)&pred).sum());fn=int(((y==1)&~pred).sum())
    fp=int(((y==0)&pred).sum());tn=int(((y==0)&~pred).sum())
    rc=wilson(tp,tp+fn);fc=wilson(fp,fp+tn)
    enough=counts["malicious"]>=100 and counts["benign"]>=3838
    gate=bool(enough and rc and fc and rc[0]>=0.80 and fc[1]<=0.001)
    result={"frozen_before_scoring_at_utc":frozen,"scored_at_utc":datetime.now(timezone.utc).isoformat(),
        "capture":"CTU-IoT-Malware-Capture-3-1","source_url":SOURCE_URL,
        "source_labels":"publisher Zeek labels; only Malicious/Benign included",
        "capture_sha256":capture_hash,"checkpoint_sha256":model_hash,
        "checkpoint":"expanded_class_balanced.pt","threshold":threshold,
        "counts":counts,"tp":tp,"fp":fp,"fn":fn,"tn":tn,
        "attack_recall":tp/(tp+fn) if tp+fn else None,"attack_recall_ci95_wilson":rc,
        "benign_fpr":fp/(fp+tn) if fp+tn else None,"benign_fpr_ci95_wilson":fc,
        "sample_size_gate_satisfied":enough,"per_capture_gate_pass":gate,
        "promotion_eligible":False,
        "note":"One independent source capture only. Passing this capture would not satisfy all release or target-network gates."}
    METRICS.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=="__main__":main()
