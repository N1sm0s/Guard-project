"""Expanded real-capture experiment: train on CTU-13 groups except capture 45.

Captures are held out as whole groups. Capture 45 alone selects the threshold.
The script excludes Background/To-Background, and never opens its independent
external evaluation source. Research output cannot be promoted automatically.
"""
from __future__ import annotations
import csv, hashlib, json, random, sys, time
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.train_v9 import MLP, load_capture, score_curve, sha256_file

DATA = ROOT / "outputs" / "network-eval"
OUT = DATA / "train-ctu13-expanded-groups"
ALL = {
    "42": DATA / "ctu-42.binetflow",
    "43": DATA / "ctu-43.binetflow",
    "44": DATA / "official-ctu13" / "capture20110812_ctu44.binetflow",
    "46": DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow",
    "47": DATA / "official-ctu13" / "capture20110816_ctu47.binetflow",
    "48": DATA / "official-ctu13" / "capture20110816-2_ctu48.binetflow",
    "49": DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow",
    "50": DATA / "official-ctu13" / "capture20110817_ctu50.binetflow",
    "51": DATA / "official-ctu13" / "capture20110818_ctu51.binetflow",
    "52": DATA / "official-ctu13" / "capture20110818-2_ctu52.binetflow",
    "53": DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54": DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}
VALIDATION = {"45": DATA / "official-ctu13" / "capture20110815_ctu45.binetflow"}
SEED, EPOCHS, PATIENCE, BATCH, FPR_CEILING = 9142, 80, 10, 4096, 0.001


def main():
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
    if torch.cuda.is_available(): torch.cuda.manual_seed_all(SEED)
    started = time.time(); OUT.mkdir(parents=True, exist_ok=True)
    xs, ys, source_hashes, counts = [], [], {}, {}
    for cid, path in ALL.items():
        x, y, _udp, excluded = load_capture(cid, path)
        xs.append(x); ys.append(y); source_hashes[cid] = sha256_file(path)
        counts[cid] = {"attack": int((y==1).sum()), "benign": int((y==0).sum()),
                       "unknown_or_invalid_excluded": int(excluded)}
        print(f"train {cid}: attack={(y==1).sum()} benign={(y==0).sum()} excluded={excluded}", flush=True)
    raw_train, y_train = np.concatenate(xs), np.concatenate(ys)
    val_xs, val_ys, val_hashes, val_counts = [], [], {}, {}
    for cid, path in VALIDATION.items():
        x, y, _udp, excluded = load_capture(cid, path)
        val_xs.append(x); val_ys.append(y); val_hashes[cid] = sha256_file(path)
        val_counts[cid] = {"attack": int((y==1).sum()), "benign": int((y==0).sum()),
                           "unknown_or_invalid_excluded": int(excluded)}
    raw_val, y_val = np.concatenate(val_xs), np.concatenate(val_ys)

    # Normalize from training captures only.
    center = np.median(raw_train, axis=0)
    q25, q75 = np.percentile(raw_train, [25, 75], axis=0)
    scale = np.maximum(q75-q25, 1e-6)
    x_train = np.clip((raw_train-center)/scale, -10, 10).astype(np.float32)
    x_val = np.clip((raw_val-center)/scale, -10, 10).astype(np.float32)
    counts_class = np.bincount(y_train, minlength=2).astype(np.float64)
    class_weights = len(y_train)/(2*np.maximum(counts_class,1))
    sample_weights = class_weights[y_train]
    sample_weights /= sample_weights.mean()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = MLP(raw_train.shape[1]).to(device)
    dataset = TensorDataset(torch.from_numpy(x_train), torch.from_numpy(y_train),
                            torch.from_numpy(sample_weights.astype(np.float32)))
    loader = DataLoader(dataset, batch_size=BATCH, shuffle=True, num_workers=0,
                        generator=torch.Generator().manual_seed(SEED),
                        pin_memory=device.type=="cuda")
    xv, yv = torch.from_numpy(x_val).to(device), torch.from_numpy(y_val).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=3e-4, weight_decay=1e-4)
    loss_fn = nn.CrossEntropyLoss(reduction="none")
    best, stale, best_epoch, best_state = float("inf"), 0, 0, None
    for epoch in range(1, EPOCHS+1):
        model.train()
        for bx, by, bw in loader:
            bx, by, bw = bx.to(device), by.to(device), bw.to(device)
            opt.zero_grad(set_to_none=True)
            loss = (loss_fn(model(bx), by)*bw).mean()
            loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(),5.0); opt.step()
        model.eval()
        with torch.no_grad(): val_loss=float(loss_fn(model(xv),yv).mean().item())
        if val_loss < best-1e-5:
            best, best_epoch, stale = val_loss, epoch, 0
            best_state={k:v.detach().cpu().clone() for k,v in model.state_dict().items()}
        else: stale += 1
        if epoch==1 or epoch%10==0:
            print(f"epoch={epoch} weighted_loss={loss.item():.5f} val_nll={val_loss:.5f} best={best:.5f}@{best_epoch}",flush=True)
        if stale >= PATIENCE: break
    model.load_state_dict(best_state); model.eval()
    with torch.no_grad():
        probs=torch.softmax(model(torch.from_numpy(x_val).to(device)),dim=1)[:,1].cpu().numpy()
    t,r,f,fh,tp,fp=score_curve(probs,y_val)
    allowed=np.flatnonzero(fh<=FPR_CEILING)
    idx=int(allowed[np.argmax(r[allowed])]) if len(allowed) else None
    point=None if idx is None else {"threshold":float(t[idx]),"recall":float(r[idx]),"fpr":float(f[idx]),
        "fpr_ci95_upper":float(fh[idx]),"tp":int(tp[idx]),"fp":int(fp[idx]),
        "fn":int((y_val==1).sum()-tp[idx]),"tn":int((y_val==0).sum()-fp[idx])}
    checkpoint=OUT/"expanded_class_balanced.pt"
    torch.save({"state_dict":best_state,"mean":center.tolist(),"scale":scale.tolist(),
        "feature_names":list(__import__('integrityguard.network_flow_schema',fromlist=['FEATURE_NAMES']).FEATURE_NAMES),
        "feature_version":__import__('integrityguard.network_flow_schema',fromlist=['FEATURE_VERSION']).FEATURE_VERSION,
        "classes":["benign","attack"],"training_captures":list(ALL),"validation_capture":"45",
        "class_counts":{"benign":int(counts_class[0]),"attack":int(counts_class[1])},
        "threshold_selected_on_validation":point["threshold"] if point else None,
        "research_only":True,"promotion_eligible":False},checkpoint)
    curve_file=OUT/"validation_curve.csv"
    with curve_file.open("w",newline="",encoding="utf-8") as fcsv:
        w=csv.writer(fcsv); w.writerow(["threshold","recall","fpr","fpr_ci95_upper","tp","fp","fn","tn"])
        for i in range(len(t)):
            w.writerow([float(t[i]),float(r[i]),float(f[i]),float(fh[i]),int(tp[i]),int(fp[i]),
                        int((y_val==1).sum()-tp[i]),int((y_val==0).sum()-fp[i])])
    manifest={"created_at_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
        "train_captures":list(ALL),"validation_capture":"45","independent_test":"not loaded",
        "label_policy":"From-Botnet=attack; From-Normal=benign; all other/background excluded",
        "train_sha256":source_hashes,"validation_sha256":val_hashes,"counts":{"train":counts,"validation":val_counts},
        "best_epoch":best_epoch,"validation_nll":best,"validation_operating_point":point,
        "checkpoint_sha256":sha256_file(checkpoint),"checkpoint":checkpoint.name,
        "elapsed_seconds":round(time.time()-started,2),"promotion_eligible":False}
    (OUT/"validation_summary.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
    print("selected validation point:",point)
    print("wrote",OUT,"; independent test was not opened; candidate not promotion eligible")


if __name__=="__main__": main()
