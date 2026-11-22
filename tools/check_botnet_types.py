"""Quick check of botnet label types in each capture to understand generalization failure."""
import csv
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "outputs" / "network-eval"

captures = {
    "42-train": DATA / "ctu-42.binetflow",
    "43-train": DATA / "ctu-43.binetflow",
    "44-train": DATA / "official-ctu13" / "capture20110812_ctu44.binetflow",
    "46-train": DATA / "official-ctu13" / "capture20110815-2_ctu46.binetflow",
    "47-train": DATA / "official-ctu13" / "capture20110816_ctu47.binetflow",
    "48-train": DATA / "official-ctu13" / "capture20110816-2_ctu48.binetflow",
    "51-train": DATA / "official-ctu13" / "capture20110818_ctu51.binetflow",
    "52-train": DATA / "official-ctu13" / "capture20110818-2_ctu52.binetflow",
    "49-val":   DATA / "official-ctu13" / "capture20110816-3_ctu49.binetflow",
    "53-test":  DATA / "official-ctu13" / "capture20110819_ctu53.binetflow",
    "54-test":  DATA / "official-ctu13" / "capture20110815-3_ctu54.binetflow",
}

for name, path in captures.items():
    botnet_labels = Counter()
    n = 0
    try:
        with path.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                lbl = row.get("Label", "")
                if "From-Botnet-" in lbl:
                    # Extract botnet family name
                    parts = lbl.split("-")
                    # flow=From-Botnet-FAMILYNAME-...
                    if len(parts) > 3:
                        family = parts[3][:20]
                    else:
                        family = lbl[:30]
                    botnet_labels[family] += 1
                n += 1
    except Exception as e:
        print(f"  {name}: ERROR {e}")
        continue
    total_attack = sum(botnet_labels.values())
    print(f"  {name}: {n:,} rows, {total_attack:,} attack flows")
    for fam, cnt in botnet_labels.most_common(5):
        print(f"    botnet family={fam!r}: {cnt:,}")
    if total_attack == 0:
        print(f"    (no attack flows found)")
