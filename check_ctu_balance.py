import csv
from pathlib import Path
from collections import Counter

data = Path('outputs/network-eval/official-ctu13')
for f in sorted(data.glob('*.binetflow')):
    counts = Counter()
    with f.open(encoding='utf-8', newline='') as fh:
        for row in csv.DictReader(fh):
            lbl = row.get('Label', '')
            if lbl.startswith('flow=From-Botnet-'):
                counts['attack'] += 1
            elif lbl.startswith('flow=From-Normal-'):
                counts['benign'] += 1
            else:
                counts['unknown'] += 1
    total = counts['attack'] + counts['benign']
    ratio = counts['attack'] / total if total else 0
    print(f"{f.name:50s} attack={counts['attack']:7d}  benign={counts['benign']:7d}  ratio={ratio:.3f}")
