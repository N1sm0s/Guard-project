"""Count how many events verified_snapshot_labels actually returns, with timing."""
import sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from integrityguard.network_evidence import NetworkEventLog
from integrityguard.network_label_reviews import NetworkLabelReviews

ev = NetworkEventLog(ROOT / "data/online/network_events.sqlite")
rv = NetworkLabelReviews(ROOT / "data/online/network_label_reviews.sqlite")

t0 = time.perf_counter()
all_ev = ev.all_events()
print(f"all_events: {len(all_ev)} in {time.perf_counter()-t0:.2f}s")

t1 = time.perf_counter()
labeled = rv.verified_snapshot_labels(ev)
print(f"verified_snapshot_labels: {len(labeled)} in {time.perf_counter()-t1:.2f}s")

if labeled:
    from collections import Counter
    print("label distribution:", Counter(x["label"] for x in labeled))
