"""Small, dependency-free statistics used by the network model release gate."""
from __future__ import annotations

import math
import re
from datetime import datetime

_Z_95 = 1.959963984540054
MIN_RELEASE_ATTACK_SUPPORT = 100
# Prospective release limit: the two-sided 95% Wilson upper FPR bound.
RELEASE_FPR_CI_CEILING = 0.0025
# At zero false positives, n=1,533 is the first benign support where the
# two-sided 95% Wilson upper bound is <=0.25%. Any FP still has to pass the
# separately computed Wilson bound and may require a larger n.
MIN_BENIGN_SUPPORT_ZERO_FP = 1533


def wilson_interval(successes: int, total: int, z: float = _Z_95) -> tuple[float, float] | None:
    """Return a two-sided Wilson score interval, or None for invalid counts."""
    if (isinstance(successes, bool) or isinstance(total, bool)
            or not isinstance(successes, int) or not isinstance(total, int)
            or total <= 0 or successes < 0 or successes > total
            or not isinstance(z, (int, float)) or not math.isfinite(float(z)) or z <= 0):
        return None
    proportion = successes / total
    z2 = float(z) ** 2
    denominator = 1.0 + z2 / total
    center = (proportion + z2 / (2.0 * total)) / denominator
    radius = (float(z) * math.sqrt(
        proportion * (1.0 - proportion) / total + z2 / (4.0 * total * total)
    ) / denominator)
    return max(0.0, center - radius), min(1.0, center + radius)


def confusion_metrics(counts: dict) -> dict | None:
    """Recompute recall/FPR and their CIs from raw integer confusion counts."""
    if not isinstance(counts, dict):
        return None
    names = ("tp_attack", "fp_benign", "fn_attack", "tn_benign")
    values = [counts.get(name) for name in names]
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0
           for value in values):
        return None
    tp, fp, fn, tn = values
    n_attack, n_benign = tp + fn, fp + tn
    recall_ci = wilson_interval(tp, n_attack)
    fpr_ci = wilson_interval(fp, n_benign)
    if recall_ci is None or fpr_ci is None:
        return None
    return {
        "n_attack": n_attack,
        "n_benign": n_benign,
        "attack_recall": tp / n_attack,
        "attack_recall_ci95_wilson": list(recall_ci),
        "benign_false_positive_rate": fp / n_benign,
        "benign_false_positive_rate_ci95_wilson": list(fpr_ci),
    }


def hash_locked_target_evaluation(record: dict, checkpoint_sha256: str | None) -> bool:
    """Require immutable capture/label manifests scored against this checkpoint."""
    if not isinstance(record, dict) or record.get("completed") is not True:
        return False
    expected_hashes = {
        "capture_sha256": record.get("capture_sha256"),
        "labels_manifest_sha256": record.get("labels_manifest_sha256"),
        "checkpoint_sha256": record.get("checkpoint_sha256"),
    }
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value)
           for value in expected_hashes.values()):
        return False
    if not checkpoint_sha256 or expected_hashes["checkpoint_sha256"].lower() != checkpoint_sha256.lower():
        return False
    try:
        locked_at = datetime.fromisoformat(str(record["locked_at_utc"]).replace("Z", "+00:00"))
        scored_at = datetime.fromisoformat(str(record["scored_at_utc"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return False
    if locked_at.tzinfo is None or scored_at.tzinfo is None or locked_at > scored_at:
        return False
    return bool(str(record.get("label_source") or "").strip())
