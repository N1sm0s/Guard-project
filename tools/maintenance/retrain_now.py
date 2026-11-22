"""Retrain the shadow classifier from independently verified network labels.

Historical language-model outputs are not training targets. Run by the scheduled task
"IntegrityGuard NN Retrain"; every attempt appends one JSON line to retrain.log.

The append-only reviewer-ledger cursor prevents new telemetry samples from
triggering repeated scans when no labels have changed.
"""
import json
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from integrityguard.network_classifier import (FEATURE_VERSION, LABEL_SOURCE,
                                               load_checkpoint)  # noqa: E402
from integrityguard.network_classifier_train import train  # noqa: E402
from integrityguard.network_evidence import NetworkEventLog  # noqa: E402
from integrityguard.network_label_reviews import NetworkLabelReviews  # noqa: E402

EVENTS = ROOT / "data" / "online" / "network_events.sqlite"
REVIEWS = EVENTS.with_name("network_label_reviews.sqlite")
CHECKPOINT = ROOT / "data" / "models" / "network_classifier.pt"
LOG = ROOT / "data" / "models" / "retrain.log"
STATE = ROOT / "data" / "models" / "retrain_state.json"


def _latest_review_id() -> int:
    """Read the append-only reviewer ledger cursor without scanning its rows."""
    if not REVIEWS.exists():
        return 0
    uri = f"file:{REVIEWS.as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5) as db:
        row = db.execute("SELECT COALESCE(MAX(id), 0) FROM reviews").fetchone()
    return int(row[0] or 0)


def _load_state() -> dict:
    try:
        value = json.loads(STATE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(review_id: int, outcome: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE.with_suffix(".tmp")
    temporary.write_text(json.dumps({
        "latest_review_id": review_id,
        "label_source": LABEL_SOURCE,
        "feature_version": FEATURE_VERSION,
        "last_outcome": "trained" if not outcome.get("skipped") else "skipped",
        "updated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(STATE)


def main() -> int:
    started = time.perf_counter()
    record = {"at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    force = "--force" in sys.argv
    try:
        if not EVENTS.exists():
            record.update(skipped=True, reason="no_events_db")
        else:
            # New telemetry does not make new training labels. Track the review
            # ledger's append-only primary-key cursor so periodic captures do not
            # repeatedly rescan/retrain against the same unresolved labels.
            latest_review_id = _latest_review_id()
            state = _load_state()
            checkpoint = load_checkpoint(CHECKPOINT)
            same_training_contract = (
                state.get("label_source") == LABEL_SOURCE
                and state.get("feature_version") == FEATURE_VERSION
            )
            retry_missing_checkpoint = (state.get("last_outcome") == "trained"
                                        and checkpoint is None)
            no_new_reviews = (same_training_contract
                              and latest_review_id <= int(state.get("latest_review_id", 0))
                              and not retry_missing_checkpoint)

            if no_new_reviews and not force:
                record.update(skipped=True, reason="no_new_reviewer_records",
                              latest_review_id=latest_review_id,
                              n_samples=checkpoint.get("n_samples", 0) if checkpoint else 0)
            else:
                event_log = NetworkEventLog(EVENTS)
                review_log = NetworkLabelReviews(REVIEWS)
                outcome = train(event_log, CHECKPOINT, reviews=review_log)
                outcome.setdefault("latest_review_id", latest_review_id)
                record.update(outcome)
                _save_state(latest_review_id, outcome)
        code = 0
    except Exception as error:  # noqa: BLE001 — a scheduled run must log, not vanish
        record.update(failed=True, error=f"{type(error).__name__}: {error}")
        code = 1
    record["seconds"] = round(time.perf_counter() - started, 2)
    line = json.dumps(record, ensure_ascii=False)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    print(line)
    return code


if __name__ == "__main__":
    sys.exit(main())
