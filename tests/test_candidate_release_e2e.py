"""Real, non-mocked end-to-end test of the candidate-release lifecycle.

Every existing test for this pipeline (test_online_candidate.py, test_release.py,
test_candidate_eval.py) monkeypatches load_detector / finetune_binary /
evaluate_candidate -- none of them exercises the real model, the real
fine-tuning code and the real feature-extraction pipeline together, through
the full chain. This test closes that gap.

It uses:
  - the project's own real, already-trained detector (models/detector.pt,
    the same fixture test_unbaselined.py uses) as the active model;
  - the project's own real corpus/feature-extraction code (corpus.gen_project)
    to build both the human-audit "confirmed" training buffer and the
    independent evaluation holdout, with real graph/weight/behavioral
    features (not synthetic placeholders);
  - the real online_learn.build_candidate, candidate_eval.evaluate_candidate,
    release.promote_candidate and release.rollback_candidate, unmodified.

Runtime: roughly 1-2 minutes (MIN_CLEAN + MIN_ATTACK synthetic projects are
generated through the real pipeline to satisfy the statistical release gate's
minimum sample counts).

The release gate's eligibility is a statistical outcome of this specific
random draw, not something this test dictates; if the candidate does not
clear it, the test still asserts that build_candidate and evaluate_candidate
ran correctly and honestly, and skips only the promote/rollback assertions.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
import torch

from integrityguard import corpus, online_learn, release
from integrityguard.candidate_eval import MIN_ATTACK, MIN_CLEAN, evaluate_candidate
from integrityguard.spec import LEVELS

MODEL = Path(__file__).resolve().parents[1] / "models" / "detector.pt"


def _real_feature_sample(pid: int, class_name: str) -> dict:
    """A sample whose x/adj/layers/behav tensors come from the real corpus +
    feature-extraction pipeline (integrityguard.corpus.gen_project), the same
    code path used to build the original training corpus."""
    generated = corpus.gen_project(pid, with_specs=True, class_name=class_name)
    assert generated is not None, f"corpus generation failed for pid={pid} class={class_name}"
    samples, _project = generated
    return samples[0]


def _confirmed_sample(pid: int, class_name: str, event_id: str) -> dict:
    s = _real_feature_sample(pid, class_name)
    return {"x": s["x"], "adj": s["adj"], "layers": s["layers"], "behav": s["behav"],
            "bin_y": float(class_name != "clean"), "_event_id": event_id,
            "_fingerprint": "train-sha-" + event_id, "_model_sha256": "",
            "_label_source": "human_audit"}


def _holdout_sample(pid: int, class_name: str, event_id: str) -> dict:
    s = _real_feature_sample(pid, class_name)
    # model.collate() requires "levels" whenever "y" is present (its multiclass
    # branch). The binary release-gate evaluation never reads this field (only
    # "logits" is consumed), so a zero placeholder of the right shape is enough.
    return {"x": s["x"], "adj": s["adj"], "layers": s["layers"], "behav": s["behav"],
            "y": int(class_name != "clean"), "levels": torch.zeros(len(LEVELS)),
            "_event_id": event_id, "_fingerprint": "hold-sha-" + event_id,
            "_project_id": f"e2e-project-{pid}",
            "_label_evidence": "independently reviewed end-to-end test fixture"}


@pytest.mark.skipif(not MODEL.is_file(), reason="repo's trained detector fixture (models/detector.pt) is missing")
def test_full_candidate_release_lifecycle_with_real_model_and_features(tmp_path):
    data_root = tmp_path / "data"
    (data_root / "online").mkdir(parents=True)

    # --- 1. Real active detector: the project's own trained model, isolated into a scratch copy.
    active_model = data_root / "runs" / "detector.pt"
    active_model.parent.mkdir(parents=True)
    shutil.copyfile(MODEL, active_model)
    active_before = hashlib.sha256(active_model.read_bytes()).hexdigest()

    # --- 2. Real human-audit "confirmed" feedback buffer (binary; real extracted features).
    confirmed = [_confirmed_sample(1000 + i, "clean", f"train-clean-{i}") for i in range(10)]
    confirmed += [_confirmed_sample(2000 + i, "weights", f"train-attack-{i}") for i in range(10)]
    torch.save(confirmed, data_root / "online" / "confirmed.pt")

    readiness = online_learn.candidate_readiness(data_root)
    assert readiness["ready"] is True
    assert readiness["benign_count"] == 10 and readiness["attack_count"] == 10

    # --- 3. build_candidate(): real fine-tuning of the real model on the real buffer.
    candidate = online_learn.build_candidate(data_root, active_model)
    assert candidate is not None
    assert candidate["status"] == "awaiting_independent_evaluation"
    assert candidate["promotion_allowed"] is False
    candidate_id = candidate["candidate_id"]
    candidate_artifact = data_root / "models" / "candidates" / candidate_id / "detector.pt"
    assert candidate_artifact.is_file()
    # build_candidate must never touch the active model.
    assert hashlib.sha256(active_model.read_bytes()).hexdigest() == active_before == candidate["parent_model_sha256"]

    # --- 4. Real independent holdout, disjoint event ids/fingerprints from the training buffer.
    holdout = [_holdout_sample(10_000 + i, "clean", f"hold-clean-{i}") for i in range(MIN_CLEAN)]
    holdout += [_holdout_sample(20_000 + i, "weights", f"hold-attack-{i}") for i in range(MIN_ATTACK)]
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    samples_path = eval_dir / "samples.pt"
    torch.save(holdout, samples_path)
    manifest = {"format": "integrityguard-independent-evaluation-v1", "data_kind": "real",
                "independent": True, "candidate_id": candidate_id, "reviewer": "e2e pytest reviewer",
                "collected_at": "2026-11-11T00:00:00+00:00",
                "source_refs": ["https://example.invalid/e2e-pytest-fixture"],
                "attestation": "Real end-to-end pytest fixture generated via corpus.gen_project; "
                               "not a production evaluation.",
                "samples_file": "samples.pt",
                "samples_sha256": hashlib.sha256(samples_path.read_bytes()).hexdigest(),
                "sample_count": len(holdout), "label_schema": "binary_v1"}
    manifest_path = eval_dir / "evaluation.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    # --- 5. evaluate_candidate(): real holdout evaluation, Wilson-interval release gates.
    evaluation = evaluate_candidate(data_root, candidate_id, manifest_path)
    assert evaluation["promotion_performed"] is False
    assert evaluation["n"] == len(holdout)
    assert evaluation["candidate_metrics"]["clean_n"] == MIN_CLEAN
    assert evaluation["candidate_metrics"]["attack_n"] == MIN_ATTACK
    updated = json.loads((data_root / "models" / "candidates" / candidate_id / "candidate.json")
                          .read_text(encoding="utf-8"))
    assert updated["promotion_allowed"] == evaluation["release_eligible"]
    # The active model must still be untouched after evaluation.
    assert hashlib.sha256(active_model.read_bytes()).hexdigest() == active_before

    if not evaluation["release_eligible"]:
        pytest.skip("candidate did not clear the statistical release gate on this random draw "
                    f"(gates={evaluation['decision']['gates']}); build_candidate and "
                    "evaluate_candidate were still verified end-to-end with real data")

    # --- 6. promote_candidate(): fresh re-evaluation, atomic backup + swap.
    promoted = release.promote_candidate(data_root, candidate_id, active_model)
    assert promoted["status"] == "committed"
    assert promoted["candidate_sha256"] == hashlib.sha256(candidate_artifact.read_bytes()).hexdigest()
    assert active_model.read_bytes() == candidate_artifact.read_bytes()
    backup = data_root / "models" / "release_backups" / f"{candidate_id}-{promoted['previous_sha256'][:16]}.pt"
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == active_before

    # --- 7. rollback_candidate(): restores the exact parent-model bytes.
    rolled_back = release.rollback_candidate(data_root, active_model)
    assert rolled_back["status"] == "committed"
    assert hashlib.sha256(active_model.read_bytes()).hexdigest() == active_before == promoted["previous_sha256"]
