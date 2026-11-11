import hashlib
import json

import pytest

from integrityguard import release


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_release_fixture(tmp_path):
    data = tmp_path / "data"
    candidate_id = "candidate-abc"
    candidate_dir = data / "models" / "candidates" / candidate_id
    candidate_dir.mkdir(parents=True)
    active = data / "runs" / "detector.pt"
    active.parent.mkdir(parents=True)
    active.write_bytes(b"parent-model")
    artifact = candidate_dir / "detector.pt"
    artifact.write_bytes(b"candidate-model")
    evaluation_file = tmp_path / "evaluation.json"
    evaluation_file.write_text("{}", encoding="utf-8")
    manifest = {"candidate_id": candidate_id, "status": "release_eligible", "promotion_allowed": True,
                "parent_model": str(active), "parent_model_sha256": sha(active),
                "training_data_sha256": "training-sha", "training_event_ids": [],
                "training_fingerprints": [], "evaluation": {
                    "evaluation_manifest": str(evaluation_file),
                    "evaluation_manifest_sha256": sha(evaluation_file),
                    "evaluation_data_sha256": "holdout-sha",
                    "candidate_model_sha256": sha(artifact), "release_eligible": True}}
    manifest_path = candidate_dir / "candidate.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return data, candidate_id, active, artifact, manifest_path


def test_promotion_rechecks_hashes_creates_backup_and_can_rollback(tmp_path, monkeypatch):
    data, candidate_id, active, artifact, manifest_path = make_release_fixture(tmp_path)
    monkeypatch.setattr(release, "evaluate_candidate", lambda *_args: {
        "release_eligible": True, "evaluation_data_sha256": "holdout-sha", "evaluated_at": "now"})

    promoted = release.promote_candidate(data, candidate_id, active)
    assert promoted["status"] == "committed"
    assert promoted["candidate_sha256"] == sha(artifact) == sha(active)
    assert sha(data / "models" / "release_backups" / f"{candidate_id}-{promoted['previous_sha256'][:16]}.pt") == promoted["previous_sha256"]
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["status"] == "promoted"

    rolled_back = release.rollback_candidate(data, active)
    assert rolled_back["action"] == "rollback" and rolled_back["status"] == "committed"
    assert active.read_bytes() == b"parent-model"
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["status"] == "rolled_back"


def test_promotion_rejects_failed_fresh_evaluation_without_touching_active_model(tmp_path, monkeypatch):
    data, candidate_id, active, _artifact, _manifest_path = make_release_fixture(tmp_path)
    before = active.read_bytes()
    monkeypatch.setattr(release, "evaluate_candidate", lambda *_args: {
        "release_eligible": False, "evaluation_data_sha256": "holdout-sha"})
    with pytest.raises(ValueError, match="(?i)повторная независимая оценка"):
        release.promote_candidate(data, candidate_id, active)
    assert active.read_bytes() == before


def test_promotion_rejects_candidate_artifact_tampering(tmp_path, monkeypatch):
    data, candidate_id, active, artifact, _manifest_path = make_release_fixture(tmp_path)
    artifact.write_bytes(b"tampered")
    monkeypatch.setattr(release, "evaluate_candidate", lambda *_args: pytest.fail("must not reevaluate tampered artifact"))
    with pytest.raises(ValueError, match="изменился после оценки"):
        release.promote_candidate(data, candidate_id, active)
    assert active.read_bytes() == b"parent-model"


def test_recovery_completes_crash_after_atomic_model_swap(tmp_path):
    data, candidate_id, active, artifact, manifest_path = make_release_fixture(tmp_path)
    backup = data / "models" / "release_backups" / "backup.pt"
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(active.read_bytes())
    old_sha, new_sha = sha(active), sha(artifact)
    active.write_bytes(artifact.read_bytes())
    state = {"action": "promote", "status": "prepared", "candidate_id": candidate_id,
             "active_model_path": str(active), "backup_path": str(backup),
             "previous_sha256": old_sha, "candidate_sha256": new_sha,
             "prepared_at": "before-crash"}
    state_path = data / "models" / "release_state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    recovered = release.recover_release(data, active)
    assert recovered["status"] == "committed" and recovered["recovered_after_crash"]
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["status"] == "promoted"


def test_recovery_aborts_if_crash_happened_before_atomic_swap(tmp_path):
    data, candidate_id, active, artifact, _manifest_path = make_release_fixture(tmp_path)
    backup = data / "models" / "release_backups" / "parent.pt"
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(active.read_bytes())
    state = {"action": "promote", "status": "prepared", "candidate_id": candidate_id,
             "active_model_path": str(active), "backup_path": str(backup),
             "previous_sha256": sha(active), "candidate_sha256": sha(artifact)}
    state_path = data / "models" / "release_state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    recovered = release.recover_release(data, active)
    assert recovered["status"] == "aborted"
    assert active.read_bytes() == b"parent-model"


def test_recovery_blocks_if_active_hash_is_neither_parent_nor_candidate(tmp_path):
    data, candidate_id, active, artifact, _manifest_path = make_release_fixture(tmp_path)
    state_path = data / "models" / "release_state.json"
    state_path.write_text(json.dumps({"action": "promote", "status": "prepared",
                                      "candidate_id": candidate_id,
                                      "previous_sha256": sha(active),
                                      "candidate_sha256": sha(artifact)}), encoding="utf-8")
    active.write_bytes(b"unexpected model")
    recovered = release.recover_release(data, active)
    assert recovered["status"] == "needs_review"
    assert active.read_bytes() == b"unexpected model"


def test_rollback_refuses_to_overwrite_model_changed_after_promotion(tmp_path, monkeypatch):
    data, candidate_id, active, _artifact, _manifest_path = make_release_fixture(tmp_path)
    monkeypatch.setattr(release, "evaluate_candidate", lambda *_args: {
        "release_eligible": True, "evaluation_data_sha256": "holdout-sha", "evaluated_at": "now"})
    release.promote_candidate(data, candidate_id, active)
    active.write_bytes(b"operator-updated-model")
    with pytest.raises(ValueError, match="изменилась после выпуска"):
        release.rollback_candidate(data, active)
    assert active.read_bytes() == b"operator-updated-model"

