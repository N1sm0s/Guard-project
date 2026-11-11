import hashlib
import json
from pathlib import Path

import torch

from integrityguard import online_learn


def test_online_feedback_creates_isolated_candidate_not_live_model(tmp_path, monkeypatch):
    active = tmp_path / "detector.pt"
    active.write_bytes(b"active detector bytes")
    active_before = hashlib.sha256(active.read_bytes()).hexdigest()
    data_root = tmp_path / "data"
    data_root.mkdir()
    confirmed_file = data_root / "online" / "confirmed.pt"
    confirmed_file.parent.mkdir()
    confirmed_file.write_bytes(b"retained feedback evidence")
    confirmed = [{"bin_y": float(i % 2), "_event_id": f"event-{i}",
                 "x": torch.full((2, 3), float(i)), "adj": torch.eye(2),
                 "layers": torch.ones((1, 4)), "behav": torch.zeros(5)} for i in range(20)]
    monkeypatch.setattr(online_learn, "load_confirmed", lambda _root: confirmed)

    from integrityguard import model, train
    calls = {"train": 0}

    class DummyModel:
        pass

    monkeypatch.setattr(model, "load_detector", lambda _path: (DummyModel(), {"threshold": 0.4}))

    def train_candidate(candidate_model, samples, _ref_val, epochs):
        calls["train"] += 1
        assert len(samples) == 20
        assert epochs == 3
        assert torch.get_num_threads() == 1
        return candidate_model, 0.6

    monkeypatch.setattr(train, "finetune_binary", train_candidate)

    def save_candidate(_model, path, metadata):
        Path(path).write_bytes(json.dumps(metadata).encode())

    monkeypatch.setattr(model, "save_detector", save_candidate)

    first = online_learn.build_candidate(data_root, active)
    second = online_learn.build_candidate(data_root, active)

    assert first["candidate_id"] == second["candidate_id"]
    assert first["status"] == "awaiting_independent_evaluation"
    assert first["promotion_allowed"] is False
    assert first["parent_model_sha256"] == active_before
    assert Path(first["artifact"]).is_file()
    assert hashlib.sha256(active.read_bytes()).hexdigest() == active_before
    assert confirmed_file.read_bytes() == b"retained feedback evidence"
    assert calls["train"] == 1
    assert first["confirmed_sample_count"] == 20
    assert first["training_sample_count"] == 20
    assert first["resource_limits"]["torch_threads"] == 1


def test_training_schedule_requires_balanced_samples_and_persists_cadence(tmp_path, monkeypatch):
    samples = [{"bin_y": float(i % 2), "_event_id": f"event-{i}",
                "x": torch.full((1, 2), float(i)), "adj": torch.eye(1),
                "layers": torch.ones((1, 3)), "behav": torch.zeros(2)} for i in range(20)]
    monkeypatch.setattr(online_learn, "load_confirmed", lambda _root: samples)
    first = online_learn.claim_candidate_schedule(tmp_path, now=1000)
    assert first["claimed"] is True
    assert first["benign_count"] == first["attack_count"] == 10

    early = online_learn.claim_candidate_schedule(tmp_path, now=2000)
    assert early["claimed"] is False
    assert early["reason"] == "training_interval_not_elapsed"
    online_learn.finish_candidate_schedule(tmp_path, "candidate_created", "candidate-1")
    due = online_learn.claim_candidate_schedule(tmp_path, now=1000 + online_learn.CANDIDATE_INTERVAL_SECONDS)
    assert due["claimed"] is True


def test_training_schedule_rejects_small_or_one_sided_feedback(tmp_path, monkeypatch):
    monkeypatch.setattr(online_learn, "load_confirmed", lambda _root: [
        {"bin_y": 1.0, "_event_id": "one", "x": torch.zeros((1, 1)), "adj": torch.zeros((1, 1)),
         "layers": torch.zeros((1, 1)), "behav": torch.zeros(1)}])
    status = online_learn.claim_candidate_schedule(tmp_path, now=1000)
    assert status["claimed"] is False
    assert status["reason"] == "insufficient_balanced_confirmed_data"
