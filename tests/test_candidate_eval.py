import hashlib
import json

import pytest
import torch

from integrityguard.candidate_eval import _validate_holdout, release_decision, wilson


def valid_sample(event_id="holdout-1", fingerprint="sha-holdout-1"):
    return {"_event_id": event_id, "_fingerprint": fingerprint, "_project_id": "project-x",
            "_label_evidence": "independent source advisory-1", "x": torch.zeros((1, 44)),
            "adj": torch.zeros((1, 1)), "layers": torch.zeros((1, 28)),
            "behav": torch.zeros(32), "y": 1}


def write_holdout(directory, candidate, samples, **overrides):
    samples_path = directory / "samples.pt"
    torch.save(samples, samples_path)
    manifest = {"format": "integrityguard-independent-evaluation-v1", "data_kind": "real",
                "independent": True, "candidate_id": candidate["candidate_id"], "reviewer": "Analyst A",
                "collected_at": "2026-11-11T10:00:00+00:00", "source_refs": ["https://advisory.example/1"],
                "attestation": "I independently verified package provenance and labels.",
                "samples_file": "samples.pt", "samples_sha256": hashlib.sha256(samples_path.read_bytes()).hexdigest(),
                "sample_count": len(samples), "label_schema": "binary_v1"}
    manifest.update(overrides)
    path = directory / "evaluation.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def candidate_manifest(**overrides):
    candidate = {"candidate_id": "cand-1", "training_event_ids": ["train-1"],
                 "training_fingerprints": ["sha-train-1"],
                 "training_project_ids": ["train-project"],
                 "training_project_ids_complete": True}
    candidate.update(overrides)
    return candidate


def test_wilson_intervals_are_conservative_for_release_gates():
    lower, upper = wilson(90, 100)
    assert 0.80 < lower < 0.84
    assert 0.94 < upper < 0.97
    clean_lower, clean_upper = wilson(0, 200)
    assert clean_lower == 0 and 0 < clean_upper < 0.02


def test_release_gate_requires_minimum_independent_counts_and_quality():
    parent = {"recall": 0.90, "fpr": 0.0, "auc": 0.96}
    candidate = {"recall": 0.90, "fpr": 0.0, "auc": 0.96}
    allowed = release_decision(parent, candidate, n_clean=300, n_attack=120)
    assert allowed["eligible"] is True

    too_small = release_decision(parent, candidate, n_clean=30, n_attack=20)
    assert too_small["eligible"] is False
    assert too_small["gates"]["minimum_clean_samples"] is False


def test_release_gate_rejects_regression_and_nan_auc():
    parent = {"recall": 0.9, "fpr": 0.01, "auc": 0.95}
    regressed = {"recall": 0.75, "fpr": 0.05, "auc": None}
    result = release_decision(parent, regressed, 300, 120)
    assert result["eligible"] is False
    assert result["gates"]["recall_non_regression"] is False
    assert result["gates"]["fpr_non_regression"] is False
    assert result["gates"]["auc_non_regression"] is False


def test_holdout_manifest_requires_real_independent_provenance(tmp_path):
    candidate = candidate_manifest()
    path = write_holdout(tmp_path, candidate, [valid_sample()])
    manifest, samples, sha, manifest_sha, sample_path = _validate_holdout(path, candidate)
    assert manifest["data_kind"] == "real"
    assert len(samples) == 1 and len(sha) == 64
    assert len(manifest_sha) == 64 and sample_path.name == "samples.pt"

    unverified = write_holdout(tmp_path, candidate, [valid_sample()], independent=False)
    with pytest.raises(ValueError, match="независимо собранных реальных данных"):
        _validate_holdout(unverified, candidate)


@pytest.mark.parametrize("sample", [
    valid_sample(event_id="train-1", fingerprint="new-sha"),
    valid_sample(event_id="new-event", fingerprint="sha-train-1"),
])
def test_holdout_overlap_with_training_is_rejected(tmp_path, sample):
    candidate = candidate_manifest()
    path = write_holdout(tmp_path, candidate, [sample])
    with pytest.raises(ValueError, match="пересекается"):
        _validate_holdout(path, candidate)


def test_holdout_tampering_and_duplicate_fingerprints_are_rejected(tmp_path):
    candidate = candidate_manifest(training_event_ids=[], training_fingerprints=[])
    path = write_holdout(tmp_path, candidate, [valid_sample(), valid_sample("holdout-2", "sha-holdout-1")])
    with pytest.raises(ValueError, match="повторные"):
        _validate_holdout(path, candidate)
    samples_path = tmp_path / "samples.pt"
    samples_path.write_bytes(samples_path.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="SHA-256"):
        _validate_holdout(path, candidate)
