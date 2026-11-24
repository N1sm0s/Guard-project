"""Role assignment must fail closed when background shards are unknown or overlap."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "lab"))
import merge_background as mb  # noqa: E402


def test_current_background_roles_are_explicit_and_disjoint():
    assigned = {sid for source_ids in mb.ROLES.values() for sid in source_ids}

    mb.validate_roles(mb.ROLES, assigned)

    assert "real-benign-12" in mb.ROLES["check"]
    assert "sess-benign-08" in mb.ROLES["check"]
    assert {"real-benign-10", "real-benign-11"} == set(mb.ROLES["calibration"])


def test_unknown_background_shard_is_rejected_not_added_to_train():
    discovered = {sid for source_ids in mb.ROLES.values() for sid in source_ids}
    discovered.add("new-benign-unassigned")

    with pytest.raises(ValueError, match="Unassigned benign shards.*new-benign-unassigned"):
        mb.validate_roles(mb.ROLES, discovered)


def test_shard_cannot_be_assigned_to_multiple_roles():
    roles = {role: list(source_ids) for role, source_ids in mb.ROLES.items()}
    roles["check"].append(roles["train"][0])
    discovered = {sid for source_ids in roles.values() for sid in source_ids}

    with pytest.raises(ValueError, match="assigned to both"):
        mb.validate_roles(roles, discovered)


def test_missing_assigned_shard_is_rejected():
    roles = {role: list(source_ids) for role, source_ids in mb.ROLES.items()}
    missing = roles["calibration"][-1]
    discovered = {sid for source_ids in roles.values() for sid in source_ids} - {missing}

    with pytest.raises(ValueError, match=f"missing:.*{missing}"):
        mb.validate_roles(roles, discovered)


def test_duplicate_id_inside_role_is_rejected():
    roles = {role: list(source_ids) for role, source_ids in mb.ROLES.items()}
    roles["train"].append(roles["train"][0])
    discovered = {sid for source_ids in roles.values() for sid in source_ids}

    with pytest.raises(ValueError, match="duplicate shard ids"):
        mb.validate_roles(roles, discovered)


def test_role_set_must_be_exact():
    roles = {"train": ["a"], "calibration": ["b"], "check": ["c"], "future": ["d"]}

    with pytest.raises(ValueError, match="Roles must be exactly"):
        mb.validate_roles(roles, {"a", "b", "c", "d"})
