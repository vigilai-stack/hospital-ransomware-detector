from __future__ import annotations

import inspect
from pathlib import Path

import vigil_detect.simulator as simulator
from vigil_detect.entropy import shannon_entropy
from vigil_detect.safety import SandboxError, assert_safe_share
from vigil_detect.seed import seed_share
from vigil_detect.simulator import (
    SHADOW_DEMO_COMMAND,
    restore_bytes,
    restore_share,
    run_simulator,
    transform_bytes,
)
from vigil_detect.snapshot import take_snapshot


def test_transform_is_reversible_and_raises_entropy():
    original = ("record_id,note\nSYN-1,Synthetic lab row. Not a real patient.\n" * 40).encode()
    assert shannon_entropy(original) < 6.0
    transformed = transform_bytes(original)
    assert shannon_entropy(transformed) >= 7.2
    assert restore_bytes(transformed) == original


def test_seeded_files_are_low_entropy(lab):
    for fact in lab.baseline.files.values():
        assert fact.entropy < 6.0, fact.rel_path


def test_simulator_refuses_paths_that_are_not_a_lab_share(tmp_path: Path):
    with pytest_raises(SandboxError):
        assert_safe_share(Path("/"))
    with pytest_raises(SandboxError):
        assert_safe_share(Path.home())

    share = tmp_path / "share"
    share.mkdir()
    (share / "VIGIL_LAB_SHARE.txt").write_text("wrong phrase\n", encoding="utf-8")
    with pytest_raises(SandboxError):
        run_simulator(share, tmp_path / "audit.log")

    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (project / "VIGIL_LAB_SHARE.txt").write_text(
        "Synthetic hospital file-share lab\n",
        encoding="utf-8",
    )
    with pytest_raises(SandboxError):
        run_simulator(project, tmp_path / "audit.log")


def test_simulator_does_not_follow_a_symlink_or_call_a_shell(lab, tmp_path: Path):
    source = inspect.getsource(simulator)
    assert "subprocess" not in source
    assert "os.system" not in source

    outside = tmp_path / "outside.txt"
    outside.write_text("keep this text", encoding="utf-8")
    link = lab.share / "EHR_Exports" / "escape.csv"
    link.symlink_to(outside)
    with pytest_raises(SandboxError):
        run_simulator(lab.share, lab.work / "audit.log")
    assert outside.read_text(encoding="utf-8") == "keep this text"
    assert list(lab.share.rglob("*.locked")) == []


def test_audit_log_must_stay_outside_the_share(lab):
    with pytest_raises(SandboxError):
        run_simulator(lab.share, lab.share / "command_audit.log")


def test_manifest_must_stay_outside_the_share(tmp_path: Path):
    share = tmp_path / "share"
    with pytest_raises(SandboxError):
        seed_share(share, share / "canary_manifest.json")


def test_simulator_round_trip_restores_bytes_and_leaves_unknown_locked_files(lab):
    originals = {
        path.relative_to(lab.share).as_posix(): path.read_bytes()
        for path in lab.share.rglob("*")
        if path.is_file() and path.suffix.lower() in {".csv", ".txt"}
    }
    decoy = lab.share / "Billing" / "notes.txt.locked"
    decoy.write_text("leave me", encoding="utf-8")
    result = run_simulator(lab.share, lab.work / "command_audit.log")
    assert result.executed is False
    assert SHADOW_DEMO_COMMAND in (lab.work / "command_audit.log").read_text(encoding="utf-8")
    assert decoy.read_text(encoding="utf-8") == "leave me"

    restored = restore_share(lab.share)
    assert decoy.read_text(encoding="utf-8") == "leave me"
    assert restored.note_removed is True
    for relative, data in originals.items():
        assert (lab.share / relative).read_bytes() == data
    assert relative_locked_count(lab.share) == 1


def relative_locked_count(share: Path) -> int:
    return len(list(share.rglob("*.locked")))


def test_snapshot_round_trip(lab, tmp_path: Path):
    destination = tmp_path / "baseline.json"
    from vigil_detect.snapshot import load_snapshot, save_snapshot

    save_snapshot(lab.baseline, destination)
    loaded = load_snapshot(destination)
    assert loaded.files.keys() == lab.baseline.files.keys()
    assert take_snapshot(lab.share).files["Billing/ClaimsBatch_SYN_441.csv"].sha256 == (
        lab.baseline.files["Billing/ClaimsBatch_SYN_441.csv"].sha256
    )


def pytest_raises(error):
    import pytest

    return pytest.raises(error)
