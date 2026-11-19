from __future__ import annotations

import os
import shutil
from pathlib import Path

from vigil_detect.diffing import diff_snapshots, is_extension_rename
from vigil_detect.engine import analyze_share, analyze_snapshot
from vigil_detect.exercises import copy_like_backup, run_backup_check
from vigil_detect.models import (
    CanaryManifest,
    CommandHit,
    FileFact,
    Snapshot,
    YaraHit,
)
from vigil_detect.response import ISOLATE_RECOMMENDATION
from vigil_detect.simulator import transform_bytes
from vigil_detect.snapshot import take_snapshot


def _fact(path: str, entropy: float, digest: str, size: int = 1200) -> FileFact:
    return FileFact(
        rel_path=path,
        size=size,
        entropy=entropy,
        sha256=digest,
        extension=Path(path).suffix.lower(),
    )


def test_extension_rename_does_not_treat_csv2_as_a_rename():
    assert is_extension_rename("file.csv", "file.csv.locked")
    assert not is_extension_rename("file.csv", "file.csv2")


def test_csv2_is_not_scored_as_encryption():
    before = Snapshot(
        files={
            "EHR/file.csv": _fact("EHR/file.csv", 4.2, "a"),
            "EHR/other.csv": _fact("EHR/other.csv", 4.2, "b"),
        }
    )
    after = Snapshot(
        files={
            "EHR/other.csv": _fact("EHR/other.csv", 4.2, "b"),
            "EHR/file.csv2": _fact("EHR/file.csv2", 7.9, "c"),
        }
    )
    incident = analyze_snapshot(
        before=before,
        after=after,
        manifest=CanaryManifest(canaries=[]),
        yara_hits=[],
        command_hits=[],
        share="memory",
    )
    assert incident.score == 0
    assert incident.severity == "none"


def test_bulk_copy_is_not_ransomware(lab):
    copied = copy_like_backup(lab.share)
    assert copied >= 5
    incident = analyze_share(lab.share, lab.baseline, lab.manifest, audit_text="backup job copy files status=ok\n")
    assert incident.backup_like is True
    assert incident.score == 0
    assert incident.severity == "info"
    assert incident.actions_taken == []
    assert ISOLATE_RECOMMENDATION not in incident.recommendations
    assert all(signal.kind != "canary_tamper" for signal in incident.signals)


def test_backup_check_command_path():
    incident, copied = run_backup_check()
    assert copied >= 5
    assert incident.severity == "info"
    assert incident.score == 0
    assert incident.backup_like is True


def test_new_zip_archives_are_not_scored(lab):
    folder = lab.share / "Backups"
    folder.mkdir()
    for index in range(8):
        (folder / f"nightly_{index}.zip").write_bytes(os.urandom(4000))
    incident = analyze_share(lab.share, lab.baseline, lab.manifest)
    assert incident.score == 0
    assert incident.severity == "info"
    assert incident.backup_like is False
    assert any(signal.kind == "new_high_entropy" for signal in incident.signals)
    assert ISOLATE_RECOMMENDATION not in incident.recommendations


def test_folder_name_does_not_hide_replacements(lab):
    sources = [
        path
        for path in sorted((lab.share / "EHR_Exports").glob("*.csv"))
        + sorted((lab.share / "Billing").glob("*.csv"))
    ][:6]
    folder = lab.share / "Backups"
    folder.mkdir()
    for index, source in enumerate(sources):
        shutil.copy(source, folder / f"record_{index}.csv")
    before = take_snapshot(lab.share)
    for path in folder.glob("*.csv"):
        locked = path.with_name(path.name + ".locked")
        locked.write_bytes(transform_bytes(path.read_bytes()))
        path.unlink()
    incident = analyze_share(lab.share, before, lab.manifest)
    assert incident.backup_like is False
    assert incident.severity == "critical"
    assert any("Backups/" in path for signal in incident.signals for path in signal.paths)


def test_calm_rewrite_is_not_ransomware(lab):
    canaries = {item.rel_path for item in lab.manifest.canaries}
    changed = 0
    for path in lab.share.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(lab.share).as_posix()
        if relative in canaries or path.suffix.lower() not in {".csv", ".txt"}:
            continue
        with path.open("a", encoding="utf-8") as handle:
            handle.write("refresh,ok,synthetic\n")
        changed += 1
    assert changed >= 5
    incident = analyze_share(lab.share, lab.baseline, lab.manifest)
    assert incident.score == 0
    assert incident.severity == "info"
    assert any(signal.kind == "bulk_rewrite" for signal in incident.signals)
    assert all(signal.kind != "canary_tamper" for signal in incident.signals)


def test_editing_one_canary_is_high_not_critical(lab):
    target = lab.share / "Billing" / "ClaimsBatch_SYN_999.csv"
    target.write_text(target.read_text(encoding="utf-8") + "note,added,by,a,person\n", encoding="utf-8")
    incident = analyze_share(lab.share, lab.baseline, lab.manifest)
    assert incident.severity == "high"
    assert incident.score == 60
    assert any(signal.kind == "canary_tamper" for signal in incident.signals)
    assert ISOLATE_RECOMMENDATION not in incident.recommendations
    assert any("person edited" in item for item in incident.recommendations)
    assert incident.actions_taken == []
    assert "patient-care systems are actually unavailable" in incident.clinical_lead


def test_note_rule_alone_is_medium_and_does_not_recommend_isolation():
    before = Snapshot(files={})
    after = Snapshot(files={"README_RESTORE_FILES.txt": _fact("README_RESTORE_FILES.txt", 4.0, "n")})
    incident = analyze_snapshot(
        before=before,
        after=after,
        manifest=CanaryManifest(canaries=[]),
        yara_hits=[
            YaraHit(
                rule="Ransom_Note_Traits",
                path="README_RESTORE_FILES.txt",
                severity="high",
                description="lab",
            )
        ],
        command_hits=[],
        share="memory",
    )
    assert incident.severity == "medium"
    assert incident.score == 25
    assert incident.clinical_actions == []
    joined = " ".join(incident.recommendations)
    assert "Containment and downtime are not recommended" in joined
    assert "clinical network" not in joined


def test_shadow_text_alone_is_high():
    empty = Snapshot(files={})
    incident = analyze_snapshot(
        before=empty,
        after=empty,
        manifest=CanaryManifest(canaries=[]),
        yara_hits=[],
        command_hits=[
            CommandHit(
                pattern_id="vssadmin_delete_shadows",
                description="vssadmin delete shadows",
                source="audit-log",
                excerpt="vssadmin delete shadows",
                note="",
            )
        ],
        share="memory",
    )
    assert incident.severity == "high"
    assert incident.score == 35
    assert ISOLATE_RECOMMENDATION not in incident.recommendations


def test_copies_do_not_cancel_a_canary(lab):
    copy_like_backup(lab.share)
    target = lab.share / "Imaging" / "Study_SYN_1099.txt"
    target.write_text(target.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
    incident = analyze_share(lab.share, lab.baseline, lab.manifest)
    assert incident.backup_like is False
    assert incident.severity in {"high", "critical"}
    assert any(signal.kind == "canary_tamper" for signal in incident.signals)
    assert any(signal.kind == "bulk_copy" for signal in incident.signals)


def test_diff_pairs_locked_extension_only():
    before = Snapshot(
        files={"EHR/a.csv": _fact("EHR/a.csv", 4.0, "a"), "EHR/a.csv2": _fact("EHR/a.csv2", 4.0, "b")}
    )
    after = Snapshot(
        files={
            "EHR/a.csv2": _fact("EHR/a.csv2", 4.0, "b"),
            "EHR/a.csv.locked": _fact("EHR/a.csv.locked", 7.8, "c"),
        }
    )
    diff = diff_snapshots(before, after, CanaryManifest(canaries=[]))
    assert len(diff.replacements) == 1
    assert diff.replacements[0].new_path == "EHR/a.csv.locked"
    assert diff.replacements[0].entropy_jump is True
