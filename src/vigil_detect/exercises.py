from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from vigil_detect.engine import analyze_share
from vigil_detect.models import Incident
from vigil_detect.safety import LAB_MARKER_NAME, iter_regular_files
from vigil_detect.seed import seed_share
from vigil_detect.snapshot import take_snapshot


def copy_like_backup(share: Path) -> int:
    """Copy share files into Backups/ and leave the originals in place."""

    backup_root = share / "Backups" / "2026-11-19"
    copied = 0
    for path in iter_regular_files(share):
        relative = path.relative_to(share)
        if path.name == LAB_MARKER_NAME or "Backups" in relative.parts:
            continue
        destination = backup_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        copied += 1
    return copied


def run_backup_check() -> tuple[Incident, int]:
    """Return the incident from a bulk copy, and how many files were copied."""

    with tempfile.TemporaryDirectory(prefix="vigil-backup-") as temporary:
        work = Path(temporary)
        share = work / "share"
        seeded = seed_share(share, work / "canary_manifest.json")
        before = take_snapshot(share)
        copied = copy_like_backup(share)
        incident = analyze_share(
            share,
            before,
            seeded.manifest,
            audit_text="backup job copy files status=ok\n",
        )
        return incident, copied
