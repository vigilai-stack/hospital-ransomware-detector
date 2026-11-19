from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from vigil_detect.seed import seed_share
from vigil_detect.snapshot import take_snapshot


@pytest.fixture
def lab(tmp_path: Path) -> SimpleNamespace:
    work = tmp_path / "work"
    share = work / "share"
    manifest_path = work / "canary_manifest.json"
    seeded = seed_share(share, manifest_path)
    baseline = take_snapshot(share)
    return SimpleNamespace(
        work=work,
        share=share,
        manifest_path=manifest_path,
        manifest=seeded.manifest,
        baseline=baseline,
    )
