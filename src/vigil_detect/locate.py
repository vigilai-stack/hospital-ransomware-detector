from __future__ import annotations

import os
from pathlib import Path


def find_project_file(relative: str) -> Path:
    """Find a repo file when running from a checkout or an editable install."""

    override = os.environ.get("VIGIL_PROJECT_ROOT")
    starts = []
    if override:
        starts.append(Path(override).resolve())
    starts.append(Path(__file__).resolve())
    starts.append(Path.cwd().resolve())

    seen: set[Path] = set()
    for start in starts:
        for parent in (start, *start.parents):
            if parent in seen:
                continue
            seen.add(parent)
            candidate = parent / relative
            if candidate.is_file():
                return candidate
    raise FileNotFoundError(
        f"Could not find {relative}. Run this from the project directory, "
        "or set VIGIL_PROJECT_ROOT."
    )
