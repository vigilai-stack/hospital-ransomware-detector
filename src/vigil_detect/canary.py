from __future__ import annotations

import json
from pathlib import Path

from vigil_detect.models import Canary, CanaryManifest, CanaryStatus, Snapshot


def safe_relative(rel_path: str) -> str:
    path = Path(rel_path)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Unsafe canary path: {rel_path}")
    return path.as_posix()


def save_manifest(manifest: CanaryManifest, path: Path) -> None:
    payload = {
        "version": manifest.version,
        "note": "Synthetic lab canaries. Hashes belong outside the share.",
        "canaries": [
            {"rel_path": item.rel_path, "sha256": item.sha256, "role": item.role}
            for item in manifest.canaries
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_manifest(path: Path) -> CanaryManifest:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("version") != 1:
        raise ValueError(f"Unsupported canary manifest version in {path}")
    canaries = [
        Canary(
            rel_path=safe_relative(item["rel_path"]),
            sha256=item["sha256"],
            role=item["role"],
        )
        for item in payload["canaries"]
    ]
    return CanaryManifest(canaries=canaries, version=1)


def evaluate_canaries(manifest: CanaryManifest, after: Snapshot) -> list[CanaryStatus]:
    statuses: list[CanaryStatus] = []
    for canary in manifest.canaries:
        current = after.files.get(canary.rel_path)
        if current is None:
            status = "missing"
        elif current.sha256 != canary.sha256:
            status = "modified"
        else:
            status = "ok"
        statuses.append(
            CanaryStatus(rel_path=canary.rel_path, role=canary.role, status=status)
        )
    return statuses
