from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vigil_detect.entropy import shannon_entropy
from vigil_detect.models import DetectorConfig, FileFact, Snapshot
from vigil_detect.safety import LAB_MARKER_NAME, PART_SUFFIX, iter_regular_files


def _skip_name(name: str) -> bool:
    return name.startswith(".") or name == LAB_MARKER_NAME or name.endswith(PART_SUFFIX)


def take_snapshot(share: Path, config: DetectorConfig | None = None) -> Snapshot:
    settings = config or DetectorConfig()
    root = share.resolve()
    files: dict[str, FileFact] = {}
    skipped: list[str] = []
    for path in iter_regular_files(root):
        relative = path.relative_to(root).as_posix()
        if _skip_name(path.name):
            continue
        size = path.stat().st_size
        if size > settings.max_hash_bytes:
            skipped.append(relative)
            continue
        data = path.read_bytes()
        files[relative] = FileFact(
            rel_path=relative,
            size=size,
            entropy=shannon_entropy(data),
            sha256=hashlib.sha256(data).hexdigest(),
            extension=path.suffix.lower(),
        )
    return Snapshot(files=files, skipped=sorted(skipped))


def save_snapshot(snapshot: Snapshot, path: Path) -> None:
    payload = {
        "version": 1,
        "skipped": snapshot.skipped,
        "files": [
            {
                "rel_path": item.rel_path,
                "size": item.size,
                "entropy": item.entropy,
                "sha256": item.sha256,
                "extension": item.extension,
            }
            for item in sorted(snapshot.files.values(), key=lambda fact: fact.rel_path)
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_snapshot(path: Path) -> Snapshot:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("version") != 1:
        raise ValueError(f"Unsupported baseline version in {path}")
    files = {
        item["rel_path"]: FileFact(
            rel_path=item["rel_path"],
            size=int(item["size"]),
            entropy=float(item["entropy"]),
            sha256=item["sha256"],
            extension=item["extension"],
        )
        for item in payload["files"]
    }
    return Snapshot(files=files, skipped=list(payload.get("skipped", [])))
