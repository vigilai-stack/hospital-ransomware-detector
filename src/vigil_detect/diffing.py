from __future__ import annotations

from pathlib import Path

from vigil_detect.canary import evaluate_canaries
from vigil_detect.models import (
    AddedFile,
    CanaryManifest,
    DetectorConfig,
    DiffResult,
    InPlaceChange,
    Replacement,
    Snapshot,
)


def _parent(rel_path: str) -> str:
    return Path(rel_path).parent.as_posix()


def is_extension_rename(old_name: str, new_name: str) -> bool:
    """True when the new name is the old name plus another extension.

    `file.csv.locked` counts. `file.csv2` does not, even though it starts
    with the same letters.
    """

    if len(new_name) <= len(old_name):
        return False
    return new_name.startswith(old_name) and new_name[len(old_name)] == "."


def pair_replacements(removed: list[str], added: list[str]) -> list[tuple[str, str]]:
    unused = set(added)
    pairs: list[tuple[str, str]] = []
    for old in sorted(removed):
        old_name = Path(old).name
        old_parent = _parent(old)
        candidates = []
        for new in unused:
            if _parent(new) != old_parent:
                continue
            if is_extension_rename(old_name, Path(new).name):
                candidates.append(new)
        if not candidates:
            continue
        chosen = min(candidates, key=len)
        unused.remove(chosen)
        pairs.append((old, chosen))
    return pairs


def _entropy_jump(old_entropy: float, new_entropy: float, config: DetectorConfig) -> bool:
    return (
        old_entropy < config.entropy_low
        and new_entropy >= config.entropy_high
        and (new_entropy - old_entropy) >= config.min_entropy_delta
    )


def diff_snapshots(
    before: Snapshot,
    after: Snapshot,
    manifest: CanaryManifest,
    config: DetectorConfig | None = None,
) -> DiffResult:
    settings = config or DetectorConfig()
    skipped = set(before.skipped) | set(after.skipped)
    before_paths = set(before.files) - skipped
    after_paths = set(after.files) - skipped
    removed = sorted(before_paths - after_paths)
    added = sorted(after_paths - before_paths)
    pairs = pair_replacements(removed, added)
    paired_old = {old for old, _new in pairs}
    paired_new = {new for _old, new in pairs}
    known_hashes = before.hashes()

    replacements: list[Replacement] = []
    for old, new in pairs:
        old_fact = before.files[old]
        new_fact = after.files[new]
        replacements.append(
            Replacement(
                old_path=old,
                new_path=new,
                old_entropy=old_fact.entropy,
                new_entropy=new_fact.entropy,
                new_extension=new_fact.extension,
                entropy_jump=_entropy_jump(old_fact.entropy, new_fact.entropy, settings),
                suspicious_extension=new_fact.extension in settings.suspicious_extensions,
            )
        )

    in_place: list[InPlaceChange] = []
    for rel_path in sorted(before_paths & after_paths):
        old_fact = before.files[rel_path]
        new_fact = after.files[rel_path]
        if old_fact.sha256 == new_fact.sha256:
            continue
        in_place.append(
            InPlaceChange(
                path=rel_path,
                old_entropy=old_fact.entropy,
                new_entropy=new_fact.entropy,
                entropy_jump=_entropy_jump(old_fact.entropy, new_fact.entropy, settings),
            )
        )

    added_files: list[AddedFile] = []
    for rel_path in added:
        if rel_path in paired_new:
            continue
        fact = after.files[rel_path]
        added_files.append(
            AddedFile(
                path=rel_path,
                entropy=fact.entropy,
                extension=fact.extension,
                sha256=fact.sha256,
                copy_of_existing=fact.sha256 in known_hashes,
                suspicious_extension=fact.extension in settings.suspicious_extensions,
                high_entropy=fact.entropy >= settings.entropy_high,
            )
        )

    return DiffResult(
        replacements=replacements,
        in_place=in_place,
        added=added_files,
        unpaired_removed=[path for path in removed if path not in paired_old],
        canaries=evaluate_canaries(manifest, after),
    )
