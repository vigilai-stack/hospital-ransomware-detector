from __future__ import annotations

import os
from pathlib import Path

LAB_MARKER_NAME = "VIGIL_LAB_SHARE.txt"
REQUIRED_MARKER_PHRASE = "Synthetic hospital file-share lab"
PART_SUFFIX = ".vigilpart"


class SandboxError(ValueError):
    """The lab simulator or a path check refused to continue."""


def assert_outside_share(share: Path, other: Path, what: str) -> None:
    share_resolved = share.resolve()
    other_resolved = other.resolve()
    if other_resolved == share_resolved or share_resolved in other_resolved.parents:
        raise SandboxError(
            f"{what} must be stored outside the share so a process that "
            "rewrites the share cannot erase it."
        )


def assert_safe_share(share: Path) -> Path:
    """Refuse anything that is not a marked lab folder.

    The simulator only transforms files after this check. The marker file has
    to contain a fixed phrase, so a same-named file in a real directory is not
    enough to unlock it.
    """

    resolved = share.resolve()
    if resolved == Path(resolved.anchor):
        raise SandboxError("Refusing the filesystem root.")
    if resolved == Path.home().resolve():
        raise SandboxError("Refusing a home directory.")
    if (resolved / ".git").exists() or (resolved / "pyproject.toml").exists():
        raise SandboxError("Refusing a project directory.")

    marker = resolved / LAB_MARKER_NAME
    if not marker.is_file() or marker.is_symlink():
        raise SandboxError(
            f"Refusing to run. {LAB_MARKER_NAME} must be a regular file in the share. "
            "Create a lab share with `vigil-detect seed`."
        )
    text = marker.read_text(encoding="utf-8", errors="replace")
    if REQUIRED_MARKER_PHRASE not in text:
        raise SandboxError(
            f"Refusing to run. {LAB_MARKER_NAME} does not contain the lab phrase."
        )

    seen = 0
    for dirpath, dirnames, filenames in os.walk(resolved, followlinks=False):
        current = Path(dirpath)
        for name in list(dirnames):
            seen += 1
            candidate = current / name
            if candidate.is_symlink():
                raise SandboxError(f"Refusing a share that contains a symlink: {candidate}")
        for name in filenames:
            seen += 1
            candidate = current / name
            if candidate.is_symlink():
                raise SandboxError(f"Refusing a share that contains a symlink: {candidate}")
            if name.endswith(".py"):
                raise SandboxError("Refusing a share that contains Python source files.")
            if seen > 5000:
                raise SandboxError("Share is too large for the lab simulator.")
    return resolved


def iter_regular_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = [name for name in dirnames if not (current / name).is_symlink()]
        for name in filenames:
            candidate = current / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            files.append(candidate)
    return files


def resolve_within(root: Path, candidate: Path) -> Path:
    root_resolved = root.resolve()
    if candidate.is_symlink():
        raise SandboxError(f"Refusing a symlink: {candidate}")
    resolved = candidate.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise SandboxError(f"Path is outside the lab share: {candidate}")
    current = root_resolved
    try:
        relative = resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise SandboxError(f"Path is outside the lab share: {candidate}") from exc
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise SandboxError(f"Refusing a symlink: {current}")
    return resolved
