from __future__ import annotations

import os
import random
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from vigil_detect.safety import (
    LAB_MARKER_NAME,
    PART_SUFFIX,
    SandboxError,
    assert_outside_share,
    assert_safe_share,
    iter_regular_files,
    resolve_within,
)

# Public, fixed seed. The lab transform is reversible on purpose.
SIMULATOR_SEED = 0x56494749
MAGIC = b"VIGILSIM1"
HEADER_SIZE = len(MAGIC) + 8
ELIGIBLE_EXTENSIONS = {".csv", ".txt", ".tsv"}
MAX_FILE_BYTES = 1_000_000
SHADOW_DEMO_COMMAND = "vssadmin.exe delete shadows /all /quiet"
NOTE_NAME = "README_RESTORE_FILES.txt"
NOTE_BANNER = "LAB SIMULATOR NOTE — not a real ransom demand. Nothing was held for payment."

RANSOM_NOTE = f"""{NOTE_BANNER}

Your files have been encrypted.
Do not rename the encrypted files.
Send bitcoin to the example address BTC-EXAMPLE-NOT-A-WALLET.
A decryption key will not actually be provided. This is a lab.
Your personal identification code is LAB-0000.
"""


@dataclass
class SimulatorResult:
    transformed: list[str] = field(default_factory=list)
    note_path: str = ""
    audit_path: str = ""
    command: str = SHADOW_DEMO_COMMAND
    executed: bool = False


@dataclass
class RestoreResult:
    restored: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    note_removed: bool = False


def transform_bytes(data: bytes, seed: int = SIMULATOR_SEED) -> bytes:
    # Deterministic lab keystream with a published seed. Not a secret and not meant to resist recovery.
    stream = random.Random(seed).randbytes(len(data))  # nosec B311
    body = bytes(byte ^ stream[index] for index, byte in enumerate(data))
    return MAGIC + struct.pack(">II", seed, len(data)) + body


def restore_bytes(blob: bytes) -> bytes:
    if not blob.startswith(MAGIC) or len(blob) < HEADER_SIZE:
        raise ValueError("Not a lab-simulator file.")
    seed, length = struct.unpack(">II", blob[len(MAGIC) : HEADER_SIZE])
    body = blob[HEADER_SIZE:]
    if length != len(body):
        raise ValueError("Lab-simulator length header does not match the file.")
    stream = random.Random(seed).randbytes(length)  # nosec B311
    return bytes(byte ^ stream[index] for index, byte in enumerate(body))


def _atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + PART_SUFFIX)
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _eligible(path: Path) -> bool:
    return (
        path.suffix.lower() in ELIGIBLE_EXTENSIONS
        and path.name not in {NOTE_NAME, LAB_MARKER_NAME}
        and not path.name.endswith(".locked")
        and path.stat().st_size <= MAX_FILE_BYTES
    )


def run_simulator(share: Path, audit_log: Path) -> SimulatorResult:
    """Rewrite lab files with a reversible transform. Does not run system commands.

    The audit log receives the text of a shadow-copy deletion command with
    executed=false. Nothing is sent to a shell.
    """

    root = assert_safe_share(share)
    assert_outside_share(root, audit_log, "The command audit log")
    audit_log.parent.mkdir(parents=True, exist_ok=True)

    for leftover in iter_regular_files(root):
        if leftover.name.endswith(PART_SUFFIX):
            resolve_within(root, leftover).unlink()

    targets = [path for path in iter_regular_files(root) if _eligible(path)]
    if len(targets) > 500:
        raise SandboxError("Refusing to transform more than 500 files.")

    result = SimulatorResult()
    for path in targets:
        source = resolve_within(root, path)
        original = source.read_bytes()
        if original.startswith(MAGIC):
            continue
        destination = resolve_within(root, source.with_name(source.name + ".locked"))
        _atomic_write(destination, transform_bytes(original))
        source.unlink()
        result.transformed.append(destination.relative_to(root).as_posix())

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = (
        f"{timestamp} host=LAB-CLINIC-01 user=lab-simulator pid=0 executed=false "
        f"command={SHADOW_DEMO_COMMAND}\n"
    )
    with audit_log.open("a", encoding="utf-8") as handle:
        handle.write(line)
    result.audit_path = str(audit_log)

    note = resolve_within(root, root / NOTE_NAME)
    _atomic_write(note, RANSOM_NOTE.encode("utf-8"))
    result.note_path = note.relative_to(root).as_posix()
    result.executed = False
    return result


def restore_share(share: Path) -> RestoreResult:
    root = assert_safe_share(share)
    result = RestoreResult()
    for path in iter_regular_files(root):
        if not path.name.endswith(".locked"):
            continue
        source = resolve_within(root, path)
        data = source.read_bytes()
        if not data.startswith(MAGIC):
            result.skipped.append(source.relative_to(root).as_posix())
            continue
        original = resolve_within(root, source.with_name(source.name[: -len(".locked")]))
        if original.exists():
            result.skipped.append(source.relative_to(root).as_posix())
            continue
        _atomic_write(original, restore_bytes(data))
        source.unlink()
        result.restored.append(original.relative_to(root).as_posix())

    note = root / NOTE_NAME
    if note.is_file() and not note.is_symlink():
        text = note.read_text(encoding="utf-8", errors="replace")
        if text.startswith(NOTE_BANNER):
            note.unlink()
            result.note_removed = True
    return result
