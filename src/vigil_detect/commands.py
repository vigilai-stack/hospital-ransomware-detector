from __future__ import annotations

import re

from vigil_detect.models import CommandHit

# Text signatures for commands that show up in ransomware incident write-ups.
# Matching a line does not mean the command ran. This module never executes a match.
_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "vssadmin_delete_shadows",
        "vssadmin delete shadows",
        re.compile(r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b", re.IGNORECASE),
    ),
    (
        "wmic_shadowcopy_delete",
        "wmic shadowcopy delete",
        re.compile(r"\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b", re.IGNORECASE),
    ),
    (
        "bcdedit_recovery_off",
        "bcdedit recoveryenabled no",
        re.compile(
            r"\bbcdedit(?:\.exe)?\s+/set\s+\"?\{default\}\"?\s+recoveryenabled\s+no\b",
            re.IGNORECASE,
        ),
    ),
    (
        "wbadmin_delete_catalog",
        "wbadmin delete catalog",
        re.compile(r"\bwbadmin(?:\.exe)?\s+delete\s+catalog\b", re.IGNORECASE),
    ),
)

SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".log"}


def scan_text(text: str, source: str) -> list[CommandHit]:
    hits: list[CommandHit] = []
    seen: set[str] = set()
    for line in text.splitlines():
        for pattern_id, description, pattern in _PATTERNS:
            if pattern_id in seen:
                continue
            if not pattern.search(line):
                continue
            seen.add(pattern_id)
            excerpt = line.strip()
            if len(excerpt) > 160:
                excerpt = excerpt[:157] + "..."
            note = ""
            if "executed=false" in line.lower():
                note = "The matching line is marked executed=false."
            hits.append(
                CommandHit(
                    pattern_id=pattern_id,
                    description=description,
                    source=source,
                    excerpt=excerpt,
                    note=note,
                )
            )
    return hits
