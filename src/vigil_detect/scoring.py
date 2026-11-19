from __future__ import annotations

from vigil_detect.models import (
    CommandHit,
    Decision,
    DetectorConfig,
    DiffResult,
    InPlaceChange,
    Replacement,
    Signal,
    Weights,
    YaraHit,
    max_severity,
)

NOTE_RULE = "Ransom_Note_Traits"
EXTENSION_RULE = "Suspicious_Extension_Trait"


def band(score: int) -> str:
    if score <= 0:
        return "none"
    if score < 15:
        return "low"
    if score < 40:
        return "medium"
    if score < 70:
        return "high"
    return "critical"


def decide(
    diff: DiffResult,
    yara_hits: list[YaraHit],
    command_hits: list[CommandHit],
    config: DetectorConfig | None = None,
    weights: Weights | None = None,
) -> Decision:
    settings = config or DetectorConfig()
    scale = weights or Weights()

    entropy_events: list[Replacement | InPlaceChange] = [
        item for item in diff.replacements if item.entropy_jump
    ] + [item for item in diff.in_place if item.entropy_jump]
    suspicious: list[Replacement | object] = [
        item for item in diff.replacements if item.suspicious_extension
    ] + [item for item in diff.added if item.suspicious_extension]
    copies = [
        item
        for item in diff.added
        if item.copy_of_existing and not item.suspicious_extension
    ]
    calm_rewrites = [item for item in diff.in_place if not item.entropy_jump]
    new_high = [
        item
        for item in diff.added
        if item.high_entropy and not item.copy_of_existing and not item.suspicious_extension
    ]
    canary_bad = [item for item in diff.canaries if item.status != "ok"]
    note_hits = [hit for hit in yara_hits if hit.rule == NOTE_RULE]
    extension_hits = [hit for hit in yara_hits if hit.rule == EXTENSION_RULE]
    other_hits = [
        hit for hit in yara_hits if hit.rule not in {NOTE_RULE, EXTENSION_RULE}
    ]
    shadow: list[CommandHit] = []
    seen_patterns: set[str] = set()
    for hit in command_hits:
        if hit.pattern_id in seen_patterns:
            continue
        seen_patterns.add(hit.pattern_id)
        shadow.append(hit)

    signals: list[Signal] = []
    observations: list[str] = []
    score = 0

    if canary_bad:
        score += scale.canary
        signals.append(
            Signal(
                kind="canary_tamper",
                weight=scale.canary,
                summary=f"{len(canary_bad)} canary file(s) were modified or removed.",
                paths=[item.rel_path for item in canary_bad],
                detail=(
                    "Canary hashes are kept outside the share. "
                    "A person saving one of these files also causes this alert."
                ),
            )
        )
        for item in canary_bad:
            observations.append(f"Canary ({item.role}) {item.status}: {item.rel_path}")

    if shadow:
        score += scale.shadow
        notes = " ".join(hit.note for hit in shadow if hit.note)
        signals.append(
            Signal(
                kind="shadow_command",
                weight=scale.shadow,
                summary="Shadow-copy or recovery-suppression command text matched.",
                paths=[hit.source for hit in shadow],
                detail=(
                    "Matched "
                    + ", ".join(hit.description for hit in shadow)
                    + ". This is a text match. The program does not know if the command ran. "
                    + notes
                ).strip(),
            )
        )

    if entropy_events:
        weight = min(scale.entropy_cap, scale.entropy_each * len(entropy_events))
        score += weight
        paths: list[str] = []
        for item in entropy_events:
            if isinstance(item, Replacement):
                paths.append(item.new_path)
                observations.append(
                    f"Entropy jump: {item.old_path} ({item.old_entropy:.2f}) "
                    f"replaced by {item.new_path} ({item.new_entropy:.2f})"
                )
            else:
                paths.append(item.path)
                observations.append(
                    f"Entropy jump: {item.path} "
                    f"({item.old_entropy:.2f} to {item.new_entropy:.2f})"
                )
        signals.append(
            Signal(
                kind="entropy_jump",
                weight=weight,
                summary=f"{len(entropy_events)} file(s) went from low entropy to high entropy.",
                paths=paths,
                detail=(
                    "High entropy means the bytes look close to random. Encryption does that. "
                    "A new archive that does not replace a known file is not counted."
                ),
            )
        )

    if suspicious:
        burst = len(suspicious) >= settings.rename_burst_count
        weight = scale.rename_burst if burst else scale.rename_partial
        score += weight
        paths = []
        for item in suspicious:
            if isinstance(item, Replacement):
                paths.append(item.new_path)
                observations.append(f"Suspicious extension: {item.old_path} -> {item.new_path}")
            else:
                paths.append(item.path)
                observations.append(f"Suspicious extension on new file: {item.path}")
        signals.append(
            Signal(
                kind="suspicious_rename",
                weight=weight,
                summary=(
                    f"{len(suspicious)} file(s) gained a ransomware-like extension"
                    + (" (burst)." if burst else " (below the burst threshold).")
                ),
                paths=paths,
                detail=(
                    "The default extension list is .locked, .encrypted, .crypt, "
                    ".crypto, .ryk, and .wncry."
                ),
            )
        )

    if note_hits:
        score += scale.yara_note
        signals.append(
            Signal(
                kind="yara_match",
                weight=scale.yara_note,
                summary=f"YARA rule {NOTE_RULE} matched {len(note_hits)} file(s).",
                paths=[hit.path for hit in note_hits],
                detail=(
                    "The rule looks for several ransom-note phrases together. "
                    "It does not identify a malware family."
                ),
            )
        )

    if extension_hits:
        applied = 0 if suspicious else scale.yara_extension
        score += applied
        signals.append(
            Signal(
                kind="yara_extension",
                weight=applied,
                summary=f"YARA rule {EXTENSION_RULE} matched the file extension.",
                paths=[hit.path for hit in extension_hits],
                detail=(
                    "Points were not added again because the rename signal already counted these files."
                    if applied == 0
                    else "No rename signal was counted, so the extension rule added a small score."
                ),
            )
        )

    if other_hits:
        signals.append(
            Signal(
                kind="yara_other",
                weight=0,
                summary="A YARA rule matched that this scorer does not weight.",
                paths=[hit.path for hit in other_hits],
                detail=", ".join(sorted({hit.rule for hit in other_hits})),
            )
        )

    malicious = score > 0
    backup_like = len(copies) >= settings.bulk_count and not malicious
    if backup_like:
        signals.append(
            Signal(
                kind="bulk_copy",
                weight=0,
                summary=f"{len(copies)} new file(s) match hashes already on the share.",
                paths=[item.path for item in copies],
                detail="Same bytes in a new path look like a copy or backup, not encryption.",
            )
        )
        observations.append(
            f"{len(copies)} files are byte-for-byte copies of files already on the share."
        )
    elif copies and malicious:
        signals.append(
            Signal(
                kind="bulk_copy",
                weight=0,
                summary=(
                    f"{len(copies)} copied file(s) were also present. They did not lower the score."
                ),
                paths=[item.path for item in copies[:20]],
                detail="Copies do not cancel canary, entropy, rename, YARA, or command signals.",
            )
        )

    if len(calm_rewrites) >= settings.bulk_count and not malicious:
        signals.append(
            Signal(
                kind="bulk_rewrite",
                weight=0,
                summary=f"{len(calm_rewrites)} file(s) were rewritten without an entropy jump.",
                paths=[item.path for item in calm_rewrites],
                detail=(
                    "The bytes changed, but they still look like structured text. "
                    "A normal export refresh looks like this."
                ),
            )
        )

    if len(new_high) >= settings.bulk_count and not malicious:
        signals.append(
            Signal(
                kind="new_high_entropy",
                weight=0,
                summary=(
                    f"{len(new_high)} new high-entropy file(s) did not replace a known record."
                ),
                paths=[item.path for item in new_high],
                detail=(
                    "A zip or other archive is often high entropy from the start. "
                    "That is not counted as a known file being encrypted."
                ),
            )
        )

    benign_renames = [
        item
        for item in diff.replacements
        if not item.suspicious_extension and not item.entropy_jump
    ]
    if len(benign_renames) >= settings.rename_burst_count and not malicious:
        signals.append(
            Signal(
                kind="ordinary_rename",
                weight=0,
                summary=(
                    f"{len(benign_renames)} file(s) were renamed without a suspicious "
                    "extension or an entropy jump."
                ),
                paths=[item.new_path for item in benign_renames],
                detail="The new names are not in the extension list and the bytes did not become random.",
            )
        )

    severity = _severity(
        score=score,
        canary=bool(canary_bad),
        shadow=bool(shadow),
        entropy_count=len(entropy_events),
        rename_count=len(suspicious),
        signals=signals,
        config=settings,
    )
    return Decision(
        severity=severity,
        score=score,
        backup_like=backup_like,
        summary=_summary(severity, backup_like, signals),
        signals=signals,
        observations=observations,
    )


def _severity(
    *,
    score: int,
    canary: bool,
    shadow: bool,
    entropy_count: int,
    rename_count: int,
    signals: list[Signal],
    config: DetectorConfig,
) -> str:
    if score <= 0:
        info_kinds = {"bulk_copy", "bulk_rewrite", "new_high_entropy", "ordinary_rename"}
        if any(signal.kind in info_kinds for signal in signals):
            return "info"
        return "none"

    severity = band(score)
    strong_entropy = entropy_count >= config.entropy_jump_count
    strong_rename = rename_count >= config.rename_burst_count
    floor = "none"
    if canary and (shadow or entropy_count > 0 or rename_count > 0):
        floor = "critical"
    elif shadow and (strong_entropy or strong_rename):
        floor = "critical"
    elif strong_entropy and strong_rename:
        floor = "critical"
    elif canary or shadow or strong_entropy or strong_rename:
        floor = "high"
    return max_severity(severity, floor)


def _summary(severity: str, backup_like: bool, signals: list[Signal]) -> str:
    weighted = " ".join(signal.summary for signal in signals if signal.weight > 0)
    if severity == "none":
        return "No file change matched the ransomware checks."
    if backup_like:
        return (
            "New files match hashes already on the share. "
            "This looks like a copy or backup, so it was not scored as ransomware."
        )
    if severity == "info":
        notes = " ".join(signal.summary for signal in signals if signal.weight == 0)
        return f"No ransomware score. {notes}".strip()
    if severity == "critical":
        return (
            "File activity on this share matches several ransomware traits at once. "
            "Treat it as a real alert until a person rules it out. "
            + weighted
        ).strip()
    if severity == "high":
        return (
            "This is a high alert, short of the full pattern used for a critical score. "
            "A person should confirm it before calling a hospital-wide downtime. "
            + weighted
        ).strip()
    return (
        "A limited trait matched. It is worth a look and it is not, by itself, "
        "a hospital-wide incident. "
        + weighted
    ).strip()
