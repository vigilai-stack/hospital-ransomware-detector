from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from vigil_detect import __version__
from vigil_detect.commands import SCRIPT_EXTENSIONS, scan_text
from vigil_detect.diffing import diff_snapshots
from vigil_detect.locate import find_project_file
from vigil_detect.models import (
    CanaryManifest,
    CommandHit,
    DetectorConfig,
    Incident,
    Snapshot,
    YaraHit,
)
from vigil_detect.response import LIMITATIONS_NOTE, build_response
from vigil_detect.scoring import decide
from vigil_detect.snapshot import take_snapshot
from vigil_detect.yara_scan import load_rules, scan_bytes


def _changed_paths(before: Snapshot, after: Snapshot) -> list[str]:
    changed: list[str] = []
    for rel_path, fact in after.files.items():
        previous = before.files.get(rel_path)
        if previous is None or previous.sha256 != fact.sha256:
            changed.append(rel_path)
    return changed


def _new_incident_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"INC-{stamp}-{uuid.uuid4().hex[:6]}"


def analyze_snapshot(
    *,
    before: Snapshot,
    after: Snapshot,
    manifest: CanaryManifest,
    yara_hits: list[YaraHit],
    command_hits: list[CommandHit],
    share: str,
    config: DetectorConfig | None = None,
    runbook_path: str = "",
) -> Incident:
    settings = config or DetectorConfig()
    diff = diff_snapshots(before, after, manifest, settings)
    decision = decide(diff, yara_hits, command_hits, settings)
    plan = build_response(decision.severity, decision.signals)
    return Incident(
        incident_id=_new_incident_id(),
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        tool_version=__version__,
        share=share,
        severity=decision.severity,
        score=decision.score,
        backup_like=decision.backup_like,
        summary=decision.summary,
        signals=decision.signals,
        observations=decision.observations,
        recommendations=plan.recommendations,
        actions_taken=plan.actions_taken,
        clinical_lead=plan.clinical_lead,
        clinical_actions=plan.clinical_actions,
        technical_actions=plan.technical_actions,
        backup_actions=plan.backup_actions,
        notification_actions=plan.notification_actions,
        runbook_path=runbook_path,
        response_mode=plan.response_mode,
        limitations_note=LIMITATIONS_NOTE,
    )


def analyze_share(
    share: Path,
    before: Snapshot,
    manifest: CanaryManifest,
    audit_text: str = "",
    config: DetectorConfig | None = None,
    rules_path: Path | None = None,
    runbook_path: Path | None = None,
) -> Incident:
    settings = config or DetectorConfig()
    root = share.resolve()
    after = take_snapshot(root, settings)
    rules = load_rules(rules_path)
    yara_hits: list[YaraHit] = []
    command_hits = scan_text(audit_text, source="audit-log") if audit_text else []

    for rel_path in _changed_paths(before, after):
        file_path = root / rel_path
        if not file_path.is_file() or file_path.is_symlink():
            continue
        data = file_path.read_bytes()
        scanned = data[: settings.max_scan_bytes]
        yara_hits.extend(scan_bytes(rules, scanned, rel_path))
        if file_path.suffix.lower() in SCRIPT_EXTENSIONS:
            command_hits.extend(
                scan_text(scanned.decode("utf-8", errors="replace"), source=rel_path)
            )

    if runbook_path is None:
        try:
            runbook_path = find_project_file("runbooks/hospital_ransomware_downtime.md")
        except FileNotFoundError:
            runbook_path = Path("runbooks/hospital_ransomware_downtime.md")

    return analyze_snapshot(
        before=before,
        after=after,
        manifest=manifest,
        yara_hits=yara_hits,
        command_hits=command_hits,
        share=str(root),
        config=settings,
        runbook_path=str(runbook_path),
    )
