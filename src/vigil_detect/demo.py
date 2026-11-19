from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from vigil_detect.engine import analyze_share
from vigil_detect.models import Incident
from vigil_detect.monitor import ShareMonitor
from vigil_detect.report import write_reports
from vigil_detect.safety import (
    LAB_MARKER_NAME,
    REQUIRED_MARKER_PHRASE,
    SandboxError,
)
from vigil_detect.seed import seed_share
from vigil_detect.simulator import run_simulator
from vigil_detect.snapshot import take_snapshot


@dataclass
class DemoResult:
    incident: Incident
    html_path: Path
    json_path: Path
    elapsed_seconds: float
    transformed: int
    live: bool


def prepare_workdir(workdir: Path) -> None:
    share = workdir / "share"
    marker = share / LAB_MARKER_NAME
    if workdir.exists():
        reusable = (
            marker.is_file()
            and REQUIRED_MARKER_PHRASE in marker.read_text(encoding="utf-8", errors="replace")
        )
        if not reusable:
            raise SandboxError(
                f"{workdir} already exists and is not a vigil lab directory. "
                "Pass a different --workdir."
            )
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)


def run_demo(workdir: Path, timeout: float = 8.0) -> DemoResult:
    prepare_workdir(workdir)
    share = workdir / "share"
    audit_log = workdir / "command_audit.log"
    seeded = seed_share(share, workdir / "canary_manifest.json")
    before = take_snapshot(share)
    monitor = ShareMonitor(share, before, seeded.manifest, audit_log)
    monitor.start()
    started = time.monotonic()
    try:
        time.sleep(0.3)
        simulated = run_simulator(share, audit_log)
        incident = monitor.wait_for_alert(timeout)
    finally:
        monitor.stop()
    if monitor.error is not None and incident is None:
        raise monitor.error
    live = incident is not None
    if incident is None:
        audit_text = ""
        if audit_log.is_file():
            audit_text = audit_log.read_text(encoding="utf-8", errors="replace")
        incident = analyze_share(share, before, seeded.manifest, audit_text=audit_text)
    elapsed = time.monotonic() - started
    json_path, html_path = write_reports(incident, workdir / "reports")
    return DemoResult(
        incident=incident,
        html_path=html_path,
        json_path=json_path,
        elapsed_seconds=elapsed,
        transformed=len(simulated.transformed),
        live=live,
    )
