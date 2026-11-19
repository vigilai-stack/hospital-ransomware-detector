from __future__ import annotations

from vigil_detect.cli import main
from vigil_detect.demo import run_demo
from vigil_detect.report import render_html
from vigil_detect.response import ISOLATE_RECOMMENDATION, SUSPEND_RECOMMENDATION


def test_demo_live_monitor_reaches_critical(tmp_path):
    result = run_demo(tmp_path / "lab-data")
    incident = result.incident
    kinds = {signal.kind for signal in incident.signals}
    assert result.live is True
    assert result.elapsed_seconds < 8
    assert incident.severity == "critical"
    assert incident.score >= 70
    assert incident.response_mode == "simulated"
    assert incident.actions_taken == []
    assert {"canary_tamper", "shadow_command", "entropy_jump", "suspicious_rename", "yara_match"} <= kinds
    assert ISOLATE_RECOMMENDATION in incident.recommendations
    assert SUSPEND_RECOMMENDATION in incident.recommendations
    assert result.html_path.is_file()
    assert result.json_path.is_file()
    page = result.html_path.read_text(encoding="utf-8")
    assert "critical" in page
    assert "Simulated. This page does not change a network" in page
    assert "No process was killed" in page


def test_report_escapes_html():
    result_html = render_html(_unsafe_incident())
    assert "<script>" not in result_html
    assert "&lt;script&gt;" in result_html


def test_cli_demo_and_backup(tmp_path):
    assert main(["demo", "--workdir", str(tmp_path / "demo")]) == 0
    assert main(["check-backup"]) == 0
    assert main(["scan-rules"]) == 0


def _unsafe_incident():
    from vigil_detect.models import Incident

    return Incident(
        incident_id="INC-test",
        generated_at="2026-11-19T00:00:00+00:00",
        tool_version="0.1.0",
        share="<script>alert(1)</script>",
        severity="low",
        score=1,
        backup_like=False,
        summary="<script>alert(1)</script>",
        signals=[],
        observations=[],
        recommendations=["No containment action."],
        actions_taken=[],
        clinical_lead="",
        clinical_actions=[],
        technical_actions=[],
        backup_actions=[],
        notification_actions=[],
        runbook_path="runbook",
        response_mode="simulated",
        limitations_note="limits",
    )
