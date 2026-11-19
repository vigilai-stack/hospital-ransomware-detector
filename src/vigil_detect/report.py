from __future__ import annotations

import html
import json
from pathlib import Path

from vigil_detect.models import Incident, Signal


def incident_to_dict(incident: Incident) -> dict:
    return {
        "incident_id": incident.incident_id,
        "generated_at": incident.generated_at,
        "tool_version": incident.tool_version,
        "share": incident.share,
        "severity": incident.severity,
        "score": incident.score,
        "backup_like": incident.backup_like,
        "summary": incident.summary,
        "signals": [
            {
                "kind": signal.kind,
                "weight": signal.weight,
                "summary": signal.summary,
                "paths": signal.paths,
                "detail": signal.detail,
            }
            for signal in incident.signals
        ],
        "observations": incident.observations,
        "recommendations": incident.recommendations,
        "actions_taken": incident.actions_taken,
        "clinical_lead": incident.clinical_lead,
        "clinical_actions": incident.clinical_actions,
        "technical_actions": incident.technical_actions,
        "backup_actions": incident.backup_actions,
        "notification_actions": incident.notification_actions,
        "runbook_path": incident.runbook_path,
        "response_mode": incident.response_mode,
        "limitations_note": incident.limitations_note,
    }


def write_reports(incident: Incident, directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "incident-report.json"
    html_path = directory / "incident-report.html"
    json_path.write_text(
        json.dumps(incident_to_dict(incident), indent=2) + "\n",
        encoding="utf-8",
    )
    html_path.write_text(render_html(incident), encoding="utf-8")
    return json_path, html_path


def render_text(incident: Incident) -> str:
    lines = [
        f"Severity: {incident.severity}",
        f"Score: {incident.score}",
        f"Id: {incident.incident_id}",
        f"Share: {incident.share}",
        "",
        incident.summary,
        "",
        "Signals:",
    ]
    if not incident.signals:
        lines.append("- none")
    for signal in incident.signals:
        lines.append(f"- [{signal.weight}] {signal.kind}: {signal.summary}")
    lines.extend(["", "Recommended actions (simulated):"])
    for item in incident.recommendations:
        lines.append(f"- {item}")
    lines.extend(
        [
            "",
            "Actions this program took: none.",
            f"Report mode: {incident.response_mode}",
            f"Runbook: {incident.runbook_path}",
        ]
    )
    return "\n".join(lines) + "\n"


def render_html(incident: Incident) -> str:
    esc = html.escape
    signal_rows = "\n".join(_signal_card(signal) for signal in incident.signals) or (
        "<p>No signals.</p>"
    )
    observations = _list(incident.observations) or "<p>No file-level notes.</p>"
    recommendations = _list(incident.recommendations)
    actions_taken = _list(incident.actions_taken) or "<p>None. The response is a recommendation only.</p>"

    care_block = ""
    if incident.clinical_actions:
        care_block = f"""
        <section>
          <h2>If care systems are down</h2>
          <p>{esc(incident.clinical_lead)}</p>
          <div class="cols">
            <div><h3>Care</h3>{_list(incident.clinical_actions)}</div>
            <div><h3>Technical</h3>{_list(incident.technical_actions)}</div>
            <div><h3>Backups</h3>{_list(incident.backup_actions)}</div>
            <div><h3>Notification</h3>{_list(incident.notification_actions)}</div>
          </div>
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>File-share report — {esc(incident.severity)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f3f6f5;
      --card: #ffffff;
      --text: #1c2423;
      --muted: #4d5c59;
      --line: #d5e0dc;
      --teal: #0f5c57;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 16px/1.5 "Segoe UI", "Helvetica Neue", sans-serif;
    }}
    main {{ max-width: 52rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; }}
    main > header, main > section {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 1.25rem 1.35rem;
      margin-bottom: 1rem;
    }}
    h1 {{ font-size: 1.7rem; line-height: 1.2; margin: 0.2rem 0 0.6rem; }}
    h2 {{ font-size: 1.15rem; margin: 0 0 0.6rem; }}
    h3 {{ font-size: 1rem; margin: 0 0 0.35rem; color: var(--teal); }}
    p {{ margin: 0.4rem 0; }}
    .eyebrow {{
      margin: 0;
      color: var(--teal);
      font-size: 0.82rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }}
    .sev {{
      display: inline-block;
      margin: 0.2rem 0 0.8rem;
      padding: 0.15rem 0.65rem;
      border-radius: 999px;
      font-weight: 700;
      letter-spacing: 0.03em;
      text-transform: uppercase;
    }}
    .sev-critical {{ background: #fde8eb; color: #8d1d34; }}
    .sev-high {{ background: #fdecd8; color: #8a4b08; }}
    .sev-medium {{ background: #fff4cc; color: #6b5600; }}
    .sev-low {{ background: #e5f0fa; color: #1e4e79; }}
    .sev-info {{ background: #e5f4ee; color: #1f5c45; }}
    .sev-none {{ background: #eceff1; color: #333333; }}
    .meta {{ color: var(--muted); font-size: 0.92rem; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.86rem; }}
    .signal {{ border-top: 1px solid var(--line); padding: 0.85rem 0; }}
    .signal:first-of-type {{ border-top: 0; padding-top: 0; }}
    .signal h3 {{
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      margin: 0 0 0.35rem;
      color: var(--text);
      font-size: 1rem;
    }}
    .weight {{ color: var(--teal); white-space: nowrap; }}
    .paths {{ margin: 0.35rem 0 0; padding-left: 1.1rem; }}
    .paths code {{ overflow-wrap: break-word; }}
    ul {{ margin: 0.2rem 0 0.2rem 1.1rem; padding: 0; }}
    li {{ margin: 0.25rem 0; }}
    .cols {{ display: grid; grid-template-columns: 1fr; gap: 1rem; }}
    .banner {{
      background: #f4fbfa;
      border-left: 4px solid var(--teal);
      padding: 0.6rem 0.8rem;
      margin-bottom: 0.8rem;
    }}
    footer {{ color: var(--muted); font-size: 0.9rem; }}
    @media (min-width: 800px) {{
      .cols {{ grid-template-columns: 1fr 1fr; }}
    }}
  </style>
</head>
<body>
<main>
  <header>
    <p class="eyebrow">VigilAI Solutions · Hospital file-share lab</p>
    <h1>File-share report</h1>
    <p class="sev sev-{esc(incident.severity)}">{esc(incident.severity)}</p>
    <p>{esc(incident.summary)}</p>
    <p class="meta">Score {incident.score} · {esc(incident.incident_id)} · {esc(incident.generated_at)}</p>
    <p class="meta">Share <code>{esc(incident.share)}</code></p>
  </header>
  <section>
    <h2>What matched</h2>
    {signal_rows}
  </section>
  <section>
    <h2>Files</h2>
    {observations}
  </section>
  <section>
    <h2>Response</h2>
    <div class="banner">Simulated. This page does not change a network, an account, or a process.</div>
    <h3>Recommended</h3>
    {recommendations}
    <h3>Actions this program took</h3>
    {actions_taken}
    <p class="meta">Response mode: {esc(incident.response_mode)}</p>
  </section>
  {care_block}
  <section>
    <h2>Limits</h2>
    <p>{esc(incident.limitations_note)}</p>
    <p class="meta">Runbook: <code>{esc(incident.runbook_path)}</code></p>
  </section>
  <footer>
    <p>hospital-ransomware-detector {esc(incident.tool_version)}. Synthetic lab data. No malware is included.</p>
  </footer>
</main>
</body>
</html>
"""


def _list(items: list[str]) -> str:
    if not items:
        return ""
    body = "\n".join(f"<li>{html.escape(item)}</li>" for item in items)
    return f"<ul>{body}</ul>"


def _breakable_path(path: str) -> str:
    return html.escape(path).replace("/", "/<wbr>")


def _signal_card(signal: Signal) -> str:
    shown = signal.paths[:8]
    extra = len(signal.paths) - len(shown)
    items = "".join(f"<li><code>{_breakable_path(path)}</code></li>" for path in shown)
    if extra > 0:
        items += f"<li>+{extra} more</li>"
    path_html = f"<ul class='paths'>{items}</ul>" if items else ""
    detail = signal.summary if not signal.detail else f"{signal.summary} {signal.detail}"
    return (
        "<article class='signal'>"
        "<h3>"
        f"<code>{html.escape(signal.kind)}</code>"
        f"<span class='weight'>{signal.weight}</span>"
        "</h3>"
        f"<p>{html.escape(detail)}</p>"
        f"{path_html}"
        "</article>"
    )
