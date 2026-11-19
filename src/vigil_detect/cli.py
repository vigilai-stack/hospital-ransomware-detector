from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vigil_detect import __version__
from vigil_detect.canary import load_manifest
from vigil_detect.demo import run_demo
from vigil_detect.engine import analyze_share
from vigil_detect.exercises import run_backup_check
from vigil_detect.monitor import ShareMonitor
from vigil_detect.report import render_text, write_reports
from vigil_detect.safety import SandboxError, assert_outside_share
from vigil_detect.seed import seed_share
from vigil_detect.simulator import restore_share, run_simulator
from vigil_detect.snapshot import load_snapshot, save_snapshot, take_snapshot
from vigil_detect.yara_scan import load_rules, rules_file, scan_tree


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vigil-detect",
        description="Lab detector for ransomware-like activity on a simulated hospital file share.",
    )
    parser.add_argument("--version", action="version", version=f"vigil-detect {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="Seed a lab share, run the safe simulator, and write a report.")
    demo.add_argument("--workdir", type=Path, default=Path("lab-data"))

    sub.add_parser(
        "check-backup",
        help="Copy lab files the way a backup would and show the score.",
    )

    scan = sub.add_parser("scan-rules", help="Run the YARA rules against sample files.")
    scan.add_argument("--path", type=Path, default=None)

    seed = sub.add_parser("seed", help="Create a synthetic share and a canary manifest.")
    seed.add_argument("--share", type=Path, required=True)
    seed.add_argument("--manifest", type=Path, required=True)

    baseline = sub.add_parser("baseline", help="Save a snapshot of a clean share.")
    baseline.add_argument("--share", type=Path, required=True)
    baseline.add_argument("--out", type=Path, required=True)

    simulate = sub.add_parser(
        "simulate",
        help="Run the reversible lab simulator inside a marked share.",
    )
    simulate.add_argument("--share", type=Path, required=True)
    simulate.add_argument("--audit", type=Path, required=True)

    restore = sub.add_parser("restore", help="Undo lab-simulator files inside a marked share.")
    restore.add_argument("--share", type=Path, required=True)

    analyze = sub.add_parser("analyze", help="Compare a share to a saved baseline and write a report.")
    _add_analysis_args(analyze)

    watch = sub.add_parser("watch", help="Watch a share until an alert or the time limit.")
    _add_analysis_args(watch)
    watch.add_argument("--seconds", type=float, default=30.0)

    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except (SandboxError, FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _add_analysis_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--share", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "demo":
        return _demo(args.workdir)
    if args.command == "check-backup":
        return _backup()
    if args.command == "scan-rules":
        return _scan_rules(args.path)
    if args.command == "seed":
        return _seed(args.share, args.manifest)
    if args.command == "baseline":
        return _baseline(args.share, args.out)
    if args.command == "simulate":
        return _simulate(args.share, args.audit)
    if args.command == "restore":
        return _restore(args.share)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "watch":
        return _watch(args)
    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 1


def _demo(workdir: Path) -> int:
    result = run_demo(workdir)
    print(render_text(result.incident), end="")
    print(f"Files transformed by the lab simulator: {result.transformed}")
    print(f"Detection time: {result.elapsed_seconds:.2f}s")
    print(f"Live monitor alert: {str(result.live).lower()}")
    print(f"HTML report: {result.html_path}")
    print(f"JSON report: {result.json_path}")
    if result.live and result.incident.severity == "critical":
        return 0
    print(
        "The demo expected a critical alert. See the report for the score that was produced.",
        file=sys.stderr,
    )
    return 2


def _backup() -> int:
    incident, copied = run_backup_check()
    print(render_text(incident), end="")
    print(f"Files copied: {copied}")
    if incident.backup_like and incident.severity in {"none", "info"} and incident.score == 0:
        print("Bulk copy was not treated as ransomware.")
        return 0
    print("The backup check produced a ransomware score.", file=sys.stderr)
    return 2


def _scan_rules(path: Path | None) -> int:
    root = path or rules_file().parents[1] / "samples"
    if not root.is_dir():
        raise FileNotFoundError(f"Sample directory not found: {root}")
    hits = scan_tree(root, load_rules())
    if not hits:
        print(f"No YARA matches under {root}")
        return 0
    for hit in hits:
        print(f"{hit.rule}\t{hit.path}")
    return 0


def _seed(share: Path, manifest: Path) -> int:
    result = seed_share(share, manifest)
    print(f"Seeded {result.file_count} synthetic files in {result.share}")
    print(f"Canary manifest: {result.manifest_path}")
    return 0


def _baseline(share: Path, out: Path) -> int:
    assert_outside_share(share, out, "The baseline")
    snapshot = take_snapshot(share)
    save_snapshot(snapshot, out)
    print(f"Baseline of {len(snapshot.files)} files written to {out}")
    return 0


def _simulate(share: Path, audit: Path) -> int:
    result = run_simulator(share, audit)
    print(f"Transformed {len(result.transformed)} files inside {share.resolve()}")
    print(f"Command text appended to {result.audit_path} (executed={str(result.executed).lower()})")
    print("No system command was run.")
    return 0


def _restore(share: Path) -> int:
    result = restore_share(share)
    print(f"Restored {len(result.restored)} files.")
    if result.skipped:
        print(f"Left untouched: {len(result.skipped)}")
    if result.note_removed:
        print("Removed the lab simulator note.")
    return 0


def _load_inputs(args: argparse.Namespace):
    assert_outside_share(args.share, args.baseline, "The baseline")
    assert_outside_share(args.share, args.manifest, "The canary manifest")
    assert_outside_share(args.share, args.audit, "The command audit log")
    assert_outside_share(args.share, args.report_dir, "The report directory")
    before = load_snapshot(args.baseline)
    manifest = load_manifest(args.manifest)
    audit_text = ""
    if args.audit.exists():
        audit_text = args.audit.read_text(encoding="utf-8", errors="replace")
    return before, manifest, audit_text


def _analyze(args: argparse.Namespace) -> int:
    before, manifest, audit_text = _load_inputs(args)
    incident = analyze_share(args.share, before, manifest, audit_text=audit_text)
    _emit(incident, args.report_dir)
    return 0


def _watch(args: argparse.Namespace) -> int:
    before, manifest, _audit_text = _load_inputs(args)
    monitor = ShareMonitor(args.share, before, manifest, args.audit)
    monitor.start()
    try:
        incident = monitor.wait_for_alert(args.seconds)
    finally:
        monitor.stop()
    if monitor.error is not None and incident is None:
        raise monitor.error
    if incident is None:
        audit_text = ""
        if args.audit.exists():
            audit_text = args.audit.read_text(encoding="utf-8", errors="replace")
        incident = analyze_share(args.share, before, manifest, audit_text=audit_text)
    _emit(incident, args.report_dir)
    return 0


def _emit(incident, report_dir: Path) -> None:
    json_path, html_path = write_reports(incident, report_dir)
    print(render_text(incident), end="")
    print(f"HTML report: {html_path}")
    print(f"JSON report: {json_path}")
