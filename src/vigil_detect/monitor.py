from __future__ import annotations

import threading
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from vigil_detect.engine import analyze_share
from vigil_detect.models import CanaryManifest, DetectorConfig, Incident, Snapshot


class ShareMonitor:
    """Watch a lab share and score it after a short quiet period.

    The watcher only decides when to look. The score comes from a snapshot
    diff, so coalesced file events change the timing, not the rules.
    """

    def __init__(
        self,
        share: Path,
        before: Snapshot,
        manifest: CanaryManifest,
        audit_log: Path,
        config: DetectorConfig | None = None,
        debounce_seconds: float = 0.4,
    ) -> None:
        self.share = share
        self.before = before
        self.manifest = manifest
        self.audit_log = audit_log
        self.config = config or DetectorConfig()
        self.debounce_seconds = debounce_seconds
        self.error: Exception | None = None
        self._incident: Incident | None = None
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._analyze_lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._observer: Observer | None = None

    @property
    def incident(self) -> Incident | None:
        with self._lock:
            return self._incident

    def start(self) -> None:
        handler = _Handler(self._schedule)
        observer = Observer()
        observer.schedule(handler, str(self.share), recursive=True)
        audit_parent = self.audit_log.parent
        if audit_parent.exists():
            observer.schedule(handler, str(audit_parent), recursive=False)
        observer.start()
        self._observer = observer

    def stop(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=3)
            self._observer = None

    def wait_for_alert(self, timeout: float) -> Incident | None:
        self._event.wait(timeout)
        return self.incident

    def _schedule(self, path: str) -> None:
        if not self._interesting(path):
            return
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            timer = threading.Timer(self.debounce_seconds, self._analyze)
            timer.daemon = True
            self._timer = timer
            timer.start()

    def _interesting(self, raw_path: str) -> bool:
        candidate = Path(raw_path)
        if candidate.name.startswith(".") or candidate.name.endswith(".vigilpart"):
            return False
        try:
            resolved = candidate.resolve()
        except OSError:
            return False
        audit = self.audit_log.resolve()
        share = self.share.resolve()
        if resolved == audit:
            return True
        return resolved == share or share in resolved.parents

    def _analyze(self) -> None:
        with self._analyze_lock:
            try:
                audit_text = ""
                if self.audit_log.is_file():
                    audit_text = self.audit_log.read_text(encoding="utf-8", errors="replace")
                incident = analyze_share(
                    self.share,
                    self.before,
                    self.manifest,
                    audit_text=audit_text,
                    config=self.config,
                )
            except Exception as exc:
                self.error = exc
                return
        with self._lock:
            self._incident = incident
        if incident.severity in {"high", "critical"}:
            self._event.set()


class _Handler(FileSystemEventHandler):
    def __init__(self, callback) -> None:
        self._callback = callback

    def on_any_event(self, event) -> None:
        if getattr(event, "is_directory", False):
            return
        self._callback(str(event.src_path))
