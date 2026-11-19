from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = ("none", "info", "low", "medium", "high", "critical")

SUSPICIOUS_EXTENSIONS = (
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypto",
    ".ryk",
    ".wncry",
)


def max_severity(left: str, right: str) -> str:
    if SEVERITY_ORDER.index(left) >= SEVERITY_ORDER.index(right):
        return left
    return right


@dataclass(frozen=True)
class DetectorConfig:
    """Defaults sized for a small lab share, not a hospital traffic study."""

    entropy_low: float = 6.0
    entropy_high: float = 7.2
    min_entropy_delta: float = 2.0
    rename_burst_count: int = 5
    entropy_jump_count: int = 3
    bulk_count: int = 5
    max_scan_bytes: int = 2_000_000
    max_hash_bytes: int = 5_000_000
    suspicious_extensions: tuple[str, ...] = SUSPICIOUS_EXTENSIONS


@dataclass(frozen=True)
class Weights:
    canary: int = 60
    shadow: int = 35
    entropy_each: int = 10
    entropy_cap: int = 30
    rename_burst: int = 25
    rename_partial: int = 10
    yara_note: int = 25
    yara_extension: int = 10


@dataclass
class FileFact:
    rel_path: str
    size: int
    entropy: float
    sha256: str
    extension: str


@dataclass
class Snapshot:
    files: dict[str, FileFact]
    skipped: list[str] = field(default_factory=list)

    def hashes(self) -> set[str]:
        return {item.sha256 for item in self.files.values()}


@dataclass(frozen=True)
class Canary:
    rel_path: str
    sha256: str
    role: str


@dataclass
class CanaryManifest:
    canaries: list[Canary]
    version: int = 1


@dataclass(frozen=True)
class CanaryStatus:
    rel_path: str
    role: str
    status: str


@dataclass(frozen=True)
class Replacement:
    old_path: str
    new_path: str
    old_entropy: float
    new_entropy: float
    new_extension: str
    entropy_jump: bool
    suspicious_extension: bool


@dataclass(frozen=True)
class InPlaceChange:
    path: str
    old_entropy: float
    new_entropy: float
    entropy_jump: bool


@dataclass(frozen=True)
class AddedFile:
    path: str
    entropy: float
    extension: str
    sha256: str
    copy_of_existing: bool
    suspicious_extension: bool
    high_entropy: bool


@dataclass
class DiffResult:
    replacements: list[Replacement]
    in_place: list[InPlaceChange]
    added: list[AddedFile]
    unpaired_removed: list[str]
    canaries: list[CanaryStatus]


@dataclass(frozen=True)
class YaraHit:
    rule: str
    path: str
    severity: str
    description: str


@dataclass(frozen=True)
class CommandHit:
    pattern_id: str
    description: str
    source: str
    excerpt: str
    note: str = ""


@dataclass
class Signal:
    kind: str
    weight: int
    summary: str
    paths: list[str] = field(default_factory=list)
    detail: str = ""


@dataclass
class Decision:
    severity: str
    score: int
    backup_like: bool
    summary: str
    signals: list[Signal]
    observations: list[str]


@dataclass
class Incident:
    incident_id: str
    generated_at: str
    tool_version: str
    share: str
    severity: str
    score: int
    backup_like: bool
    summary: str
    signals: list[Signal]
    observations: list[str]
    recommendations: list[str]
    actions_taken: list[str]
    clinical_lead: str
    clinical_actions: list[str]
    technical_actions: list[str]
    backup_actions: list[str]
    notification_actions: list[str]
    runbook_path: str
    response_mode: str
    limitations_note: str
