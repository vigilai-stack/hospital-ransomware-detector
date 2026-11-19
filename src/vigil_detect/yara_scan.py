from __future__ import annotations

from pathlib import Path

import yara

from vigil_detect.locate import find_project_file
from vigil_detect.models import YaraHit

_COMPILED: dict[str, yara.Rules] = {}


def rules_file() -> Path:
    return find_project_file("rules/hospital_ransomware_traits.yar")


def load_rules(path: Path | None = None) -> yara.Rules:
    rules_path = (path or rules_file()).resolve()
    key = str(rules_path)
    cached = _COMPILED.get(key)
    if cached is not None:
        return cached
    try:
        compiled = yara.compile(
            filepath=str(rules_path),
            externals={"filename": "", "extension": ""},
        )
    except yara.Error as exc:
        raise RuntimeError(f"Could not compile YARA rules at {rules_path}: {exc}") from exc
    _COMPILED[key] = compiled
    return compiled


def scan_bytes(rules: yara.Rules, data: bytes, rel_path: str) -> list[YaraHit]:
    base_name = Path(rel_path).name
    extension = Path(rel_path).suffix.lower()
    matches = rules.match(
        data=data,
        externals={"filename": base_name, "extension": extension},
    )
    hits: list[YaraHit] = []
    for match in matches:
        meta = match.meta or {}
        hits.append(
            YaraHit(
                rule=match.rule,
                path=rel_path,
                severity=str(meta.get("severity", "")),
                description=str(meta.get("description", "")),
            )
        )
    return hits


def scan_tree(root: Path, rules: yara.Rules | None = None) -> list[YaraHit]:
    compiled = rules or load_rules()
    hits: list[YaraHit] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        data = path.read_bytes()
        relative = path.relative_to(root).as_posix()
        hits.extend(scan_bytes(compiled, data, relative))
    return hits
