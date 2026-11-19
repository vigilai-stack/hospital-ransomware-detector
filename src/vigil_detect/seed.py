from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from vigil_detect.canary import save_manifest
from vigil_detect.models import Canary, CanaryManifest
from vigil_detect.safety import (
    LAB_MARKER_NAME,
    REQUIRED_MARKER_PHRASE,
    SandboxError,
    assert_outside_share,
)

MARKER_TEXT = (
    f"{REQUIRED_MARKER_PHRASE}\n"
    "No real patient data. Safe to delete this folder.\n"
    "The file simulator runs only in a folder that contains this file and this phrase.\n"
)


@dataclass(frozen=True)
class SeedResult:
    share: Path
    manifest_path: Path
    manifest: CanaryManifest
    file_count: int


def _ehr_csv(batch: str, rows: int = 36) -> str:
    departments = ("Outpatient", "Imaging", "Lab", "Billing Office")
    visits = ("Follow-up", "New visit", "Results review")
    lines = ["record_id,display_name,department,visit_type,note"]
    for index in range(rows):
        lines.append(
            ",".join(
                [
                    f"SYN-{batch}-{index:04d}",
                    f"Example Person {index}",
                    departments[index % len(departments)],
                    visits[index % len(visits)],
                    "Synthetic lab row. Not a real patient.",
                ]
            )
        )
    return "\n".join(lines) + "\n"


def _imaging_note(study_id: str) -> str:
    filler = "Phantom slice placeholder. No image pixels. Lab use only. " * 40
    return (
        f"study_id: {study_id}\n"
        "modality: CT\n"
        "description: Synthetic phantom study for a lab share. Not a DICOM file. No patient.\n"
        "status: demo\n"
        f"{filler}\n"
    )


def _claims(batch: str, rows: int = 36) -> str:
    lines = ["claim_id,payer,amount_usd,status,note"]
    for index in range(rows):
        lines.append(
            f"SYN-CLM-{batch}-{index:04d},Example Payer,125.00,demo,"
            "Synthetic claim. Not a real bill."
        )
    return "\n".join(lines) + "\n"


def _schedule() -> str:
    body = (
        "Outpatient schedule (synthetic, not a patient list)\n"
        "Monday 09:00  Example Clinician A  clinic block\n"
        "Tuesday 09:00  Example Clinician B  results review\n"
        "Friday 15:00  Downtime-binder drill\n"
        "No patient names. No orders. Lab fixture only.\n"
    )
    return body + ("Lab fixture line for file size. Not a patient.\n" * 30)


def _write(share: Path, relative: str, text: str) -> str:
    path = share / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def seed_share(share: Path, manifest_path: Path) -> SeedResult:
    assert_outside_share(share, manifest_path, "The canary manifest")
    share.mkdir(parents=True, exist_ok=True)
    (share / LAB_MARKER_NAME).write_text(MARKER_TEXT, encoding="utf-8")

    normal_files = {
        "EHR_Exports/PatientExport_SYN_2026-09.csv": _ehr_csv("202609"),
        "EHR_Exports/PatientExport_SYN_2026-10.csv": _ehr_csv("202610"),
        "EHR_Exports/PatientExport_SYN_2026-11.csv": _ehr_csv("202611"),
        "Imaging/Study_SYN_1001.txt": _imaging_note("SYN-IMG-1001"),
        "Imaging/Study_SYN_1002.txt": _imaging_note("SYN-IMG-1002"),
        "Imaging/Study_SYN_1003.txt": _imaging_note("SYN-IMG-1003"),
        "Imaging/Study_SYN_1004.txt": _imaging_note("SYN-IMG-1004"),
        "Billing/ClaimsBatch_SYN_441.csv": _claims("441"),
        "Billing/ClaimsBatch_SYN_442.csv": _claims("442"),
        "Billing/ClaimsBatch_SYN_443.csv": _claims("443"),
        "Operations/ClinicSchedule_SYN.txt": _schedule(),
        "Operations/DowntimeBinder_Location_SYN.txt": (
            "Downtime binder location (synthetic)\n"
            "Charge nurse station, bottom drawer, labeled Downtime.\n"
            "Paper order forms, downtime medication sheets, and a call list.\n"
            "This file is a lab placeholder, not a real unit's instructions.\n"
        )
        * 8,
    }
    canary_files = {
        "EHR_Exports/PatientExport_SYN_2026-12.csv": ("ehr", _ehr_csv("202612")),
        "Imaging/Study_SYN_1099.txt": ("imaging", _imaging_note("SYN-IMG-1099")),
        "Billing/ClaimsBatch_SYN_999.csv": ("billing", _claims("999")),
    }

    for relative, text in normal_files.items():
        _write(share, relative, text)

    canaries: list[Canary] = []
    for relative, (role, text) in canary_files.items():
        digest = _write(share, relative, text)
        canaries.append(Canary(rel_path=relative, sha256=digest, role=role))

    manifest = CanaryManifest(canaries=canaries)
    save_manifest(manifest, manifest_path)
    if not (share / LAB_MARKER_NAME).is_file():
        raise SandboxError("Lab marker was not written.")
    return SeedResult(
        share=share,
        manifest_path=manifest_path,
        manifest=manifest,
        file_count=len(normal_files) + len(canary_files),
    )
