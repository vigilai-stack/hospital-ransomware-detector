from __future__ import annotations

from dataclasses import dataclass

from vigil_detect.models import Signal

LIMITATIONS_NOTE = (
    "This is a lab tool. It was not tested on real malware. "
    "A match is a clue for a person to review, not proof of ransomware and not "
    "identification of a malware family. Thresholds are defaults for a small synthetic "
    "share, not measured false-positive rates from a hospital network. "
    "No process was killed and no device was isolated by this program."
)

ISOLATE_RECOMMENDATION = (
    "Recommend isolating the host that writes to this share from the clinical network. "
    "This program did not change a firewall, a switch port, or an account."
)

SUSPEND_RECOMMENDATION = (
    "Recommend suspending the process that is renaming or rewriting these files, "
    "using your endpoint tools. This program did not kill or suspend any process."
)

CLINICAL_LEAD = (
    "Use the care list only if patient-care systems are actually unavailable. "
    "A file alert by itself does not mean the EHR is down."
)

CLINICAL_ACTIONS = (
    "Follow the facility downtime policy if it differs from this list.",
    "Keep emergency and inpatient care going. Postpone elective work only if clinical leadership decides to.",
    "Tell the charge nurse and the department lead what is unavailable, in plain words.",
    "Use the downtime forms for orders, notes, and registration while the EHR is down.",
    "Read back verbal orders. Use the downtime medication process for doses. Do not invent a dose from memory.",
    "If the lab or imaging system is down, report critical results by phone using the existing critical-value process.",
    "Do not reboot a device that is supporting a patient unless the clinical team agrees.",
    "Ask biomedical engineering before changing pumps, monitors, or imaging devices.",
)

TECHNICAL_ACTIONS = (
    "Name an incident lead and a clinical lead.",
    "Preserve logs and this report before rebuilding machines.",
    "Disconnect the suspected workstation from the clinical network if the incident lead agrees.",
    "Disable compromised accounts. Reset passwords after the source of the activity is understood.",
    "Leave unaffected clinical systems in service.",
    "Check whether file shares are still being changed before you reconnect anything.",
)

BACKUP_ACTIONS = (
    "Find the newest backup taken before these file changes.",
    "Treat a backup that was online and writable as untrusted until you check it.",
    "Restore onto an isolated machine first, not back onto the live share.",
    "Confirm a sample of clinical files opens and looks right before you call the restore done.",
    "After the record system is back, reconcile paper downtime orders under the facility's usual process.",
)

NOTIFICATION_ACTIONS = (
    "Notify the privacy officer, compliance, and the executive on call.",
    "Do not post about the incident on social media.",
    "Give staff a short factual update: what is down, to use downtime procedures, and who the incident lead is.",
    "Whether patients or regulators must be notified is a decision for the privacy officer and counsel. "
    "The HIPAA Breach Notification Rule is the usual U.S. reference, including its 60-day outer timeline "
    "for a breach of unsecured protected health information. Confirm the current rule before you rely on it.",
    "Contacting CISA, law enforcement, or a cyber insurer is a leadership decision. This program does not send those notices.",
    "Paying a ransom is not a step in this runbook. CISA's public guidance discourages payment. Leadership and counsel decide.",
)


@dataclass
class ResponsePlan:
    recommendations: list[str]
    actions_taken: list[str]
    clinical_lead: str
    clinical_actions: list[str]
    technical_actions: list[str]
    backup_actions: list[str]
    notification_actions: list[str]
    response_mode: str = "simulated"


def build_response(severity: str, signals: list[Signal]) -> ResponsePlan:
    kinds = {signal.kind for signal in signals}
    recommendations: list[str] = []
    clinical: list[str] = []
    technical: list[str] = []
    backup: list[str] = []
    notification: list[str] = []
    clinical_lead = ""

    if severity == "critical":
        recommendations.extend(
            [
                ISOLATE_RECOMMENDATION,
                SUSPEND_RECOMMENDATION,
                "Do not restore backups onto this share until the writing has stopped "
                "and a restore has been tested on an isolated machine.",
                "Keep this report. It is a starting note, not a forensic image.",
            ]
        )
    elif severity == "high":
        recommendations.append(
            "Recommend containing the workstation or account that changed these files, "
            "after a person confirms the change was not authorized. "
            "This program did not isolate a host or disable an account."
        )
        file_traits = {"entropy_jump", "suspicious_rename", "shadow_command", "yara_match"}
        if "canary_tamper" in kinds and not (kinds & file_traits):
            recommendations.append(
                "A canary file changed and the other ransomware traits did not. "
                "Confirm whether a person edited it before you declare an incident."
            )
        recommendations.append("Keep this report. It is a starting note, not a forensic image.")
    elif severity == "medium":
        recommendations.append(
            "Review the matched files. Containment and downtime are not recommended from this score alone."
        )
    elif severity == "low":
        recommendations.append(
            "Note the file and check it when you have time. No containment action is recommended."
        )
    else:
        recommendations.append("No containment action.")

    if severity in {"high", "critical"}:
        clinical_lead = CLINICAL_LEAD
        clinical = list(CLINICAL_ACTIONS)
        technical = list(TECHNICAL_ACTIONS)
        backup = list(BACKUP_ACTIONS)
        notification = list(NOTIFICATION_ACTIONS)

    return ResponsePlan(
        recommendations=recommendations,
        actions_taken=[],
        clinical_lead=clinical_lead,
        clinical_actions=clinical,
        technical_actions=technical,
        backup_actions=backup,
        notification_actions=notification,
    )
