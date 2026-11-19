# Hospital ransomware downtime runbook

This is a checklist for a clinic or hospital file-share incident. It is not a medical order set, and it is not legal advice. If the facility already has a downtime policy, follow that policy when the two differ.

The lab tool that sits next to this document can raise an alert. It does not isolate a machine, kill a process, or decide that a breach occurred.

## 1. Care comes first

The first question is how patients in the building will be cared for. Reimaging a server is later.

- Name a clinical lead (charge nurse, department manager, or the person the facility already uses) and an incident lead.
- Tell them, in plain words, which systems are unavailable. Avoid guessing.
- Keep emergency care and current inpatients moving. Postpone elective visits or cases only if clinical leadership decides to.
- Do not reboot a device that is supporting a patient unless the clinical team agrees.
- Biomedical engineering handles pumps, monitors, and imaging devices. Do not treat those like office PCs.

## 2. Downtime documentation

Use the downtime binder for the unit. In this lab, a placeholder file only says where a binder would be. A real unit already knows its own drawer, forms, and call list.

While the record system is down:

- Register patients on the downtime form.
- Write orders on the downtime order form. Read verbal orders back.
- Use the downtime medication process for doses. Do not invent a dose from memory if a downtime sheet or other approved source is available.
- File paper notes so they can be reconciled after the system returns. Reconciliation follows the facility's usual process, not this document.
- If the lab system is down, report critical results by phone using the existing critical-value process.
- If imaging is down, use the phone path the department already has for stat reads. Do not invent a new one during the incident.

Put a short sign at registration: which systems are down, that care is continuing on paper, and who to call.

## 3. Staff message

Keep it short.

> Clinical systems are down. Use downtime procedures. Patient care continues. Do not connect personal devices to the hospital network. Questions go to the incident lead.

Do not post about the incident on social media. Do not guess about the cause in a waiting room.

## 4. Containment

Do this after someone is clearly covering patient care, or at the same time if you have two people.

- The incident lead decides whether to disconnect the suspected workstation or segment. Do it at the switch or with the endpoint tool the facility already owns. This project does not do it.
- If an endpoint agent shows one process doing the mass renames, suspend that process with the endpoint tool. This project does not send a kill signal.
- Disable accounts that are part of the activity. Reset passwords after you understand the source.
- Leave systems that are still healthy in service. A wide shutdown can hurt care more than the file share does.
- Keep the affected machines powered if you can do that safely and leadership wants the logs. Do not wipe disks as a first step.
- Preserve this tool's report, file-server logs, and endpoint logs before anyone rebuilds the machine. The report is a starting note, not a forensic image.

Attackers sometimes try to delete recovery points and volume shadow copies. Confirm that in the endpoint or server logs. This runbook is not the place those commands are run, and this lab does not run them.

## 5. Backups

- Find the newest backup taken before the file changes started. The alert time is when this tool noticed, which can be later than the first bad write.
- A backup that was online and writable may have been changed too. Do not trust it until someone checks it.
- Restore onto an isolated machine first. Do not copy a restore back onto a share that is still being rewritten.
- Open a sample of clinical files. Confirm they look like records and not scrambled bytes.
- Billing systems wait. Pharmacy, the legal medical record, and identity services matter more for the first hours.

## 6. Who to notify inside the building

- Incident lead and clinical lead
- Privacy officer and compliance
- Executive on call
- Biomedical engineering, if devices are involved
- Health information management, for the paper-to-electronic reconciliation later
- Communications, if patients in the building need a script

## 7. Who might be notified outside

This software does not send these notices. Leadership decides.

- Patients, regulators, and the media: the privacy officer and counsel decide whether the HIPAA Breach Notification Rule applies. That rule is the usual U.S. reference. It talks about notice without unreasonable delay and, for a breach of unsecured protected health information, an outer timeline of 60 days from discovery. Confirm the current text before you rely on it. This checklist cannot decide that a breach happened.
- Law enforcement, CISA, or a cyber insurer: a leadership decision. Many hospitals call them. This document does not require it and does not make the call.
- Payment to an attacker is not a step here. CISA's public guidance discourages paying. It also does not make the files come back. Leadership and counsel decide.

## 8. Coming back up

- Reconnect shares only after the rewriting has stopped.
- Bring back identity and core network, then pharmacy and the record system, then lab and imaging interfaces, then billing.
- Watch the share. If the same pattern starts again, disconnect and stop the restore.
- Enter paper orders into the record system under the facility's reconciliation process.
- Hold a short after-action review: what failed, what the downtime binder was missing, and what to change before the next drill.

## 9. What this lab project will not do

- It will not declare a breach.
- It will not tell a clinician how to treat a patient.
- It will not replace an endpoint product, offline backups, or allowlisting.
- It was not tested on real malware. A drill with the safe simulator is not a measure of detection on a live ward.
