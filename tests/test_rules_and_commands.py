from __future__ import annotations

from pathlib import Path

from vigil_detect.commands import scan_text
from vigil_detect.simulator import SHADOW_DEMO_COMMAND
from vigil_detect.yara_scan import load_rules, rules_file, scan_bytes, scan_tree


def test_crafted_note_matches_and_benign_files_do_not():
    rules = load_rules()
    root = rules_file().parents[1] / "samples"
    hits = scan_tree(root, rules)
    matched = {(hit.rule, hit.path) for hit in hits}
    assert ("Ransom_Note_Traits", "crafted_traits/readme_restore_lab.txt") in matched
    benign = [hit for hit in hits if hit.path.startswith("benign_clinical/")]
    assert benign == []
    two = [hit for hit in hits if hit.path.endswith("two_phrases_should_not_match.txt")]
    assert two == []


def test_rules_file_does_not_match_itself():
    path = rules_file()
    hits = scan_bytes(load_rules(), path.read_bytes(), path.name)
    assert hits == []


def test_extension_rule_matches_locked_and_ignores_csv(tmp_path: Path):
    rules = load_rules()
    locked = scan_bytes(rules, b"not a program", "drop.locked")
    csv_hit = scan_bytes(rules, b"not a program", "export.csv")
    assert [hit.rule for hit in locked] == ["Suspicious_Extension_Trait"]
    assert csv_hit == []


def test_shadow_deletion_text_matches_and_list_command_does_not():
    hits = scan_text(
        f"command={SHADOW_DEMO_COMMAND} executed=false\n",
        source="audit-log",
    )
    assert [hit.pattern_id for hit in hits] == ["vssadmin_delete_shadows"]
    assert "executed=false" in hits[0].note

    listed = scan_text("vssadmin.exe list shadows\n", source="audit-log")
    assert listed == []

    backup = scan_text("backup job copy files status=ok\n", source="audit-log")
    assert backup == []


def test_other_recovery_suppression_lines_match():
    text = "\n".join(
        [
            "wmic.exe shadowcopy delete",
            r"bcdedit /set {default} recoveryenabled no",
            "wbadmin delete catalog -quiet",
        ]
    )
    found = {hit.pattern_id for hit in scan_text(text, source="fixture")}
    assert found == {
        "wmic_shadowcopy_delete",
        "bcdedit_recovery_off",
        "wbadmin_delete_catalog",
    }


def test_uppercase_vssadmin_matches():
    hits = scan_text("VSSADMIN.EXE DELETE SHADOWS /all /quiet\n", source="audit-log")
    assert [hit.pattern_id for hit in hits] == ["vssadmin_delete_shadows"]
