"""Attack-chain (kill-chain) ordering — plan item 3.9.4."""

from app.intelligence.kill_chain import order_by_kill_chain, tactic_label


def test_phases_returned_in_kill_chain_order():
    ttps = [
        {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "impact"},
        {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "initial-access"},
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "execution"},
    ]
    phases = order_by_kill_chain(ttps)
    assert [p["tactic"] for p in phases] == ["initial-access", "execution", "impact"]
    assert phases[0]["techniques"][0]["technique_id"] == "T1566"


def test_multi_tactic_technique_appears_in_each_phase():
    ttps = [
        {
            "technique_id": "T1055",
            "technique_name": "Process Injection",
            "tactics": ["defense-evasion", "privilege-escalation"],
        },
    ]
    phases = order_by_kill_chain(ttps)
    tactics = [p["tactic"] for p in phases]
    assert "privilege-escalation" in tactics
    assert "defense-evasion" in tactics
    # kill-chain order: privilege-escalation precedes defense-evasion
    assert tactics.index("privilege-escalation") < tactics.index("defense-evasion")


def test_unmapped_technique_collects_into_trailing_phase():
    ttps = [
        {"technique_id": "T9999", "technique_name": "Unknown", "tactic": None},
        {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "initial-access"},
    ]
    phases = order_by_kill_chain(ttps)
    assert phases[-1]["tactic"] is None
    assert phases[-1]["label"] == "Unmapped"
    assert phases[0]["tactic"] == "initial-access"


def test_empty_input_yields_no_phases():
    assert order_by_kill_chain([]) == []


def test_tactic_label_humanizes_slug():
    assert tactic_label("initial-access") == "Initial Access"
    assert tactic_label(None) == "Unmapped"
