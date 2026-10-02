"""parse_ai_json repairs the escapes small models get wrong on Windows paths."""

from app.ai.engine import parse_ai_json


def test_parse_ai_json_repairs_illegal_backslash_escapes():
    raw = (
        '{"iocs": [{"kind": "path", "value": "C:\\ProgramData\\AnyDesk.exe"}, '
        '{"kind": "cmdline", "value": "reg add HKCU\\Software\\x /v y"}]}'
    )
    parsed = parse_ai_json(raw)
    assert parsed.get("_extraction_status") is None
    assert parsed["iocs"][0]["value"] == "C:\\ProgramData\\AnyDesk.exe"
    assert parsed["iocs"][1]["value"] == "reg add HKCU\\Software\\x /v y"


def test_parse_ai_json_keeps_valid_escapes_and_fences():
    assert parse_ai_json('```json\n{"a": "line\\nbreak \\"quoted\\" \\\\ back"}\n```') == {
        "a": 'line\nbreak "quoted" \\ back'
    }
    assert parse_ai_json('{"a": [1, 2,]}') == {"a": [1, 2]}
    assert parse_ai_json('{"a": [1, 2').get("_extraction_status") == "parse_error"


def test_parse_ai_json_salvages_a_response_cut_off_mid_array():
    from app.ai.engine import parse_ai_json

    sha = "a" * 64
    head = (
        '{"summary": "s", "iocs": [{"kind": "sha256", "value": "' + sha + '", "role": "payload", "evidence": "e"}, '
        '{"kind": "domain", "value": "c2.example-bad.net", "role": "c2", "evidence": "e"}], '
        '"scripts": [], "relationships": [], "ttps": [{"technique_id": "T1059.001", "source_text": "ok"}, '
        '{"technique_id": "T1547.001", "source_text": "cut right he'
    )
    out = parse_ai_json(head)
    assert out.get("_truncated") is True
    assert [i["value"] for i in out["iocs"]] == [sha, "c2.example-bad.net"]
    assert [t["technique_id"] for t in out["ttps"]] == ["T1059.001"]
    assert "_extraction_status" not in out

    # Cut inside a string value in the middle of an ioc: the complete ones survive.
    cut_in_iocs = (
        '{"summary": "s", "iocs": [{"kind": "md5", "value": "'
        + "b" * 32
        + '", "role": "payload", "evidence": "e"}, {"kind": "url", "value": "https://x.example-bad.net/a'
    )
    out = parse_ai_json(cut_in_iocs)
    assert out.get("_truncated") is True and [i["kind"] for i in out["iocs"]] == ["md5"]

    # Nothing complete at all is still a parse error, not an empty success.
    assert parse_ai_json('{"summary": "unterminated').get("_extraction_status") == "parse_error"
    # Valid JSON is untouched.
    assert parse_ai_json('{"a": [1, 2]}') == {"a": [1, 2]}
