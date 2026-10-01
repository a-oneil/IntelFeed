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
