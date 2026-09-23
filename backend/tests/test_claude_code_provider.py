"""Tests for ClaudeCodeProvider's CLI-output parsing — usage/cost extraction.

Focused on the pure parsing helpers (no subprocess): the result payload shape
the claude CLI emits for both `--output-format json` (single payload) and the
terminal ``{"type": "result"}`` stream-json event, which carries token usage
and ``total_cost_usd`` for cost-dashboard accounting.
"""

import json

from app.ai.providers.claude_code_provider import ClaudeCodeProvider

# A realistic CLI result payload (shared shape between `--output-format json`
# stdout and the stream-json terminal "result" event).
_RESULT_PAYLOAD = {
    "type": "result",
    "subtype": "success",
    "is_error": False,
    "duration_ms": 2377,
    "num_turns": 1,
    "result": "The answer.",
    "session_id": "abc",
    "total_cost_usd": 0.031772,
    "usage": {
        "input_tokens": 12,
        "output_tokens": 345,
        "cache_creation_input_tokens": 4000,
        "cache_read_input_tokens": 16000,
    },
}


class TestExtractUsage:
    def test_full_payload(self):
        usage = ClaudeCodeProvider._extract_usage(_RESULT_PAYLOAD)
        # tokens_input includes both cache buckets — the full processed context.
        assert usage["tokens_input"] == 12 + 4000 + 16000
        assert usage["tokens_output"] == 345
        assert usage["cache_creation_input_tokens"] == 4000
        assert usage["cache_read_input_tokens"] == 16000
        assert usage["total_cost_usd"] == 0.031772

    def test_missing_usage_degrades_to_zero(self):
        usage = ClaudeCodeProvider._extract_usage({"type": "result", "result": "hi"})
        assert usage["tokens_input"] == 0
        assert usage["tokens_output"] == 0
        assert usage["total_cost_usd"] is None

    def test_none_payload(self):
        usage = ClaudeCodeProvider._extract_usage(None)
        assert usage["tokens_input"] == 0
        assert usage["tokens_output"] == 0
        assert usage["total_cost_usd"] is None

    def test_malformed_fields_do_not_raise(self):
        usage = ClaudeCodeProvider._extract_usage(
            {"usage": {"input_tokens": "not-a-number", "output_tokens": None}, "total_cost_usd": "free"}
        )
        assert usage["tokens_input"] == 0
        assert usage["tokens_output"] == 0
        assert usage["total_cost_usd"] is None


class TestExtractResult:
    def test_returns_text_and_payload(self):
        stdout = json.dumps(_RESULT_PAYLOAD).encode()
        text, payload = ClaudeCodeProvider._extract_result(stdout)
        assert text == "The answer."
        assert payload["total_cost_usd"] == 0.031772

    def test_structured_output_preferred(self):
        payload = {**_RESULT_PAYLOAD, "structured_output": {"verdict": "ok"}}
        text, parsed = ClaudeCodeProvider._extract_result(json.dumps(payload).encode())
        assert json.loads(text) == {"verdict": "ok"}
        assert parsed["usage"]["output_tokens"] == 345

    def test_bare_string_payload_has_no_usage(self):
        text, payload = ClaudeCodeProvider._extract_result(b'"just text"')
        assert text == "just text"
        assert payload is None


class TestMapStreamEvent:
    def _provider(self) -> ClaudeCodeProvider:
        return ClaudeCodeProvider(config={})

    def test_result_event_emits_done_with_usage(self):
        out = self._provider()._map_stream_event(_RESULT_PAYLOAD)
        assert len(out) == 1
        assert out[0]["kind"] == "done"
        assert out[0]["usage"]["tokens_input"] == 12 + 4000 + 16000
        assert out[0]["usage"]["tokens_output"] == 345
        assert out[0]["usage"]["total_cost_usd"] == 0.031772

    def test_result_event_without_usage_still_done(self):
        out = self._provider()._map_stream_event({"type": "result", "subtype": "success"})
        assert out[0]["kind"] == "done"
        assert out[0]["usage"]["total_cost_usd"] is None

    def test_text_delta_unaffected(self):
        event = {
            "type": "stream_event",
            "event": {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "hi"}},
        }
        out = self._provider()._map_stream_event(event)
        assert out == [{"kind": "text", "text": "hi"}]
