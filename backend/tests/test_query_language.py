"""The preferred query language: one setting, read everywhere a query is written."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select

from app.ai import query_language as ql
from app.models.ai_provider import AIProvider
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment


class TestVocabulary:
    def test_setting_falls_back_to_the_default(self):
        assert ql.preferred_query_language(None) == "kql"
        assert ql.preferred_query_language({}) == "kql"
        assert ql.preferred_query_language({"query_language": "spl"}) == "spl"
        assert ql.preferred_query_language({"query_language": "cobol"}) == "kql"

    def test_every_language_has_a_name_short_form_and_platform(self):
        for q in ql.QUERY_LANGUAGES.values():
            assert q.name and q.short and q.platform and q.fence

    def test_rule_type_maps_onto_the_library_formats(self):
        import re

        from app.schemas.intelligence import RULE_TYPE_PATTERN

        for q in ql.QUERY_LANGUAGES.values():
            if q.rule_type is not None:
                assert re.match(RULE_TYPE_PATTERN, q.rule_type), q.id

    def test_default_rule_types_are_sigma_plus_the_analysts_own(self):
        assert ql.default_rule_types({"query_language": "spl"}) == ["sigma", "splunk_spl"]
        assert ql.default_rule_types({"query_language": "kql"}) == ["sigma", "kql"]
        # Sigma itself adds nothing; every other language is a library format,
        # including the ones stored without a syntax check.
        assert ql.default_rule_types({"query_language": "sigma"}) == ["sigma"]
        assert ql.default_rule_types({"query_language": "yaral"}) == ["sigma", "yaral"]
        assert ql.default_rule_types({"query_language": "sql"}) == ["sigma", "sql"]

    def test_with_query_language_never_overrides_the_caller(self):
        merged = ql.with_query_language({"query_language": "spl", "x": 1}, "kql")
        assert merged["query_language"] == "spl"
        assert merged["query_language_name"] == "KQL (Microsoft Sentinel / Defender XDR)"
        assert merged["x"] == 1


def _stub_provider(monkeypatch, content='{"answer": "ok"}'):
    import app.ai.engine as engine

    response = MagicMock(content=content, model="qwen", tokens_input=12, tokens_output=4, latency_ms=7, cost_usd=None)
    stub = MagicMock()
    stub.complete = AsyncMock(return_value=response)
    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: stub)
    return stub


@pytest.mark.asyncio
class TestInjectedIntoEveryTask:
    async def test_run_task_renders_the_users_language(self, db_session, test_user, monkeypatch):
        from app.ai.engine import run_task

        provider = AIProvider(name="Lab Ollama", provider_type="ollama", base_url="http://ollama.test:11434")
        db_session.add(provider)
        await db_session.flush()
        task = AITask(
            name="ql_probe",
            display_name="Probe",
            default_prompt_template="Write it in {{ query_language_name }} ({{ query_language }}).",
        )
        db_session.add(task)
        await db_session.flush()
        db_session.add(AITaskAssignment(task_id=task.id, provider_id=provider.id, model_name="qwen"))
        test_user.settings = {**(test_user.settings or {}), "query_language": "spl"}
        await db_session.commit()
        _stub_provider(monkeypatch)

        await run_task(db_session, test_user.id, "ql_probe", variables={})

        row = (await db_session.execute(select(AIResult).where(AIResult.task_id == task.id))).scalar_one()
        assert "Write it in SPL (Splunk) (spl)." in (row.prompt_used or "")

    async def test_system_caller_gets_the_default(self, db_session):
        assert await ql.preferred_for_user(db_session, uuid.UUID(int=0)) == "kql"
        assert await ql.preferred_for_user(db_session, uuid.uuid4()) == "kql"
