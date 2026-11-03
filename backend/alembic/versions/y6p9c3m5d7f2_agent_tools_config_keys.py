"""AI task assignments: ``ollama_tools`` / ``ollama_tools_read_only`` become ``agent_tools`` / ``agent_tools_read_only``.

The tool lists apply to every provider with an in-process tool loop (Ollama,
the Anthropic API, OpenAI-compatible), so the keys don't name a provider.
Both tables that hold an assignment config are rewritten: the instance's
``ai_task_assignments`` and people's own ``user_ai_routes``. A row that
already has the new key keeps it. The code reads only the new names.

Downgrade moves the keys back.

Revision ID: y6p9c3m5d7f2
Revises: x5n8b2k4c6d1
"""

from alembic import op

revision = "y6p9c3m5d7f2"
down_revision = "x5n8b2k4c6d1"
branch_labels = None
depends_on = None

_TABLES = ("ai_task_assignments", "user_ai_routes")
_RENAMES = (("ollama_tools", "agent_tools"), ("ollama_tools_read_only", "agent_tools_read_only"))


def _move(old: str, new: str) -> None:
    for table in _TABLES:
        op.execute(
            f"UPDATE {table} SET config = (config - '{old}') || "
            f"CASE WHEN config ? '{new}' THEN '{{}}'::jsonb ELSE jsonb_build_object('{new}', config -> '{old}') END "
            f"WHERE config ? '{old}'"
        )


def upgrade() -> None:
    for old, new in _RENAMES:
        _move(old, new)


def downgrade() -> None:
    for old, new in _RENAMES:
        _move(new, old)
