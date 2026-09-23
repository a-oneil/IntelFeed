"""migrate per-user notification webhooks into automation rules

Each row in `users` may carry `notification_webhook_url` plus filter prefs in
its `settings` JSONB column. The settings-level webhook plumbing is being
removed in favor of the automation engine's `on_correlation_event` trigger and
`run_webhook` action, which cover the same surface and are toggleable + visible
in the Automations UI.

For every user with a non-empty `notification_webhook_url`, create one
automation rule (disabled by default — the legacy feature was rarely active,
and the user asked to opt in explicitly) that replicates the old behavior,
then strip the four `notification_*` keys from `users.settings`.

Revision ID: z1a2b3c4d5f6
Revises: y1a2b3c4d5f5
Create Date: 2026-06-08

"""

import json
import uuid

import sqlalchemy as sa

from alembic import op

revision = "z1a2b3c4d5f6"
down_revision = "y1a2b3c4d5f5"
branch_labels = None
depends_on = None


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

# Mirror of frontend WEBHOOK_EVENT_TYPE_GROUPS (SettingsPage.tsx) — the full
# catalog of event types the legacy webhook could send, with their declared
# severity. Inlined here so this migration is self-contained.
EVENT_TYPE_SEVERITY: dict[str, str] = {
    "new_ttp_for_known_actor": "medium",
    "new_ttp_for_known_malware": "medium",
    "new_malware_for_known_actor": "medium",
    "actor_malware_cooccurrence": "medium",
    "coverage_gap": "high",
    "exploit_status_change": "high",
    "cve_score_change": "high",
    "new_exploit_discovered": "high",
    "kev_addition": "high",
    "trending_entity": "medium",
    "feed_stale": "low",
    "feed_error": "low",
}


def _allowed_event_types(min_severity: str, disabled_types: list[str]) -> list[str]:
    threshold = SEVERITY_RANK.get(min_severity, 0)
    disabled = set(disabled_types or [])
    return sorted(
        key for key, sev in EVENT_TYPE_SEVERITY.items() if key not in disabled and SEVERITY_RANK[sev] >= threshold
    )


def upgrade() -> None:
    bind = op.get_bind()

    users = bind.execute(
        sa.text(
            "SELECT id, settings FROM users "
            "WHERE settings ? 'notification_webhook_url' "
            "AND COALESCE(settings->>'notification_webhook_url', '') <> ''"
        )
    ).fetchall()

    for row in users:
        user_id = row[0]
        settings = row[1] or {}

        webhook_url = settings.get("notification_webhook_url", "")
        if not webhook_url:
            continue

        min_severity = settings.get("notification_min_severity", "low")
        disabled_types = settings.get("notification_disabled_types") or []
        was_enabled = bool(settings.get("notification_webhook_enabled", False))

        event_types = _allowed_event_types(min_severity, disabled_types)

        trigger_config: dict = {}
        if event_types:
            trigger_config["event_types"] = event_types

        actions = [
            {
                "type": "run_webhook",
                "config": {"url": webhook_url, "payload": ""},
            }
        ]

        description = (
            "Migrated from the legacy Settings → Webhooks tab. "
            "Fires the same correlation-event webhook the user previously had "
            f"configured (was {'enabled' if was_enabled else 'disabled'} in "
            "settings). Imported disabled so it can be reviewed before turning "
            "on."
        )

        bind.execute(
            sa.text(
                "INSERT INTO automation_rules ("
                "id, created_by, name, description, is_enabled, trigger_type, "
                "trigger_config, conditions, actions, labels, run_count"
                ") VALUES ("
                ":id, :created_by, :name, :description, :is_enabled, :trigger_type, "
                "CAST(:trigger_config AS jsonb), CAST(:conditions AS jsonb), "
                "CAST(:actions AS jsonb), CAST(:labels AS jsonb), 0"
                ")"
            ),
            {
                "id": uuid.uuid4(),
                "created_by": user_id,
                "name": "Webhook: Correlation Events (migrated from settings)",
                "description": description,
                "is_enabled": False,
                "trigger_type": "on_correlation_event",
                "trigger_config": json.dumps(trigger_config),
                "conditions": json.dumps({}),
                "actions": json.dumps(actions),
                "labels": json.dumps(["migrated", "webhook"]),
            },
        )

    # Drain the four notification_* keys from every user's settings — the
    # consumer is gone, so leaving them in place is just dead data.
    bind.execute(
        sa.text(
            "UPDATE users SET settings = settings "
            "- 'notification_webhook_url' "
            "- 'notification_webhook_enabled' "
            "- 'notification_min_severity' "
            "- 'notification_disabled_types' "
            "WHERE settings ?| ARRAY["
            "'notification_webhook_url', 'notification_webhook_enabled', "
            "'notification_min_severity', 'notification_disabled_types']"
        )
    )


def downgrade() -> None:
    # The legacy settings shape was unstructured and the rules we created have
    # no reliable link back to a specific user's prior config beyond
    # `created_by` + the migrated label. Don't try to reconstruct.
    pass
