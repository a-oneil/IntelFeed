import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import noload, selectinload

from app.core.security import get_admin_user
from app.database import get_db
from app.models.ai_prompt_template import AIPromptTemplate
from app.models.ai_provider import AIProvider
from app.models.ai_task_assignment import AITaskAssignment
from app.models.automation_rule import AutomationRule
from app.models.category import Category
from app.models.dashboard import Dashboard
from app.models.detection_rule import DetectionRule
from app.models.feed import Feed
from app.models.saved_search import SavedSearch
from app.models.tag import Tag
from app.models.theme import Theme
from app.models.user import User

router = APIRouter()


class ConfigImportRequest(BaseModel):
    automation_rules: list[dict] = []
    tags: list[dict] = []
    saved_searches: list[dict] = []
    themes: list[dict] = []
    detection_rules: list[dict] = []

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "automation_rules": [
                    {
                        "name": "Morning Briefing",
                        "description": "Weekday summary of overnight entries",
                        "is_enabled": True,
                        "trigger_type": "schedule",
                        "trigger_config": {"cron": "0 7 * * 1-5"},
                        "conditions": {},
                        "actions": [{"type": "ai_task", "task": "briefing"}],
                    }
                ],
                "tags": [{"name": "ransomware", "color": "#DC2626"}],
                "saved_searches": [{"name": "APT29 activity", "query": "APT29", "filters": {"unread_only": True}}],
                "themes": [{"name": "Midnight Analyst", "css_variables": {"--bg-primary": "#0d1117"}}],
                "detection_rules": [
                    {
                        "title": "Suspicious ISO Mount Spawning LNK Execution",
                        "rule_type": "sigma",
                        "rule_content": "title: Suspicious ISO Mount...\ndetection:\n  condition: selection",
                        "severity": "high",
                        "tags": ["attack.t1566.001"],
                        "source_ttps": ["T1566.001"],
                    }
                ],
            }
        }
    )


def _uuid_serializer(obj: object) -> str:
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


@router.get("/export")
async def export_config(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Export all user configuration as JSON for backup/restore. Admin only."""

    # Categories (with hierarchy info)
    cat_result = await db.execute(select(Category).order_by(Category.position))
    categories = [
        {
            "name": c.name,
            "parent_id": str(c.parent_id) if c.parent_id else None,
            "position": c.position,
            "_id": str(c.id),
        }
        for c in cat_result.scalars().all()
    ]

    # Feeds (direct export)
    feed_result = await db.execute(select(Feed))
    feeds = [
        {
            "feed_url": feed.url,
            "feed_title": feed.title,
            "feed_type": feed.feed_type,
            "is_muted": feed.is_muted,
            "retention_days": feed.retention_days,
            "category_id": str(feed.category_id) if feed.category_id else None,
        }
        for feed in feed_result.scalars().all()
    ]

    # Tags
    tag_result = await db.execute(select(Tag))
    tags = [{"name": t.name, "color": t.color} for t in tag_result.scalars().all()]

    # AI providers (redact API keys)
    provider_result = await db.execute(select(AIProvider))
    providers = [
        {
            "name": p.name,
            "provider_type": p.provider_type,
            "base_url": p.base_url,
            "models": p.models,
            "is_active": p.is_active,
            "config": p.config,
            "_id": str(p.id),
        }
        for p in provider_result.scalars().all()
    ]

    # AI task assignments
    assignment_result = await db.execute(select(AITaskAssignment))
    task_assignments = [
        {
            "task_id": str(a.task_id),
            "provider_id": str(a.provider_id),
            "model_name": a.model_name,
            "is_enabled": a.is_enabled,
            "config": a.config,
        }
        for a in assignment_result.scalars().all()
    ]

    # AI prompt templates
    prompt_result = await db.execute(select(AIPromptTemplate))
    prompt_templates = [
        {
            "task_id": str(p.task_id),
            "name": p.name,
            "template_text": p.template_text,
            "variables": p.variables,
            "is_active": p.is_active,
            "version": p.version,
        }
        for p in prompt_result.scalars().all()
    ]

    # Automation rules
    auto_result = await db.execute(select(AutomationRule))
    automation_rules = [
        {
            "name": r.name,
            "description": r.description,
            "is_enabled": r.is_enabled,
            "trigger_type": r.trigger_type,
            "trigger_config": r.trigger_config,
            "conditions": r.conditions,
            "actions": r.actions,
        }
        for r in auto_result.scalars().all()
    ]

    # Saved searches
    search_result = await db.execute(select(SavedSearch))
    saved_searches = [{"name": s.name, "query": s.query, "filters": s.filters} for s in search_result.scalars().all()]

    # Dashboards with widgets
    dash_result = await db.execute(select(Dashboard).options(selectinload(Dashboard.widgets)))
    dashboards = [
        {
            "name": d.name,
            "layout": d.layout,
            "is_default": d.is_default,
            "widgets": [
                {
                    "widget_type": w.widget_type,
                    "title": w.title,
                    "config": w.config,
                    "position_x": w.position_x,
                    "position_y": w.position_y,
                    "width": w.width,
                    "height": w.height,
                }
                for w in d.widgets
            ],
        }
        for d in dash_result.scalars().all()
    ]

    # Detection rules
    # noload: DetectionRule.entry is lazy="joined"; without it this unbounded
    # export drags every rule's full entry row along (multi-GB on large DBs).
    det_result = await db.execute(select(DetectionRule).options(noload(DetectionRule.entry)))
    detection_rules = [
        {
            "rule_type": r.rule_type,
            "title": r.title,
            "description": r.description,
            "rule_content": r.rule_content,
            "severity": r.severity,
            "tags": r.tags,
            "source_ttps": r.source_ttps,
        }
        for r in det_result.scalars().all()
    ]

    # Custom themes
    theme_result = await db.execute(select(Theme))
    themes = [{"name": t.name, "css_variables": t.css_variables} for t in theme_result.scalars().all()]

    # User settings
    user_settings = {
        "display_name": user.username,
        "settings": user.settings or {},
        "custom_css": user.custom_css,
    }

    export_data = {
        "version": "1.0",
        "exported_at": datetime.utcnow().isoformat(),
        "user": user_settings,
        "categories": categories,
        "feeds": feeds,
        "tags": tags,
        "ai_providers": providers,
        "ai_task_assignments": task_assignments,
        "ai_prompt_templates": prompt_templates,
        "automation_rules": automation_rules,
        "saved_searches": saved_searches,
        "dashboards": dashboards,
        "detection_rules": detection_rules,
        "themes": themes,
    }

    filename = f"intelfeed-config-{datetime.utcnow().strftime('%Y%m%d')}.json"
    return JSONResponse(
        content=export_data,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/import")
async def import_config(
    body: ConfigImportRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Import configuration from a backup export. Merges non-destructively. Admin only."""
    imported = {
        "automation_rules": 0,
        "tags": 0,
        "saved_searches": 0,
        "themes": 0,
        "detection_rules": 0,
    }

    # Import tags (skip duplicates by name; tag names are globally unique)
    existing_tags = await db.execute(select(Tag.name))
    existing_tag_names = {r[0] for r in existing_tags.all()}
    for tag_data in body.tags:
        if tag_data.get("name") and tag_data["name"] not in existing_tag_names:
            db.add(Tag(created_by=user.id, name=tag_data["name"], color=tag_data.get("color", "#6B7280")))
            imported["tags"] += 1

    # Import automation rules (by name, skip duplicates).
    # Dedup is instance-wide, matching the export: the export contains every
    # rule regardless of who created it, so scoping this to the importing user
    # would duplicate any rule another user happened to author.
    existing_rules = await db.execute(select(AutomationRule.name))
    existing_rule_names = {r[0] for r in existing_rules.all()}
    for rule_data in body.automation_rules:
        name = rule_data.get("name")
        if name and name not in existing_rule_names:
            db.add(
                AutomationRule(
                    created_by=user.id,
                    name=name,
                    description=rule_data.get("description"),
                    is_enabled=rule_data.get("is_enabled", False),
                    trigger_type=rule_data.get("trigger_type", "on_manual"),
                    trigger_config=rule_data.get("trigger_config", {}),
                    conditions=rule_data.get("conditions", {}),
                    actions=rule_data.get("actions", []),
                )
            )
            imported["automation_rules"] += 1

    # Import saved searches (by name, skip duplicates)
    existing_searches = await db.execute(select(SavedSearch.name))
    existing_search_names = {r[0] for r in existing_searches.all()}
    for search_data in body.saved_searches:
        name = search_data.get("name")
        if name and name not in existing_search_names:
            db.add(
                SavedSearch(
                    created_by=user.id,
                    name=name,
                    query=search_data.get("query"),
                    filters=search_data.get("filters", {}),
                )
            )
            imported["saved_searches"] += 1

    # Import themes (by name, skip duplicates)
    existing_themes = await db.execute(select(Theme.name))
    existing_theme_names = {r[0] for r in existing_themes.all()}
    for theme_data in body.themes:
        name = theme_data.get("name")
        if name and name not in existing_theme_names:
            db.add(
                Theme(
                    created_by=user.id,
                    name=name,
                    css_variables=theme_data.get("css_variables", {}),
                    is_system=False,
                )
            )
            imported["themes"] += 1

    # Import detection rules (always add — no natural dedup key)
    for rule_data in body.detection_rules:
        if rule_data.get("title") and rule_data.get("rule_content"):
            db.add(
                DetectionRule(
                    created_by=user.id,
                    rule_type=rule_data.get("rule_type", "sigma"),
                    title=rule_data["title"],
                    description=rule_data.get("description"),
                    rule_content=rule_data["rule_content"],
                    severity=rule_data.get("severity"),
                    tags=rule_data.get("tags", []),
                    source_ttps=rule_data.get("source_ttps", []),
                )
            )
            imported["detection_rules"] += 1

    await db.flush()
    return {"imported": imported}
