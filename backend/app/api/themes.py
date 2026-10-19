"""Theme management API — built-in and custom themes, user theme preferences."""

import re
import uuid

from fastapi import APIRouter, Depends, Path, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.theme import Theme
from app.models.user import User
from app.schemas.theme import (
    ColorSchemaResponse,
    ThemeCreate,
    ThemeDuplicate,
    ThemePreferenceUpdate,
    ThemeResponse,
    ThemeUpdate,
)
from app.services.system_settings import get_default_theme_id, set_default_theme_id

router = APIRouter()

# Canonical workbench color coding vocabulary and base theme variables.
# Mirrors frontend/src/index.css, entityTheme.ts, colorSchemes.ts, ransomwareColors.ts,
# and severity.ts so mobile and web clients share one server-driven vocabulary.
_BASE_VARIABLES: dict[str, str] = {
    "bg-primary": "#0d1117",
    "bg-secondary": "#161b22",
    "bg-tertiary": "#21262d",
    "bg-hover": "#30363d",
    "text-primary": "#e6edf3",
    "text-secondary": "#8b949e",
    "text-muted": "#484f58",
    "accent": "#f78166",
    "accent-hover": "#ffa28b",
    "accent-text": "#ffffff",
    "border": "#30363d",
    "danger": "#f85149",
    "danger-fg": "#000000",
    "success": "#3fb950",
    "warning": "#d29922",
    "sidebar-bg": "#010409",
    "sidebar-hover": "#161b22",
    "sidebar-active": "#21262d",
    "card-bg": "#161b22",
    "card-border": "#30363d",
}

_DOMAIN_ACCENTS: dict[str, str] = {
    "feeds": "#f78166",
    "intel": "#58a6ff",
    "intel-fg": "#0d1117",
    "detect": "#3fb950",
    "dash": "#bc8cff",
}

_ENTITY_TYPES: dict[str, str] = {
    "threat_actor": "#f97316",
    "malware": "#a855f7",
    "ttp": "#3b82f6",
    "cve": "#ef4444",
    "cwe": "#b45309",
    "country": "#06b6d4",
    "detection_rule": "#22c55e",
    "campaign": "#14b8a6",
    "vendor": "#6366f1",
    "product": "#ec4899",
    "tool": "#eab308",
    "mitigation": "#84cc16",
    "sector": "#10b981",
    "ransomware_victim": "#e0555b",
    "pir": "#06b6d4",
    "observable": "#d946ef",
    "note": "#9aa4b2",
}

_ENTITY_CSS_VARIABLES: dict[str, str] = {
    "entity-actor": _ENTITY_TYPES["threat_actor"],
    "entity-malware": _ENTITY_TYPES["malware"],
    "entity-ttp": _ENTITY_TYPES["ttp"],
    "entity-cve": _ENTITY_TYPES["cve"],
    "entity-cwe": _ENTITY_TYPES["cwe"],
    "entity-country": _ENTITY_TYPES["country"],
    "entity-rule": _ENTITY_TYPES["detection_rule"],
    "entity-campaign": _ENTITY_TYPES["campaign"],
    "entity-vendor": _ENTITY_TYPES["vendor"],
    "entity-product": _ENTITY_TYPES["product"],
    "entity-tool": _ENTITY_TYPES["tool"],
    "entity-mitigation": _ENTITY_TYPES["mitigation"],
    "entity-sector": _ENTITY_TYPES["sector"],
    "entity-victim": _ENTITY_TYPES["ransomware_victim"],
    "entity-pir": _ENTITY_TYPES["pir"],
    "entity-ioc": _ENTITY_TYPES["observable"],
    "entity-note": _ENTITY_TYPES["note"],
}

_SEVERITY: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#fb923c",
    "medium": "#d29922",
    "low": "#3fb950",
    "info": "#58a6ff",
}

_RULE_FORMATS: dict[str, str] = {
    "sigma": "#56d364",
    "yara": "#d2a8ff",
    "kql": "#79c0ff",
    "elastic-ql": "#79c0ff",
    "nuclei": "#ffa657",
    "splunk-spl": "#7ee787",
}

_RANSOMWARE_GROUPS: dict[str, str] = {
    "lockbit": "#e05c2f",
    "clop": "#12996a",
    "akira": "#2a78d6",
    "qilin": "#c2537f",
    "play": "#b5820f",
    "ransomhub": "#2f8f2f",
    "other": "#8b94a3",
}

_PIR_CATEGORIES: dict[str, str] = {
    "strategic": "#8b5cf6",
    "operational": "#f97316",
    "tactical": "#ef4444",
    "technical": "#06b6d4",
}

_TLP: dict[str, str] = {
    "TLP:CLEAR": "#6b7280",
    "TLP:GREEN": "#22c55e",
    "TLP:AMBER": "#f59e0b",
    "TLP:AMBER+STRICT": "#f59e0b",
    "TLP:RED": "#ef4444",
}

_AUTOMATION_NODES: dict[str, str] = {
    "trigger": "#f59e0b",
    "condition": "#3b82f6",
    "action": "#22c55e",
    "branch": "#a855f7",
}

_SYNTAX: dict[str, str] = {
    "keyword": "#cba6f7",
    "string": "#a6e3a1",
    "number": "#fab387",
    "comment": "#6c7086",
    "function": "#89b4fa",
    "operator": "#89dceb",
    "attr": "#f9e2af",
}

_HEATMAP: dict[str, str] = {
    "empty": "rgba(255, 255, 255, 0.04)",
    "1": "#0e4429",
    "2": "#006d32",
    "3": "#26a641",
    "4": "#39d353",
    "5": "#56e373",
}

_CANONICAL_CSS_VARIABLES: dict[str, str] = {
    **_BASE_VARIABLES,
    **{f"accent-{k}": v for k, v in _DOMAIN_ACCENTS.items()},
    **_ENTITY_CSS_VARIABLES,
    **{f"severity-{k}": v for k, v in _SEVERITY.items()},
    "severity-critical-fg": "#ffffff",
    "severity-high-fg": "#0d1117",
    "severity-medium-fg": "#0d1117",
    "severity-low-fg": "#0d1117",
    "severity-info-fg": "#ffffff",
    **{f"fmt-{k}": v for k, v in _RULE_FORMATS.items()},
    **{f"rgroup-{k}": v for k, v in _RANSOMWARE_GROUPS.items()},
    **{f"pir-{k}": v for k, v in _PIR_CATEGORIES.items()},
    "tlp-clear": _TLP["TLP:CLEAR"],
    "tlp-green": _TLP["TLP:GREEN"],
    "tlp-amber": _TLP["TLP:AMBER"],
    "tlp-amber-strict": _TLP["TLP:AMBER+STRICT"],
    "tlp-red": _TLP["TLP:RED"],
    **{f"node-{k}": v for k, v in _AUTOMATION_NODES.items()},
    **{f"syntax-{k}": v for k, v in _SYNTAX.items()},
    **{f"heatmap-{k}": v for k, v in _HEATMAP.items()},
}

COLOR_SCHEMA = ColorSchemaResponse(
    base=_BASE_VARIABLES,
    domain_accents=_DOMAIN_ACCENTS,
    entity_types=_ENTITY_TYPES,
    severity=_SEVERITY,
    rule_formats=_RULE_FORMATS,
    ransomware_groups=_RANSOMWARE_GROUPS,
    pir=_PIR_CATEGORIES,
    tlp=_TLP,
    automation_nodes=_AUTOMATION_NODES,
    syntax=_SYNTAX,
    heatmap=_HEATMAP,
    css_variables=_CANONICAL_CSS_VARIABLES,
)


@router.get("", response_model=list[ThemeResponse])
async def list_themes(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all themes."""
    result = await db.execute(select(Theme).order_by(Theme.is_system.desc(), Theme.name))
    default_id = await get_default_theme_id(db)
    responses = []
    for t in result.scalars().all():
        resp = ThemeResponse.model_validate(t)
        resp.is_default = str(t.id) == default_id
        responses.append(resp)
    return responses


@router.get("/schema", response_model=ColorSchemaResponse)
async def get_color_schema():
    """Public (no auth): canonical workbench color coding vocabulary and default theme tokens.

    Mobile and web clients fetch this so entity types, severity ramps, domain accents,
    rule formats, ransomware groups, PIR categories, TLP levels, automation nodes, and
    syntax tokens are driven by the server rather than hardcoded in client builds.
    """
    return COLOR_SCHEMA


@router.get("/default", response_model=ThemeResponse | None)
async def get_public_default_theme(db: AsyncSession = Depends(get_db)):
    """Public (no auth): the instance default theme, used to style pre-auth pages.

    Returns null when no default is configured. Must be declared before the
    /{theme_id} route so "default" isn't captured by the UUID path param.
    """
    default_id = await get_default_theme_id(db)
    if not default_id:
        return None
    result = await db.execute(select(Theme).where(Theme.id == uuid.UUID(default_id)))
    theme = result.scalar_one_or_none()
    if not theme:
        return None
    resp = ThemeResponse.model_validate(theme)
    resp.is_default = True
    return resp


# Only variable names the app actually themes are emitted, so a malformed
# css_variables row can't inject arbitrary CSS into every page load.
_CSS_VAR_NAME = re.compile(r"^[a-z0-9-]+$")


@router.get(
    "/default.css",
    response_class=Response,
    summary="Instance default theme as a stylesheet",
    responses={200: {"content": {"text/css": {"example": ":root:root{--bg-primary:#0d1117;}"}}}},
)
async def get_default_theme_css(db: AsyncSession = Depends(get_db)):
    """Public (no auth): the instance default theme as a render-blocking stylesheet.

    index.html links this in <head> so the very first paint of a browser that has
    never signed in already uses the admin-set default. Fetching it from React
    instead would paint the baked-in palette first and repaint after the response
    — the flash this exists to remove.

    Wins over index.css's :root regardless of stylesheet order (":root:root"),
    and loses to the inline custom properties theme-init.js restores for a
    browser that already has a palette cached. Empty when no default is set.
    """
    default_id = await get_default_theme_id(db)
    theme = None
    if default_id:
        result = await db.execute(select(Theme).where(Theme.id == uuid.UUID(default_id)))
        theme = result.scalar_one_or_none()
    if not theme:
        css = ""
    else:
        decls = "".join(
            f"--{name}:{value};"
            for name, value in (theme.css_variables or {}).items()
            if _CSS_VAR_NAME.match(name) and isinstance(value, str) and "}" not in value and ";" not in value
        )
        css = f":root:root{{{decls}}}" if decls else ""
    return Response(
        content=css,
        media_type="text/css",
        # Blocks first paint, so it must come off the disk cache on repeat loads.
        # A default change lands within the window, and the logged-out React path
        # (same 5 min staleTime) repaints it sooner for anyone sitting on /login.
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.get("/{theme_id}", response_model=ThemeResponse)
async def get_theme(
    theme_id: uuid.UUID = Path(..., description="UUID of the theme"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch a single theme by id, flagging whether it is the instance default."""
    result = await db.execute(select(Theme).where(Theme.id == theme_id))
    theme = result.scalar_one_or_none()
    if not theme:
        raise AppError(code="not_found", message="Theme not found", status_code=404)
    resp = ThemeResponse.model_validate(theme)
    resp.is_default = str(theme.id) == await get_default_theme_id(db)
    return resp


@router.post("", response_model=ThemeResponse, status_code=201)
async def create_theme(
    body: ThemeCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a custom theme."""
    theme = Theme(name=body.name, css_variables=body.css_variables, is_system=False, created_by=user.id)
    db.add(theme)
    await db.flush()
    await db.refresh(theme)
    return ThemeResponse.model_validate(theme)


@router.put("/{theme_id}", response_model=ThemeResponse)
async def update_theme(
    body: ThemeUpdate,
    theme_id: uuid.UUID = Path(..., description="UUID of the custom theme to update"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a custom theme's name and/or CSS variables. System themes cannot be modified."""
    result = await db.execute(select(Theme).where(Theme.id == theme_id))
    theme = result.scalar_one_or_none()
    if not theme:
        raise AppError(code="not_found", message="Theme not found", status_code=404)
    if theme.is_system:
        raise AppError(code="forbidden", message="Cannot modify system themes", status_code=403)
    if user.role != "admin" and theme.created_by != user.id:
        raise AppError(code="forbidden", message="Only the theme's creator or an admin can modify it", status_code=403)

    if body.name is not None:
        theme.name = body.name
    if body.css_variables is not None:
        theme.css_variables = body.css_variables

    db.add(theme)
    await db.flush()
    await db.refresh(theme)
    return ThemeResponse.model_validate(theme)


@router.delete("/{theme_id}", status_code=204)
async def delete_theme(
    theme_id: uuid.UUID = Path(..., description="UUID of the custom theme to delete"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a user's custom theme."""
    result = await db.execute(select(Theme).where(Theme.id == theme_id))
    theme = result.scalar_one_or_none()
    if not theme:
        raise AppError(code="not_found", message="Theme not found", status_code=404)
    if theme.is_system:
        raise AppError(code="forbidden", message="Cannot delete system themes", status_code=403)
    if user.role != "admin" and theme.created_by != user.id:
        raise AppError(code="forbidden", message="Only the theme's creator or an admin can delete it", status_code=403)

    # If user's active theme is being deleted, clear it
    if user.theme_id == theme.id:
        user.theme_id = None
        db.add(user)

    # If this theme was the instance default, clear the default
    if str(theme.id) == await get_default_theme_id(db):
        await set_default_theme_id(db, None)

    await db.delete(theme)
    await db.flush()


@router.post("/{theme_id}/duplicate", response_model=ThemeResponse, status_code=201)
async def duplicate_theme(
    body: ThemeDuplicate,
    theme_id: uuid.UUID = Path(..., description="UUID of the source theme to clone"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Clone a theme (system or own) as a new user-owned custom theme."""
    result = await db.execute(select(Theme).where(Theme.id == theme_id))
    source = result.scalar_one_or_none()
    if not source:
        raise AppError(code="not_found", message="Theme not found", status_code=404)
    clone = Theme(
        name=body.name,
        css_variables=dict(source.css_variables),
        is_system=False,
        created_by=user.id,
    )
    db.add(clone)
    await db.flush()
    await db.refresh(clone)
    return ThemeResponse.model_validate(clone)


@router.put("/user/preferences", response_model=dict)
async def update_theme_preference(
    body: ThemePreferenceUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update the current user's theme preference.

    Picks a theme, clears it back to the instance default (clear_theme), and/or
    sets the user's personal custom CSS overrides.
    """
    if body.clear_theme:
        user.theme_id = None
    elif body.theme_id is not None:
        result = await db.execute(select(Theme).where(Theme.id == body.theme_id))
        theme = result.scalar_one_or_none()
        if not theme:
            raise AppError(code="not_found", message="Theme not found", status_code=404)
        user.theme_id = body.theme_id

    if body.custom_css is not None:
        user.custom_css = body.custom_css

    db.add(user)
    await db.flush()
    return {"status": "ok", "theme_id": str(user.theme_id) if user.theme_id else None}


@router.put("/{theme_id}/default", response_model=dict)
async def set_default_theme(
    theme_id: uuid.UUID = Path(..., description="UUID of the theme to make the instance default"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Set the instance-wide default theme, applied to users without their own theme."""
    result = await db.execute(select(Theme).where(Theme.id == theme_id))
    theme = result.scalar_one_or_none()
    if not theme:
        raise AppError(code="not_found", message="Theme not found", status_code=404)
    await set_default_theme_id(db, str(theme.id))
    return {"status": "ok", "default_theme_id": str(theme.id)}


@router.delete("/{theme_id}/default", response_model=dict)
async def clear_default_theme(
    theme_id: uuid.UUID = Path(..., description="UUID of the theme to unset as instance default"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Clear the instance default if this theme is currently it."""
    if str(theme_id) == await get_default_theme_id(db):
        await set_default_theme_id(db, None)
    current = await get_default_theme_id(db)
    return {"status": "ok", "default_theme_id": current}
