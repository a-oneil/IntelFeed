"""Stamp ``applied_by`` on the maintenance logs from the acting user.

A Review change is applied through many code paths (a row's Apply, Apply
all, Restore, a hand unlink, the per-scan apply endpoints). Rather than thread
the user through each, one session hook sets ``applied_by`` on every log row
that becomes applied inside a request a person made. Rows the adjudicate
stage or the duplicate review apply on their own run without an acting user
and keep NULL, so History names them by origin.
"""

from __future__ import annotations

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.services.acting_user import current_acting_user

_LINK_APPLIED_ACTIONS = ("removed", "restored")


@event.listens_for(Session, "before_flush")
def _stamp_applied_by(session: Session, _flush_context, _instances) -> None:
    user_id = current_acting_user()
    if user_id is None:
        return
    for obj in list(session.new) + list(session.dirty):
        if isinstance(obj, EntityMaintenanceLog):
            if not obj.applied or obj.applied_by is not None:
                continue
            if obj in session.new or inspect(obj).attrs.applied.history.has_changes():
                obj.applied_by = user_id
        elif isinstance(obj, EntityLinkValidationLog):
            if obj in session.new and obj.action in _LINK_APPLIED_ACTIONS and obj.applied_by is None:
                obj.applied_by = user_id
