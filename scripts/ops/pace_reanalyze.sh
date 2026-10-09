#!/bin/bash
# Paced backfill: re-analyse long research articles (over 15k chars with an
# indicator section, last 90 days) that have no entry_analysis result newer
# than the 2026-10-02 prompt fixes — 8 at a time, only when the ai queue is
# quiet, so live ingest analysis never waits behind the backfill.
cd ~/intelfeed || exit 1
LOG=logs/reanalyze-pace.log
PW=$(grep -E "^REDIS_PASSWORD=" .env | cut -d= -f2-)
while true; do
  depth=$(docker compose -f docker-compose.prod.yml exec -T redis redis-cli -a "$PW" --no-auth-warning llen ai 2>/dev/null | tr -d '\r')
  if [ "${depth:-99}" -lt 10 ]; then
    out=$(docker compose -f docker-compose.prod.yml exec -T api python - <<'PY' 2>/dev/null
import asyncio, sys
sys.path.insert(0, "/app")
import app.models
from sqlalchemy import select, func, text, or_, and_, exists
from app.database import async_session
from app.models.entry import Entry
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.services.analysis_window import find_indicator_section, html_to_analysis_text
from app.workers.ai_batch_tasks import run_entry_analysis_task
SINCE = "2026-10-02 13:11"
async def main():
    async with async_session() as db:
        task_id = (await db.execute(select(AITask.id).where(AITask.name == "entry_analysis"))).scalar_one()
        fresh = exists().where(and_(AIResult.target_id == Entry.id, AIResult.task_id == task_id, AIResult.is_current.is_(True),
                                    AIResult.created_at > text(f"'{SINCE}'"),
                                    func.coalesce(AIResult.parsed_result["_extraction_status"].astext, "") != "parse_error"))
        q = (select(Entry.id, Entry.content_html, Entry.content_text)
             .where(Entry.published_at >= func.now() - text("interval '90 days'"),
                    func.coalesce(Entry.metadata_["content_type"].astext, "") != "ioc_list",
                    func.length(func.coalesce(Entry.content_text, "")) > 15000, ~fresh)
             .order_by(Entry.published_at.desc()))
        picked = []
        for eid, html, txt in (await db.execute(q)).all():
            body = html_to_analysis_text(html) if html else (txt or "")
            if len(body) > 15000 and find_indicator_section(body) is not None:
                picked.append(eid)
            if len(picked) >= 8:
                break
    for eid in picked:
        run_entry_analysis_task.delay(str(eid), force=True)
    print(f"queued {len(picked)}")
asyncio.run(main())
PY
)
    echo "$(date -u +%FT%TZ) queue=$depth $out" >> "$LOG"
    case "$out" in *"queued 0"*) echo "$(date -u +%FT%TZ) backfill complete" >> "$LOG"; exit 0;; esac
  else
    echo "$(date -u +%FT%TZ) queue=$depth busy, waiting" >> "$LOG"
  fi
  sleep 900
done
