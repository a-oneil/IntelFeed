## What this changes

<!-- One or two sentences. What moved, and why. -->

## How it was verified

<!-- What you actually ran or clicked, not what CI will run for you. -->

## Checks

CI only runs the areas you touched, so tick the ones that apply. The commands
mirror what the workflows run — see [CLAUDE.md](../CLAUDE.md#ci).

**Backend** (`cd backend`)

- [ ] `ruff check . && ruff format --check .`
- [ ] `pytest tests/ -q`
- [ ] New/changed models have a migration, and `alembic upgrade head` then
      `alembic downgrade -1` both work
- [ ] New tools are in `TOOL_DEFINITIONS`, destructive ones in `ADMIN_TOOLS`,
      and `scripts/dev/sync_skill_clis.py` has been re-run

**Frontend** (`cd frontend`)

- [ ] `pnpm lint`
- [ ] `pnpm test`
- [ ] `pnpm build`
- [ ] Checked at phone width if the change is visual

**Anything user-facing**

- [ ] No secrets, tokens or real hostnames in the diff (gitleaks runs on this PR)
- [ ] Docs under `docs/` updated if behaviour changed
- [ ] New settings are registered — `settings.get()` on an unregistered key is
      permanently inert

## Notes for review

<!-- Anything deliberately left out, follow-ups, or a part you want a second
     pair of eyes on. Delete if there's nothing. -->
