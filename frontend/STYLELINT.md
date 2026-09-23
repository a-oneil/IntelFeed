# CSS token guard (stylelint)

Keeps the D6 geometry scale in `src/index.css` from drifting back into
hand-rolled values. It is a **ratchet**, not a rewrite: the ~3,760 existing
violations are frozen in a baseline, and only *new* ones fail.

## Commands

```bash
pnpm lint:css            # enforce — exit 0 on a clean tree, exit 2 on new violations
pnpm lint:css:baseline   # regenerate the frozen baseline (see "Maintaining the baseline")
```

There is **no CI pipeline** in this repo (self-hosted Gitea, no workflow files),
so nothing runs this for you. Run `pnpm lint:css` alongside `pnpm lint` and
`pnpm build` before pushing, same as the rest of the pre-push checks in
[CLAUDE.md](../CLAUDE.md).

## What it flags

Scope is `src/**/*.module.css` only. Plain `.css` (including `index.css`, which
*defines* the tokens) is untouched.

| Flagged | Use instead |
| --- | --- |
| Raw hex color — `color: #2563eb` | `var(--accent)` or another `index.css` token |
| `font-size` in `px`/`rem` — `font-size: 13px` | `var(--fs-2xs … --fs-xl)` |
| `border-radius` in `px` — `border-radius: 6px` | `var(--r-sm / --r-md / --r-full)` |

Deliberately **allowed** for now:

- `rgba(…)` and `color-mix(…)` — too many legitimate one-off alpha overlays.
- `border-radius: 50%` — circles are a shape, not a scale step.
- `font-size` in `em`, `%`, or `ch` — relative sizing is intentional.
  (`calc()` containing a `px`/`rem` literal *is* still flagged.)
- Raw `px` for spacing, width, height, gap. The `--sp-*` and `--h-*` tokens
  exist but are not enforced; too much layout CSS is legitimately bespoke to
  make a blanket rule useful.

One known false positive: a hex used as a `var()` fallback
(`color: var(--accent, #2563eb)`) is flagged. That is intentional — the fallback
is still a hardcoded brand color that themes cannot override — but if you are
converting a file, expect to deal with those too.

## How the baseline works

`stylelint-suppressions.json` is stylelint 17's native suppressions file
(`--suppress` / `--suppress-location`). It records, **per file and per rule, a
count** of problems that existed when it was generated:

```json
"src/pages/AutomationPage.module.css": {
  "color-no-hex": { "count": 14 },
  "declaration-property-value-disallowed-list": { "count": 43 }
}
```

`pnpm lint:css` passes as long as no file exceeds its recorded count.

### What this catches

- **Any violation in a file with no baseline entry** — i.e. every converted file
  and every new `.module.css`. These are hard-fail from problem #1.
- **A net increase in any baselined file.** Add a 15th hex to
  `AutomationPage.module.css` and the run fails.

### What this does NOT catch — read this before trusting it

- **Swaps inside a baselined file.** Delete one hex and add another in the same
  file and the count is unchanged, so it passes. The guard is count-based, not
  line-based. In practice this only lets a violation through in a file that is
  already dirty for that exact rule.
- **The ~3,760 existing violations.** They are frozen, not fixed. This is the
  price of a guard anyone can actually run today.

The baseline is a debt ledger, not an allowlist of good code.

## Maintaining the baseline

The counts only ever go **down** by hand. Falling below a recorded count does
*not* error (stylelint does not report stale suppressions), so a file you clean
up keeps its old, now-too-generous entry until someone regenerates.

After converting a batch of files, run:

```bash
pnpm lint:css:baseline
git diff stylelint-suppressions.json   # should only ever show counts decreasing
```

Review that diff. Two things must not appear in it:

- **A count going up.** You just laundered a new violation into the ledger.
- **A brand-new file entry.** New `.module.css` files should be written against
  the tokens from the start and never need a baseline entry.

Those are the failure modes of this setup, and only code review catches them.

When a file's entry disappears entirely, that file is fully converted and is now
permanently guarded.
