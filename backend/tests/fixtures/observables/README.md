# Observable extraction fixture

Regression set for the one-pass analysis's observables judgment (issue #1).
Each `cases/<slug>.json` describes one real article:

```json
{
  "slug": "talos-uat-11587",
  "title_like": "China-nexus UAT-11587%",       // how to find the entry in a corpus DB
  "url": "https://blog.talosintelligence.com/...",
  "publisher": "Cisco Talos",
  "kind": "positive",                            // positive | negative (must yield nothing)
  "attribution": [{"type": "threat_actor", "name": "UAT-11587"}, {"type": "malware", "name": "Antino"}],
  "expected": [
    {"kind": "sha256", "value": "e809da86...", "role": "delivery", "note": "malicious HTA stager"},
    {"kind": "domain", "value": "osc-cdn.com", "role": "delivery"}
  ],
  "must_not": [
    {"kind": "domain", "value": "talosintelligence.com", "why": "publisher self-link"},
    {"kind": "sha256", "value": "cee96a38...", "why": "AES key, not a file hash"}
  ],
  "optional": [ {"kind": "path", "value": "D:\\a\\antino\\...\\antino_client_template.pdb"} ]
}
```

- `expected` values are **canonical** (refanged, lowercase where the kind
  lowercases) — exactly what `normalize_value` would store. `role` is optional
  and scored separately.
- `must_not` is the garbage list for that article: values a careless extractor
  would emit. Any hit is a hard failure.
- `optional` items earn no recall credit and cost no precision — real
  artifacts whose ledger-worthiness is a judgment call. The seeder puts every
  hash / IP / defanged value it finds *outside* the IOC section here; promote
  the ones the article treats as indicators to `expected`.
- Article bodies are **not** committed (they are the publishers' copyrighted
  text). The eval pulls them from the corpus DB by `title_like`, or fetches
  `url` when `--fetch` is given.

Seed a case from an article's own IOC section, then hand-edit:

    docker compose -f docker-compose.dev.yml exec api \
      python scripts/dev/build_observable_fixture.py --title-like "China-nexus UAT-11587%" --slug talos-uat-11587

Run the eval (calls the configured AI provider, writes a report):

    docker compose -f docker-compose.dev.yml exec api \
      python scripts/dev/eval_observable_extraction.py --report /app/planning/observables-eval.md

Gate (from the plan): network kinds precision ≥ 0.95 / recall ≥ 0.80, host
kinds precision ≥ 0.90, zero `must_not` hits, attribution-edge recall ≥ 0.6.

`tests/test_observable_fixture.py` runs offline: every `expected` value must
pass `validate_kind_value` for its kind (so the fixture and the validators
can't drift apart), and every `must_not` item flagged `"validator": true`
must be *rejected* by the validator.
