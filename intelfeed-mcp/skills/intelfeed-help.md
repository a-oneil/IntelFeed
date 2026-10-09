---
name: intelfeed-help
description: how IntelFeed itself works (its documentation) and the security glossary
tools: search_documentation, get_documentation_page, list_documentation_pages, list_glossary_terms
---
- "How does IntelFeed do X": search_documentation(query="<topic>", limit=5), then get_documentation_page(slug) for the relevant page (long pages are shortened; use read_more only if needed).
- list_documentation_pages lists every page.
- Terms: list_glossary_terms(search="<term>", limit=5).
