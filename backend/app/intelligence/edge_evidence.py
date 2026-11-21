"""The sentence behind a relationship claim, for whoever judges it.

A reviewer asked "does this article state that A uses B?" needs the sentence
that would say so, not the whole article: the per-article review
(app/services/entry_adjudication.py) prints it on the edge's item line, and
the edge sweep (app/services/relationship_sweep.py) builds its passages
from it. Two sources, best first:

* the analysis's own ``evidence`` sentence for the pair, when it asserted it;
* the article's sentences that name a form of both ends.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

# Sentence ends: punctuation followed by space, or a line break.
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?;])\s+|\n+")
_MIN_FORM_LEN = 2
SENTENCE_MAX = 300


def _form_pattern(forms: list[str]) -> re.Pattern | None:
    clean = sorted({f.strip() for f in forms if f and len(f.strip()) >= _MIN_FORM_LEN}, key=len, reverse=True)
    if not clean:
        return None
    # Word boundaries, hyphen included: "Russia-based" and "China-nexus" name
    # the country, and they are exactly the sentences an origin claim turns on.
    return re.compile(r"(?<!\w)(?:" + "|".join(re.escape(f) for f in clean) + r")(?!\w)", re.IGNORECASE)


def names(text: str, forms: list[str]) -> bool:
    pattern = _form_pattern(forms)
    return bool(pattern and pattern.search(text or ""))


def sentences_naming(text: str, forms_a: list[str], forms_b: list[str], limit: int = 2) -> list[str]:
    """The article's sentences that name both ends, in order, clipped."""
    pa, pb = _form_pattern(forms_a), _form_pattern(forms_b)
    if pa is None or pb is None or not text:
        return []
    out: list[str] = []
    for sentence in _SENTENCE_SPLIT.split(text):
        s = " ".join(sentence.split())
        if s and pa.search(s) and pb.search(s):
            out.append(s[:SENTENCE_MAX])
            if len(out) >= limit:
                break
    return out


def first_sentence_naming(text: str, forms: list[str]) -> str | None:
    pattern = _form_pattern(forms)
    if pattern is None or not text:
        return None
    for sentence in _SENTENCE_SPLIT.split(text):
        s = " ".join(sentence.split())
        if s and pattern.search(s):
            return s[:SENTENCE_MAX]
    return None


PASSAGE_MAX = 700


def _clip_around(text: str, patterns: list[re.Pattern], limit: int = PASSAGE_MAX) -> str:
    """The paragraph, or the window of it that holds the first mention of
    each end, at most ``limit`` characters."""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    starts = [m.start() for p in patterns if (m := p.search(text))]
    lo = max(0, min(starts) - 120) if starts else 0
    hi = min(len(text), max(lo + limit, (max(starts) + 200) if starts else limit))
    if hi - lo > limit:
        hi = lo + limit
    piece = text[lo:hi]
    return ("…" if lo else "") + piece + ("…" if hi < len(text) else "")


def paragraphs(title: str | None, summary: str | None, content: str | None) -> list[str]:
    """The article split the way the autolinker records positions: title,
    summary, then the body's paragraphs."""
    from app.intelligence.autolinker import split_into_paragraphs

    return [text for _i, text in split_into_paragraphs(title or "", summary or "", content or "")]


def passages_naming(
    paras: list[str], forms_a: list[str], forms_b: list[str], limit: int = 2
) -> tuple[list[str], list[str], list[str]]:
    """(paragraphs naming both ends, first paragraph naming only A, first naming
    only B), clipped. A claim is often stated across a paragraph's sentences
    ("UAC-0099 gained access … the attackers deployed MythicRatatoskr"), so the
    judge reads the paragraph, not the sentence."""
    pa, pb = _form_pattern(forms_a), _form_pattern(forms_b)
    if pa is None or pb is None:
        return [], [], []
    both, only_a, only_b = [], [], []
    for text in paras:
        has_a, has_b = bool(pa.search(text)), bool(pb.search(text))
        if has_a and has_b and len(both) < limit:
            both.append(_clip_around(text, [pa, pb]))
        elif has_a and not has_b and not only_a:
            only_a.append(_clip_around(text, [pa], 400))
        elif has_b and not has_a and not only_b:
            only_b.append(_clip_around(text, [pb], 400))
    return both, only_a, only_b


def paragraph_holding(paras: list[str], quote: str) -> str | None:
    """The paragraph a quote was taken from (its longest piece found there)."""
    pieces = sorted(
        (normalized(p).strip(" '\".,;:") for p in re.split(r"\.\.\.|\u2026", quote or "")), key=len, reverse=True
    )
    piece = next((p for p in pieces if p), "")
    if not piece:
        return None
    return next((text for text in paras if piece in normalized(text)), None)


def normalized(text: str) -> str:
    """Lowercase, quotes and dashes folded, whitespace collapsed: how a quote
    is matched against the article it claims to come from."""
    text = (text or "").lower()
    for a, b in (("\u2018", "'"), ("\u2019", "'"), ("\u201c", '"'), ("\u201d", '"'), ("\u2013", "-"), ("\u2014", "-")):
        text = text.replace(a, b)
    return " ".join(text.replace("\u2026", " ").split())


def quote_in(text: str, quote: str, min_len: int = 20) -> bool:
    """True when ``quote`` (ellipses allowed between pieces) is the article's
    own text: every piece of at least a few words appears in it."""
    hay = normalized(text)
    pieces = [normalized(p).strip(" '\".,;:") for p in re.split(r"\.\.\.|\u2026", quote or "")]
    pieces = [p for p in pieces if p]
    if not pieces or sum(len(p) for p in pieces) < min_len:
        return False
    return all(p in hay for p in pieces)


def analysis_evidence(parsed: dict | None, forms_a: list[str], forms_b: list[str]) -> tuple[str, str] | None:
    """(verb, sentence) the analysis gave when it asserted this pair, either way round."""
    if not isinstance(parsed, dict):
        return None
    lower_a = {f.lower() for f in forms_a if f}
    lower_b = {f.lower() for f in forms_b if f}
    for rel in parsed.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        src = str(rel.get("source_name") or "").strip().lower()
        tgt = str(rel.get("target_name") or "").strip().lower()
        if (src in lower_a and tgt in lower_b) or (src in lower_b and tgt in lower_a):
            evidence = " ".join(str(rel.get("evidence") or "").split())
            if evidence:
                return str(rel.get("relationship_type") or ""), evidence[:SENTENCE_MAX]
    return None


async def edge_forms(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, entry_id: uuid.UUID | None = None
) -> list[str]:
    """Names a sentence may use for an endpoint: its display name, its
    aliases, a TTP's technique name, and the forms the autolinker matched in
    this article."""
    from app.services.entry_adjudication import _display_name, _junction_for, _model_for

    model = _model_for(entity_type)
    obj = await db.get(model, entity_id) if model is not None else None
    forms: list[str] = []
    if obj is not None:
        forms.append(_display_name(obj))
        for attr in ("aliases", "name"):
            val = getattr(obj, attr, None)
            if isinstance(val, list):
                forms += [str(v) for v in val if v]
            elif isinstance(val, str) and val not in forms:
                forms.append(val)
    if entry_id is not None:
        junction = await _junction_for(db, entity_type, entry_id, entity_id)
        if junction is not None:
            forms += [str(m) for m in (getattr(junction, "matched_names", None) or []) if m]
    seen: dict[str, str] = {}
    for f in forms:
        seen.setdefault(f.lower(), f)
    return list(seen.values())
