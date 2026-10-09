"""JSON-schema normalizers shared across providers that constrain structured output.

Each provider's "strict" or "no additional properties" mode imposes slightly
different requirements on an already-written task schema (``app.ai.prompts``),
so these walk the schema defensively rather than assuming it was authored with
any particular provider in mind.
"""

from __future__ import annotations

import copy

# Keywords that at least one OpenAI-compatible server (notably local
# grammar-based engines) has been seen to reject under ``strict: true``.
# Conservative default: length constraints only. ``pattern`` is left alone —
# it's accepted by the servers tested so far.
DEFAULT_STRICT_STRIP_KEYWORDS: tuple[str, ...] = ("minLength", "maxLength")


def enforce_required(schema: dict) -> dict:
    """Recursively require every declared property on object nodes.

    Explicit ``required`` lists are preserved. Shared by the Ollama and
    OpenAI-compatible providers, whose grammar-constrained decoding otherwise
    accepts a degenerate-but-schema-valid ``{}`` for any optional field.
    """

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "object" and node.get("properties") and "required" not in node:
                node["required"] = list(node["properties"].keys())
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    cloned = copy.deepcopy(schema)
    walk(cloned)
    return cloned


def enforce_no_additional_properties(schema: dict) -> dict:
    """Recursively set ``additionalProperties: false`` on every object node.

    Required by Anthropic's and OpenAI's structured-output APIs; preserves
    any explicit value the schema already sets.
    """

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "object" and "additionalProperties" not in node:
                node["additionalProperties"] = False
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    cloned = copy.deepcopy(schema)
    walk(cloned)
    return cloned


def to_openai_strict(schema: dict, strip: tuple[str, ...] = DEFAULT_STRICT_STRIP_KEYWORDS) -> dict:
    """Normalize a schema for OpenAI's ``json_schema`` ``strict: true`` mode.

    Strict mode has stronger requirements than plain ``json_schema``:

    * every object property must be listed in ``required`` (no partial
      ``required`` lists) and every object must set
      ``additionalProperties: false``
    * a property that the source schema left optional is kept in the output
      by making it nullable (``type: [T, "null"]``, with ``null`` added to
      its ``enum`` when present) rather than silently becoming mandatory
    * certain keywords some strict implementations reject are stripped
      (default: ``minLength``/``maxLength``; ``pattern`` is left alone)

    Callers that need this (vs. plain ``enforce_required`` +
    ``enforce_no_additional_properties``) should expect previously-optional
    fields to come back as ``null`` rather than absent — downstream readers
    of the parsed result must tolerate that.
    """

    def walk(node):
        if not isinstance(node, dict):
            if isinstance(node, list):
                for item in node:
                    walk(item)
            return

        for key in strip:
            node.pop(key, None)

        if node.get("type") == "object" and node.get("properties"):
            properties = node["properties"]
            original_required = set(node.get("required") or [])
            all_keys = list(properties.keys())
            for key in all_keys:
                if key not in original_required:
                    prop = properties[key]
                    _make_nullable(prop)
            node["required"] = all_keys
            node["additionalProperties"] = False

        for value in node.values():
            walk(value)

    cloned = copy.deepcopy(schema)
    walk(cloned)
    return cloned


def _make_nullable(prop: dict) -> None:
    """Widen a property's ``type``/``enum`` to admit ``null`` in place."""
    if not isinstance(prop, dict):
        return
    prop_type = prop.get("type")
    if prop_type is None:
        return
    if isinstance(prop_type, list):
        if "null" not in prop_type:
            prop_type.append("null")
    elif prop_type != "null":
        prop["type"] = [prop_type, "null"]
    enum = prop.get("enum")
    if isinstance(enum, list) and None not in enum:
        enum.append(None)
