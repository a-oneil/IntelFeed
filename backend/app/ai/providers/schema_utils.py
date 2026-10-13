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
    """Normalize a schema for OpenAI's ``json_schema`` ``strict: true`` mode:
    every object gets ``required`` filled and ``additionalProperties: false``
    (recursively, through ``items`` and ``anyOf``/``oneOf``), and a property
    the source schema left optional is kept by making it nullable rather than
    silently mandatory. Callers should expect optional fields to come back as
    ``null`` rather than absent.

    A free-form object (no declared ``properties``) is left untouched —
    strict mode has no properties to enumerate as required, so the vendor
    will reject it with its own error rather than this function fabricating
    one.
    """

    def normalize(node) -> None:
        if not isinstance(node, dict):
            return

        for key in strip:
            node.pop(key, None)

        node_type = node.get("type")
        types = node_type if isinstance(node_type, list) else [node_type] if node_type else []

        if "object" in types and node.get("properties"):
            properties = node["properties"]
            original_required = set(node.get("required") or [])
            all_keys = list(properties.keys())
            for key in all_keys:
                prop = properties[key]
                # Normalize the child while it's still an "object" — making
                # it nullable widens its type and would hide it from this
                # branch on a later pass.
                normalize(prop)
                if key not in original_required:
                    _make_nullable(prop)
            node["required"] = all_keys
            node["additionalProperties"] = False

        if "array" in types and isinstance(node.get("items"), dict):
            normalize(node["items"])

        for combinator in ("anyOf", "oneOf", "allOf"):
            for sub in node.get(combinator) or []:
                normalize(sub)

    cloned = copy.deepcopy(schema)
    normalize(cloned)
    return cloned


def _make_nullable(prop: dict) -> None:
    """Widen a property's ``type``/``enum``/combinator to admit ``null`` in place.

    Handles three shapes: an explicit ``type`` (widened to a list with
    ``"null"`` added), an ``enum`` (gets a ``None`` member), and a property
    with neither — described only via ``anyOf``/``oneOf`` — which gets a
    ``{"type": "null"}`` branch appended to whichever combinator it uses.
    """
    if not isinstance(prop, dict):
        return
    prop_type = prop.get("type")
    if prop_type is not None:
        if isinstance(prop_type, list):
            if "null" not in prop_type:
                prop_type.append("null")
        elif prop_type != "null":
            prop["type"] = [prop_type, "null"]

    enum = prop.get("enum")
    if isinstance(enum, list) and None not in enum:
        enum.append(None)

    if prop_type is None and enum is None:
        for combinator in ("anyOf", "oneOf"):
            options = prop.get(combinator)
            if isinstance(options, list):
                already_nullable = any(isinstance(o, dict) and o.get("type") == "null" for o in options)
                if not already_nullable:
                    options.append({"type": "null"})
                break
