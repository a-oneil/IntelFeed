"""YARA rule templates — scaffolding from IOCs and file indicators."""


def generate_yara_rules(
    iocs: list[dict],
    rule_name_prefix: str = "intelfeed",
    author: str = "IntelFeed",
) -> list[dict]:
    """Generate YARA rules from IOCs.

    Each IOC dict should have: type, value, context (optional).
    Supported types: hash (md5/sha1/sha256), domain, url, ip, string/pattern.
    Returns list of dicts with: title, rule_content, template_type.
    """
    rules = []
    for ioc in iocs:
        ioc_type = ioc.get("type", "").lower()
        value = ioc.get("value", "").strip()
        context = ioc.get("context", "Threat intelligence indicator")

        if not value:
            continue

        template_fn = TEMPLATE_MAP.get(ioc_type)
        if template_fn:
            result = template_fn(value, context, rule_name_prefix, author)
            if result:
                rules.append(result)

    return rules


def _safe_rule_name(prefix: str, label: str) -> str:
    """Create a valid YARA rule name from a prefix and label."""
    name = f"{prefix}_{label}"
    return "".join(c if c.isalnum() or c == "_" else "_" for c in name)[:128]


def _hash_rule(value: str, context: str, prefix: str, author: str) -> dict:
    """Generate a YARA rule that matches files by hash."""
    hash_len = len(value)
    if hash_len == 32:
        hash_type = "md5"
        hash_func = "hash.md5(0, filesize)"
    elif hash_len == 40:
        hash_type = "sha1"
        hash_func = "hash.sha1(0, filesize)"
    elif hash_len == 64:
        hash_type = "sha256"
        hash_func = "hash.sha256(0, filesize)"
    else:
        hash_type = "unknown"
        hash_func = "hash.sha256(0, filesize)"

    rule_name = _safe_rule_name(prefix, f"{hash_type}_{value[:12]}")

    content = f"""import "hash"

rule {rule_name} {{
    meta:
        author = "{author}"
        description = "{context}"
        hash_{hash_type} = "{value}"
        date = "auto-generated"

    condition:
        {hash_func} == "{value.lower()}"
}}
"""
    return {
        "title": f"File hash detection ({hash_type}): {value[:16]}...",
        "rule_content": content,
        "template_type": "hash",
    }


def _string_rule(value: str, context: str, prefix: str, author: str) -> dict:
    """Generate a YARA rule that matches files containing a string."""
    rule_name = _safe_rule_name(prefix, f"string_{value[:20]}")
    # Escape quotes in the value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')

    content = f"""rule {rule_name} {{
    meta:
        author = "{author}"
        description = "{context}"
        date = "auto-generated"

    strings:
        $s1 = "{escaped}" ascii wide nocase

    condition:
        any of them
}}
"""
    return {
        "title": f"String match: {value[:40]}",
        "rule_content": content,
        "template_type": "generic",
    }


def _domain_rule(domain: str, context: str, prefix: str, author: str) -> dict:
    """Generate a YARA rule that detects domain strings in files (e.g., config files, malware)."""
    rule_name = _safe_rule_name(prefix, f"domain_{domain.replace('.', '_')}")

    content = f"""rule {rule_name} {{
    meta:
        author = "{author}"
        description = "Detects files referencing domain: {domain}"
        reference = "{context}"
        date = "auto-generated"

    strings:
        $domain = "{domain}" ascii wide nocase

    condition:
        any of them
}}
"""
    return {
        "title": f"Domain in file: {domain}",
        "rule_content": content,
        "template_type": "generic",
    }


def _url_rule(url: str, context: str, prefix: str, author: str) -> dict:
    """Generate a YARA rule that detects URL strings in files."""
    rule_name = _safe_rule_name(prefix, f"url_{url[:30]}")
    escaped = url.replace("\\", "\\\\").replace('"', '\\"')

    content = f"""rule {rule_name} {{
    meta:
        author = "{author}"
        description = "Detects files referencing URL: {url}"
        reference = "{context}"
        date = "auto-generated"

    strings:
        $url = "{escaped}" ascii wide nocase

    condition:
        any of them
}}
"""
    return {
        "title": f"URL in file: {url[:50]}",
        "rule_content": content,
        "template_type": "generic",
    }


def _ip_rule(ip: str, context: str, prefix: str, author: str) -> dict:
    """Generate a YARA rule that detects IP address strings in files."""
    rule_name = _safe_rule_name(prefix, f"ip_{ip.replace('.', '_')}")

    content = f"""rule {rule_name} {{
    meta:
        author = "{author}"
        description = "Detects files referencing IP: {ip}"
        reference = "{context}"
        date = "auto-generated"

    strings:
        $ip = "{ip}" ascii wide

    condition:
        any of them
}}
"""
    return {
        "title": f"IP in file: {ip}",
        "rule_content": content,
        "template_type": "generic",
    }


def generate_pe_template(rule_name: str, author: str = "IntelFeed") -> str:
    """Generate a PE file detection template."""
    return f"""import "pe"

rule {rule_name} {{
    meta:
        author = "{author}"
        description = "PE file detection template"
        date = "auto-generated"

    strings:
        $s1 = "PLACEHOLDER" ascii wide nocase

    condition:
        pe.is_pe and any of ($s*)
}}
"""


def generate_elf_template(rule_name: str, author: str = "IntelFeed") -> str:
    """Generate an ELF file detection template."""
    return f"""import "elf"

rule {rule_name} {{
    meta:
        author = "{author}"
        description = "ELF binary detection template"
        date = "auto-generated"

    strings:
        $s1 = "PLACEHOLDER" ascii

    condition:
        elf.type == elf.ET_EXEC and any of ($s*)
}}
"""


def generate_document_template(rule_name: str, author: str = "IntelFeed") -> str:
    """Generate a document/maldoc detection template."""
    return f"""rule {rule_name} {{
    meta:
        author = "{author}"
        description = "Malicious document detection template"
        date = "auto-generated"

    strings:
        $magic_ole = {{ D0 CF 11 E0 A1 B1 1A E1 }}
        $magic_zip = {{ 50 4B 03 04 }}
        $macro1 = "AutoOpen" ascii nocase
        $macro2 = "Auto_Open" ascii nocase
        $macro3 = "Document_Open" ascii nocase
        $suspicious1 = "Shell" ascii nocase
        $suspicious2 = "WScript" ascii nocase
        $suspicious3 = "powershell" ascii nocase

    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        any of ($macro*) and
        any of ($suspicious*)
}}
"""


def generate_memory_template(rule_name: str, author: str = "IntelFeed") -> str:
    """Generate a memory scan detection template."""
    return f"""rule {rule_name} {{
    meta:
        author = "{author}"
        description = "Memory scan detection template"
        date = "auto-generated"
        scan_context = "memory"

    strings:
        $s1 = "PLACEHOLDER" ascii wide

    condition:
        any of them
}}
"""


TEMPLATE_MAP = {
    "hash": _hash_rule,
    "md5": _hash_rule,
    "sha1": _hash_rule,
    "sha256": _hash_rule,
    "file_hash": _hash_rule,
    "domain": _domain_rule,
    "hostname": _domain_rule,
    "fqdn": _domain_rule,
    "url": _url_rule,
    "uri": _url_rule,
    "ip": _ip_rule,
    "ipv4": _ip_rule,
    "ipv6": _ip_rule,
    "ip_address": _ip_rule,
    "string": _string_rule,
    "pattern": _string_rule,
}

SCAFFOLDING_TEMPLATES = {
    "pe_file": generate_pe_template,
    "elf_file": generate_elf_template,
    "document": generate_document_template,
    "memory": generate_memory_template,
}
