"""Network detection rule templates — Snort/Suricata scaffolding from IOCs."""

from datetime import datetime
from urllib.parse import urlparse


def _next_sid(base: int = 1000000) -> int:
    """Generate a SID. In production, track used SIDs; here we use timestamp-based."""
    return base + int(datetime.utcnow().timestamp()) % 999999


def generate_snort_suricata_rules(iocs: list[dict], rule_prefix: str = "INTELFEED") -> list[dict]:
    """Generate Snort/Suricata rules from IOCs.

    Each IOC dict should have: type (ip, domain, url, hash), value, context (optional).
    Returns list of dicts with: title, rule_content, ioc_type, ioc_value.
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
            result = template_fn(value, context, rule_prefix)
            if result:
                rules.extend(result if isinstance(result, list) else [result])

    return rules


def _ip_rules(ip: str, context: str, prefix: str) -> list[dict]:
    """Generate bidirectional IP detection rules."""
    sid_out = _next_sid()
    sid_in = sid_out + 1

    outbound = (
        f"alert ip $HOME_NET any -> {ip} any "
        f'(msg:"{prefix} - Outbound to suspicious IP {ip}"; '
        f"classtype:trojan-activity; "
        f"sid:{sid_out}; rev:1; "
        f"metadata:created_by intelfeed;)"
    )

    inbound = (
        f"alert ip {ip} any -> $HOME_NET any "
        f'(msg:"{prefix} - Inbound from suspicious IP {ip}"; '
        f"classtype:trojan-activity; "
        f"sid:{sid_in}; rev:1; "
        f"metadata:created_by intelfeed;)"
    )

    return [
        {"title": f"Outbound traffic to {ip}", "rule_content": outbound, "ioc_type": "ip", "ioc_value": ip},
        {"title": f"Inbound traffic from {ip}", "rule_content": inbound, "ioc_type": "ip", "ioc_value": ip},
    ]


def _domain_dns_rule(domain: str, context: str, prefix: str) -> list[dict]:
    """Generate DNS query detection for a domain."""
    sid = _next_sid()

    rule = (
        f"alert dns $HOME_NET any -> any any "
        f'(msg:"{prefix} - DNS lookup for {domain}"; '
        f'dns.query; content:"{domain}"; nocase; '
        f"classtype:trojan-activity; "
        f"sid:{sid}; rev:1; "
        f"metadata:created_by intelfeed;)"
    )

    sid2 = sid + 1
    tls_rule = (
        f"alert tls $HOME_NET any -> $EXTERNAL_NET any "
        f'(msg:"{prefix} - TLS SNI match for {domain}"; '
        f'tls.sni; content:"{domain}"; nocase; '
        f"classtype:trojan-activity; "
        f"sid:{sid2}; rev:1; "
        f"metadata:created_by intelfeed;)"
    )

    return [
        {"title": f"DNS query for {domain}", "rule_content": rule, "ioc_type": "domain", "ioc_value": domain},
        {"title": f"TLS SNI match for {domain}", "rule_content": tls_rule, "ioc_type": "domain", "ioc_value": domain},
    ]


def _url_rule(url: str, context: str, prefix: str) -> list[dict]:
    """Generate an HTTP request detection rule for a URL indicator.

    Indicators are often written without a scheme ("evil.com/payload.exe"), so
    one is assumed rather than letting urlparse fold the whole string into the
    path and leave the rule with an empty host.
    """
    candidate = url if "://" in url else f"http://{url}"
    parsed = urlparse(candidate)

    host = parsed.netloc
    if not host:
        return []

    uri = parsed.path or "/"
    if parsed.query:
        uri = f"{uri}?{parsed.query}"

    sid = _next_sid()
    rule = (
        f"alert http $HOME_NET any -> $EXTERNAL_NET any "
        f'(msg:"{prefix} - HTTP request to suspicious URL {url}"; '
        f'http.host; content:"{host}"; nocase; '
        f'http.uri; content:"{uri}"; nocase; '
        f"classtype:trojan-activity; "
        f"sid:{sid}; rev:1; "
        f"metadata:created_by intelfeed;)"
    )

    return [
        {
            "title": f"HTTP request to {url}",
            "rule_content": rule,
            "ioc_type": "url",
            "ioc_value": url,
        }
    ]


def _hash_rule(hash_value: str, context: str, prefix: str) -> list[dict]:
    """Generate a comment-based rule stub for hash IOCs (hashes can't be detected in network traffic)."""
    hash_len = len(hash_value)
    if hash_len == 32:
        hash_type = "MD5"
    elif hash_len == 40:
        hash_type = "SHA1"
    elif hash_len == 64:
        hash_type = "SHA256"
    else:
        hash_type = "unknown"

    stub = (
        f"# {prefix} - File hash indicator ({hash_type}): {hash_value}\n"
        f"# Context: {context}\n"
        f"# Note: File hashes cannot be detected via network rules.\n"
        f"# Consider using YARA rules or EDR-based detection for this indicator.\n"
        f"# If this hash is associated with a known dropper URL or C2 domain,\n"
        f"# create network rules for those IOCs instead."
    )

    return [
        {
            "title": f"Hash indicator stub ({hash_type}): {hash_value[:16]}...",
            "rule_content": stub,
            "ioc_type": "hash",
            "ioc_value": hash_value,
        }
    ]


TEMPLATE_MAP = {
    "ip": _ip_rules,
    "ipv4": _ip_rules,
    "ipv6": _ip_rules,
    "ip_address": _ip_rules,
    "domain": _domain_dns_rule,
    "hostname": _domain_dns_rule,
    "fqdn": _domain_dns_rule,
    "url": _url_rule,
    "uri": _url_rule,
    "hash": _hash_rule,
    "md5": _hash_rule,
    "sha1": _hash_rule,
    "sha256": _hash_rule,
    "file_hash": _hash_rule,
}
