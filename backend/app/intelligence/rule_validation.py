"""BE-4: Rule validation engine.

Syntax-only validation for 9 detection rule formats:
SIGMA, Splunk SPL, KQL, Elastic QL (EQL / ES|QL), CrowdStrike QL, Snort/Suricata,
YARA, Nuclei, Panther.
"""

import re
from dataclasses import dataclass, field

import yaml


@dataclass
class ValidationError:
    line: int | None
    column: int | None
    severity: str  # "error" | "warning"
    message: str


@dataclass
class ValidationResult:
    valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


def _check_balanced(text: str, open_char: str, close_char: str) -> list[ValidationError]:
    """Check for balanced characters (parens, brackets, braces, quotes)."""
    errors = []
    count = 0
    for i, ch in enumerate(text):
        if ch == open_char:
            count += 1
        elif ch == close_char:
            count -= 1
        if count < 0:
            line = text[:i].count("\n") + 1
            errors.append(
                ValidationError(line=line, column=None, severity="error", message=f"Unmatched '{close_char}'")
            )
            count = 0
    if count > 0:
        errors.append(
            ValidationError(
                line=None,
                column=None,
                severity="error",
                message=f"Unmatched '{open_char}' — missing {count} closing '{close_char}'",
            )
        )
    return errors


def _check_balanced_quotes(text: str) -> list[ValidationError]:
    errors = []
    for quote_char in ['"', "'"]:
        # Count quotes outside escaped sequences
        count = 0
        i = 0
        while i < len(text):
            if text[i] == "\\" and i + 1 < len(text):
                i += 2
                continue
            if text[i] == quote_char:
                count += 1
            i += 1
        if count % 2 != 0:
            errors.append(
                ValidationError(line=None, column=None, severity="error", message=f"Unmatched {quote_char} quote")
            )
    return errors


def _strip_comments(text: str) -> str:
    """Drop ``//`` and ``/* */`` comments (KQL, EQL, ES|QL) outside string literals.

    Published hunting queries open with comment lines ("// processes that
    don't …"); an apostrophe there is prose, not an unbalanced quote. KQL
    verbatim strings (``@"C:\\Temp\\"``) take no backslash escapes.
    """
    out: list[str] = []
    i, n = 0, len(text)
    quote: str | None = None
    verbatim = False
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and verbatim:
                out.append("/")  # a literal backslash, not an escape
                i += 1
                continue
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            verbatim = i > 0 and text[i - 1] == "@"
            out.append(ch)
            i += 1
            continue
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _check_balanced_code(text: str) -> list[ValidationError]:
    """Bracket and quote balance with comments left out."""
    code = _strip_comments(text)
    errors = _check_balanced(code, "(", ")")
    errors.extend(_check_balanced(code, "[", "]"))
    errors.extend(_check_balanced_quotes(code))
    return errors


def validate_sigma(rule_content: str) -> ValidationResult:
    """Validate SIGMA YAML rule structure."""
    errors = []
    suggestions = []

    try:
        rule = yaml.safe_load(rule_content)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        return ValidationResult(
            valid=False,
            errors=[
                ValidationError(
                    line=mark.line + 1 if mark else None, column=None, severity="error", message=f"Invalid YAML: {e}"
                )
            ],
        )

    if not isinstance(rule, dict):
        return ValidationResult(
            valid=False,
            errors=[
                ValidationError(line=None, column=None, severity="error", message="SIGMA rule must be a YAML mapping")
            ],
        )

    for required_field in ["title", "status", "logsource", "detection"]:
        if required_field not in rule:
            errors.append(
                ValidationError(
                    line=None, column=None, severity="error", message=f"Required field '{required_field}' missing"
                )
            )

    if "logsource" in rule:
        ls = rule["logsource"]
        if isinstance(ls, dict) and not any(k in ls for k in ["category", "product", "service"]):
            errors.append(
                ValidationError(
                    line=None,
                    column=None,
                    severity="error",
                    message="Logsource must have at least one of: category, product, service",
                )
            )

    if "detection" in rule:
        det = rule["detection"]
        if isinstance(det, dict):
            if "condition" not in det:
                errors.append(
                    ValidationError(
                        line=None, column=None, severity="error", message="Detection section must include 'condition'"
                    )
                )
            selections = [k for k in det if k not in ("condition", "timeframe")]
            if not selections:
                errors.append(
                    ValidationError(
                        line=None,
                        column=None,
                        severity="error",
                        message="Detection must have at least one named selection",
                    )
                )

    if "level" not in rule:
        suggestions.append("Consider adding 'level' field (informational, low, medium, high, critical)")
    if "falsepositives" not in rule:
        suggestions.append("Consider adding 'falsepositives' section to document known FP scenarios")
    if "tags" not in rule:
        suggestions.append("Consider adding ATT&CK tags (e.g., attack.execution, attack.t1059.001)")

    has_errors = any(e.severity == "error" for e in errors)
    return ValidationResult(valid=not has_errors, errors=errors, suggestions=suggestions)


def validate_splunk_spl(rule_content: str) -> ValidationResult:
    """Basic SPL syntax validation."""
    errors = []
    suggestions = []

    content = rule_content.strip()
    if not content:
        return ValidationResult(
            valid=False, errors=[ValidationError(line=None, column=None, severity="error", message="Empty SPL query")]
        )

    errors.extend(_check_balanced(content, "(", ")"))
    errors.extend(_check_balanced(content, "[", "]"))
    errors.extend(_check_balanced_quotes(content))

    # Check for index= specification
    if "index=" not in content.lower():
        suggestions.append("Consider specifying an index (e.g., index=main)")

    has_errors = any(e.severity == "error" for e in errors)
    return ValidationResult(valid=not has_errors, errors=errors, suggestions=suggestions)


def validate_kql(rule_content: str) -> ValidationResult:
    """Basic KQL (Kusto Query Language) syntax validation."""
    errors = []
    suggestions = []

    content = rule_content.strip()
    if not content:
        return ValidationResult(
            valid=False, errors=[ValidationError(line=None, column=None, severity="error", message="Empty KQL query")]
        )

    errors.extend(_check_balanced_code(content))

    # KQL should typically start with a table name
    first_token = content.split()[0] if content.split() else ""
    if first_token.startswith("|"):
        suggestions.append("KQL queries typically start with a table name before pipe operators")

    has_errors = any(e.severity == "error" for e in errors)
    return ValidationResult(valid=not has_errors, errors=errors, suggestions=suggestions)


def validate_elastic_ql(rule_content: str) -> ValidationResult:
    """Basic Elastic Query Language validation."""
    errors = []
    suggestions = []

    content = rule_content.strip()
    if not content:
        return ValidationResult(
            valid=False, errors=[ValidationError(line=None, column=None, severity="error", message="Empty EQL query")]
        )

    errors.extend(_check_balanced_code(content))

    # EQL typically starts with event category; ES|QL with FROM
    eql_categories = ["process", "file", "network", "registry", "any", "sequence", "join"]
    words = _strip_comments(content).split()
    first_word = words[0].lower() if words else ""
    if first_word not in eql_categories and first_word not in ("where", "from"):
        suggestions.append(f"EQL queries typically start with an event category: {', '.join(eql_categories)}")

    has_errors = any(e.severity == "error" for e in errors)
    return ValidationResult(valid=not has_errors, errors=errors, suggestions=suggestions)


def validate_crowdstrike_ql(rule_content: str) -> ValidationResult:
    """Basic CrowdStrike Query Language validation."""
    errors = []
    suggestions = []

    content = rule_content.strip()
    if not content:
        return ValidationResult(
            valid=False,
            errors=[ValidationError(line=None, column=None, severity="error", message="Empty CrowdStrike QL query")],
        )

    errors.extend(_check_balanced(content, "(", ")"))
    errors.extend(_check_balanced(content, "[", "]"))
    errors.extend(_check_balanced_quotes(content))

    # CrowdStrike QL uses event_simpleName commonly
    if "event_simplename" not in content.lower() and "event_platform" not in content.lower():
        suggestions.append("Consider filtering by event_simpleName or event_platform")

    has_errors = any(e.severity == "error" for e in errors)
    return ValidationResult(valid=not has_errors, errors=errors, suggestions=suggestions)


def validate_snort_suricata(rule_content: str) -> ValidationResult:
    """Basic Snort/Suricata rule syntax validation."""
    errors = []
    suggestions = []

    content = rule_content.strip()
    if not content:
        return ValidationResult(
            valid=False,
            errors=[ValidationError(line=None, column=None, severity="error", message="Empty Snort/Suricata rule")],
        )

    # Basic structure: action protocol src_addr src_port direction dst_addr dst_port (options)
    valid_actions = {"alert", "log", "pass", "drop", "reject", "sdrop"}
    valid_protocols = {"tcp", "udp", "icmp", "ip", "http", "ftp", "tls", "smb", "dns", "pkthdr"}
    valid_directions = {"->", "<>"}

    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(None, 7)
        if len(parts) < 7:
            errors.append(
                ValidationError(
                    line=i,
                    column=None,
                    severity="error",
                    message="Rule must have at least: action protocol src_addr src_port direction dst_addr dst_port",
                )
            )
            continue

        action = parts[0].lower()
        if action not in valid_actions:
            errors.append(
                ValidationError(
                    line=i,
                    column=None,
                    severity="error",
                    message=f"Invalid action '{action}'. Valid: {', '.join(sorted(valid_actions))}",
                )
            )

        protocol = parts[1].lower()
        if protocol not in valid_protocols:
            errors.append(
                ValidationError(line=i, column=None, severity="warning", message=f"Unknown protocol '{protocol}'")
            )

        direction = parts[4]
        if direction not in valid_directions:
            errors.append(
                ValidationError(
                    line=i,
                    column=None,
                    severity="error",
                    message=f"Invalid direction '{direction}'. Must be '->' or '<>'",
                )
            )

        # Check for options block
        if "(" not in line or ")" not in line:
            errors.append(
                ValidationError(
                    line=i,
                    column=None,
                    severity="error",
                    message="Rule must have an options block enclosed in parentheses",
                )
            )
        else:
            options = line[line.index("(") + 1 : line.rindex(")")]
            if "sid:" not in options:
                errors.append(
                    ValidationError(
                        line=i, column=None, severity="error", message="Rule must include 'sid:' in options"
                    )
                )
            if "msg:" not in options:
                suggestions.append(f"Line {i}: Consider adding 'msg:' to describe the rule")

    has_errors = any(e.severity == "error" for e in errors)
    return ValidationResult(valid=not has_errors, errors=errors, suggestions=suggestions)


def validate_yara(rule_content: str) -> ValidationResult:
    """Basic YARA rule syntax validation."""
    errors = []
    suggestions = []

    content = rule_content.strip()
    if not content:
        return ValidationResult(
            valid=False, errors=[ValidationError(line=None, column=None, severity="error", message="Empty YARA rule")]
        )

    errors.extend(_check_balanced(content, "{", "}"))
    errors.extend(_check_balanced(content, "(", ")"))

    # Check for rule keyword
    rule_match = re.search(r"\brule\s+(\w+)", content)
    if not rule_match:
        errors.append(
            ValidationError(line=None, column=None, severity="error", message="YARA rule must start with 'rule <name>'")
        )
    else:
        # Check for required sections
        if "condition:" not in content:
            errors.append(
                ValidationError(
                    line=None, column=None, severity="error", message="YARA rule must have a 'condition:' section"
                )
            )

        if "strings:" not in content and "condition:" in content:
            # condition-only rules are valid but worth noting
            suggestions.append("Consider adding a 'strings:' section for string-based matching")

        if "meta:" not in content:
            suggestions.append("Consider adding a 'meta:' section with author, description, and date")

    has_errors = any(e.severity == "error" for e in errors)
    return ValidationResult(valid=not has_errors, errors=errors, suggestions=suggestions)


def _validate_panther(content: str) -> ValidationResult:
    """Basic validation for Panther Python detection rules."""
    errors: list[ValidationError] = []
    suggestions: list[str] = []

    if not content.strip():
        errors.append(ValidationError(line=1, column=None, severity="error", message="Empty rule content"))
        return ValidationResult(valid=False, errors=errors)

    # Must have a rule() function
    if not re.search(r"def\s+rule\s*\(", content):
        errors.append(
            ValidationError(
                line=None, column=None, severity="error", message="Missing required 'def rule(event)' function"
            )
        )

    # Check balanced parens/brackets
    errors.extend(_check_balanced(content, "(", ")"))
    errors.extend(_check_balanced(content, "[", "]"))
    errors.extend(_check_balanced(content, "{", "}"))

    # Suggestions
    if not re.search(r"def\s+title\s*\(", content):
        suggestions.append("Consider adding a 'def title(event)' function for dynamic alert titles")

    has_errors = any(e.severity == "error" for e in errors)
    return ValidationResult(valid=not has_errors, errors=errors, suggestions=suggestions)


def validate_rule(rule_type: str, rule_content: str) -> ValidationResult:
    """Route to appropriate validator."""
    validators = {
        "sigma": validate_sigma,
        "splunk_spl": validate_splunk_spl,
        "kql": validate_kql,
        "elastic_ql": validate_elastic_ql,
        "crowdstrike_ql": validate_crowdstrike_ql,
        "snort_suricata": validate_snort_suricata,
        "yara": validate_yara,
        "nuclei": validate_sigma,  # YAML-based, reuse Sigma YAML validator
        "panther": _validate_panther,
    }

    validator = validators.get(rule_type)
    if not validator:
        return ValidationResult(
            valid=False,
            errors=[
                ValidationError(
                    line=None,
                    column=None,
                    severity="error",
                    message=f"Unknown rule type: {rule_type}. Supported: {', '.join(validators.keys())}",
                )
            ],
        )

    return validator(rule_content)
