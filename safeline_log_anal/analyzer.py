"""Tools for analysing Safeline web attack alerts."""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

import pandas as pd


@dataclass(frozen=True)
class AttackSignature:
    """A simple representation of an attack pattern we want to detect."""

    name: str
    pattern: re.Pattern[str]
    description: str


def _compile_signatures() -> List[AttackSignature]:
    """Build a list of attack signatures used for payload inspection."""

    raw_patterns: Sequence[Tuple[str, str, str]] = (
        (
            "csrf_indicator",
            r"(?i)(?:csrf|xsrf)[-_]?token\s*=|cross-site\s*request\s*forgery",
            "Indicators of CSRF attempts such as forged tokens or anti-CSRF bypass markers",
        ),
        (
            "ssrf_internal",
            r"(?i)(?:https?|file|gopher|ftp)://(?:169\.254\.169\.254|169\.254\.\d+\.\d+|localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|metadata\.googleinternal|169\.254\.169\.253)",
            "Server-side request forgery attempts targeting internal metadata or loopback endpoints",
        ),
        (
            "denial_of_service",
            r"(?i)(?:ping\s+-[tn]\s*\d+|waitfor\s+delay\s+'00:00:\d+|sleep\s*\(\s*\d{2,}|benchmark\s*\(\s*\d+)",
            "Payloads attempting to exhaust resources through long waits or repeated network probes",
        ),
        (
            "backdoor_shell",
            r"(?i)(?:c99shell|r57shell|cmdshell|webshell|phpspy|backdoor)",
            "Classic web shell and backdoor identifiers",
        ),
        (
            "sql_union",
            r"(?i)union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table",
            "SQL keywords suggesting data extraction or manipulation",
        ),
        (
            "sql_boolean",
            r"(?i)(or|and)\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(",
            "Boolean or time-based SQL injection patterns",
        ),
        (
            "sql_comment",
            r"(?i)(;--|--\s|#|/\*.*?\*/)",
            "SQL style comments often used to terminate legitimate queries",
        ),
        (
            "xss_script",
            r"(?i)<\s*script|onerror\s*=|onload\s*=|javascript:\s*|document\.cookie",
            "Common cross-site scripting script payload markers",
        ),
        (
            "xss_html_event",
            r"(?i)<\s*(iframe|svg|img|video)[^>]*on[a-z]+\s*=",
            "HTML event handlers often used in reflected XSS payloads",
        ),
        (
            "xss_alert",
            r"(?i)alert\s*\(|prompt\s*\(|confirm\s*\(",
            "Classic reflected XSS payload invoking browser dialogs",
        ),
        (
            "xxe_attack",
            r"(?i)<!DOCTYPE\s+|<!ENTITY\s+|SYSTEM\s+['\"](?:file|http|ftp):",
            "XML external entity definitions leaking local resources",
        ),
        (
            "path_traversal",
            r"\.\./|\.\.\\|etc/passwd|boot\.ini",
            "Directory traversal indicators",
        ),
        (
            "command_injection",
            r"(?i)(?:^|[;&|])\s*(cat|ls|bash|sh|cmd|powershell|wget|curl|nslookup|whoami)\b",
            "Command injection invoking shell commands",
        ),
        (
            "deserialization",
            r"(?i)java\.lang|org\.apache\.commons|ObjectInputStream",
            "Java deserialization gadget references",
        ),
        (
            "code_execution_runtime",
            r"(?i)(?:runtime\.getruntime\(\)\.exec|ProcessBuilder\s*\(|system\s*\(|popen\s*\()",
            "Direct runtime or process execution primitives",
        ),
        (
            "code_injection_dynamic",
            r"(?i)(?:new\s+Function\s*\(|__import__\s*\(|process\.mainModule\.require|eval\s*\(|exec\s*\()",
            "Dynamic code construction or evaluation markers",
        ),
        (
            "php_code",
            r"(?i)<\?php|system\s*\(|exec\s*\(|shell_exec\s*\(|base64_decode\s*\(",
            "Embedded PHP code execution patterns",
        ),
        (
            "ldap",
            r"(?i)\(\|(objectClass|userPassword)|\(uid=\*\)",
            "LDAP injection patterns",
        ),
        (
            "xpath_injection",
            r"(?i)(?:contains\s*\(|count\s*\(|starts-with\s*\(|name\s*\(|string\s*\()",
            "XPath function usage typical in XPath injection payloads",
        ),
        (
            "nosql",
            r"(?i)\$where|\$ne|\$gt|\$regex",
            "NoSQL injection operators",
        ),
        (
            "ssi",
            r"(?i)<!--#(include|exec|echo)",
            "Server-side include directives",
        ),
        (
            "mysql_xml_extractvalue",
            r"(?i)extractvalue\s*\(\s*1\s*,",
            "MySQL EXTRACTVALUE exploitation technique",
        ),
        (
            "hash_md5",
            r"(?i)md5\s*\(",
            "Suspicious usage of MD5 hashing commonly found in proof-of-concept payloads",
        ),
        (
            "mssql_hashbytes",
            r"(?i)sys\.fn_sqlvarbasetostr|hashbytes\s*\(",
            "Microsoft SQL Server HASHBYTES abuse",
        ),
        (
            "file_include",
            r"(?i)(?:include|require|include_once|require_once)\s*\(|php://input|php://filter",
            "File inclusion primitives that allow executing remote or local files",
        ),
        (
            "file_upload_attempt",
            r"(?i)content-disposition:\s*form-data;\s*name=\"file\"|filename=|upload_file",
            "Multipart form uploads attempting to deliver files",
        ),
        (
            "file_reading",
            r"(?i)(?:\bcat\b|\btype\b|\bmore\b|\btail\b)\s+(?:[A-Z]:\\|/|\\)",
            "Commands attempting to read sensitive files",
        ),
        (
            "file_discovery",
            r"(?i)/etc/passwd|/etc/shadow|/etc/shells|system32\\drivers\\etc\\hosts|c://windows//temp//",
            "Attempts to read sensitive operating system files",
        ),
        (
            "file_modification",
            r"(?i)(?:echo\s+.+>\s*(?:/|[A-Z]:\\)|sed\s+-i|truncate\s|replace\s+file|touch\s+(?:/|[A-Z]:\\))",
            "Commands modifying files on disk",
        ),
        (
            "file_deletion",
            r"(?i)(?:rm\s+-rf|del\s+/f|erase\s|unlink\s*\()",
            "Commands deleting files from the system",
        ),
        (
            "xss_event_handler",
            r"(?i)on[a-z]+\s*=\s*['\"]",
            "Inline event handler likely originating from an XSS payload",
        ),
        (
            "php_template_injection",
            r"(?i)\$\{\s*@?print|\$\{\s*\@?eval",
            "PHP or template injection attempting to execute code",
        ),
        (
            "generic_template_injection",
            r"(?i)(?:\{\{.*?\}\}|<%.*?%>|\$\{.*?\})",
            "Template expression injection markers across common engines",
        ),
        (
            "open_redirect",
            r"(?i)(?:window\.location|document\.location|location\.href|http-equiv\s*=\s*\"refresh\")",
            "Client-side or meta refresh redirects to attacker controlled destinations",
        ),
        (
            "clickjacking",
            r"(?i)<iframe[^>]+style=['\"][^'\"]*(?:opacity:0|display:none)[^'\"]*['\"]",
            "Hidden iframe intended for clickjacking attacks",
        ),
        (
            "permission_misconfiguration",
            r"(?i)(?:chmod\s+777|grant\s+all\s+privileges|chgrp\s+\w+\s+/)",
            "Commands that weaken permission boundaries",
        ),
        (
            "insecure_configuration",
            r"(?i)(?:\.git/config|\.svn/entries|\.env|web\.config|application\.yml|id_rsa)",
            "Discovery of configuration artefacts exposing sensitive data",
        ),
        (
            "information_disclosure",
            r"(?i)(?:password=|credit_card|ssn=|secret_key|aws_access_key_id)",
            "Indicators of leaked secrets or personal data",
        ),
        (
            "unauthorized_access_attempt",
            r"(?i)/(?:admin|manager|phpmyadmin|wp-admin|private|secret)",
            "Probing for administrative or restricted endpoints",
        ),
        (
            "scanner_activity",
            r"(?i)(?:sqlmap|acunetix|nessus|nikto|nmap|wpscan|masscan)",
            "Known automated scanner identifiers",
        ),
        (
            "horizontal_privilege_bypass",
            r"(?i)(?:as_user|switch_user|impersonate|masquerade|become_user)",
            "Attempts to impersonate another horizontal peer user",
        ),
        (
            "vertical_privilege_bypass",
            r"(?i)(?:is_admin=1|role=admin|makeadmin|setrole\s*\(\s*['\"]admin)",
            "Escalation to elevated privileges",
        ),
        (
            "logic_manipulation",
            r"(?i)(?:price=0|discount=100|amount=0|quantity=9999|coupon=free)",
            "Business logic abuse manipulating transactional values",
        ),
        (
            "crlf_injection",
            r"(?i)(?:%0d%0a|\r\n)[^\s]",
            "Carriage-return line-feed injection into headers",
        ),
        (
            "buffer_overflow",
            r"(?i)(?:A{100,}|B{100,}|C{100,}|%s{50,})",
            "Overly long repeating patterns indicative of overflow testing",
        ),
        (
            "integer_overflow",
            r"(?i)(?:\b214748364[8-9]\b|\b429496729[0-9]\b|\b-214748364[8-9]\b|\b9{9,}\b)",
            "Boundary values targeting integer overflow vulnerabilities",
        ),
        (
            "format_string",
            r"(?i)(?:%[0-9\$]*[diuoxXeEfFgGcsSpPn]\s*){2,}",
            "Printf-style format string exploit markers",
        ),
        (
            "race_condition",
            r"(?i)(?:race\s*condition|toctou|time-of-check|/tmp/lock|lockfile)",
            "Terminology suggesting time-of-check to time-of-use exploitation",
        ),
    )

    return [
        AttackSignature(name=name, pattern=re.compile(pattern), description=description)
        for name, pattern, description in raw_patterns
    ]


ATTACK_SIGNATURES: List[AttackSignature] = _compile_signatures()


def _iter_decoded_variants(payload: str) -> Iterable[str]:
    """Yield different decoded variants of a payload for analysis."""

    seen = set()
    current = payload
    for _ in range(3):
        if current in seen:
            break
        seen.add(current)
        yield current
        decoded = urllib.parse.unquote_plus(current)
        if decoded == current:
            break
        current = decoded


def detect_malicious_payload(payload: Optional[str]) -> Tuple[bool, Optional[str], Optional[str]]:
    """Determine whether the supplied payload appears malicious.

    Parameters
    ----------
    payload:
        The payload string extracted from the alert. ``None`` or empty strings are treated as
        benign.

    Returns
    -------
    Tuple[bool, Optional[str], Optional[str]]
        A tuple containing:
            * ``True`` if the payload matches one of the known attack signatures.
            * The name of the signature that was matched (``None`` when benign).
            * A human readable description for the matched signature (``None`` when benign).
    """

    if not payload:
        return False, None, None

    for variant in _iter_decoded_variants(str(payload)):
        for signature in ATTACK_SIGNATURES:
            if signature.pattern.search(variant):
                return True, signature.name, signature.description

    return False, None, None


def analyze_alerts(
    df: pd.DataFrame,
    payload_column: str = "payload",
    fallback_column: str = "website",
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Analyse the alerts contained within ``df``.

    The function inspects the ``payload`` column if it exists. When that column is not present, it
    falls back to analysing the ``website`` column (which stores the request URL).

    Two dataframes are returned:
        * ``annotated_df``: the original data enriched with analysis metadata.
        * ``benign_df``: a subset containing rows that were considered benign / likely false positive.

    Parameters
    ----------
    df:
        A :class:`pandas.DataFrame` instance representing the Safeline alert export.
    payload_column:
        Name of the column that stores the decoded payload (defaults to ``"payload"`` which is the
        Excel ``AU`` column).
    fallback_column:
        Name of the column that stores the request URL. Used only when the main payload column is
        missing.
    """

    selected_column = None
    if payload_column in df.columns:
        selected_column = payload_column
    elif fallback_column in df.columns:
        selected_column = fallback_column
    else:
        raise KeyError(
            f"Neither '{payload_column}' nor '{fallback_column}' columns are present in the dataset."
        )

    analysis_results = []
    for value in df[selected_column].fillna(""):
        is_malicious, signature_name, signature_description = detect_malicious_payload(value)
        analysis_results.append(
            {
                "analysis_is_malicious": is_malicious,
                "analysis_signature": signature_name,
                "analysis_description": signature_description,
            }
        )

    analysis_df = pd.DataFrame(analysis_results)
    annotated_df = pd.concat([df.reset_index(drop=True), analysis_df], axis=1)

    benign_df = annotated_df[~annotated_df["analysis_is_malicious"]].copy()

    return annotated_df, benign_df
