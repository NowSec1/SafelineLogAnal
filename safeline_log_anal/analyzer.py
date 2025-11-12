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
            "path_traversal",
            r"\.\./|\.\.\\|etc/passwd|boot\.ini",
            "Directory traversal indicators",
        ),
        (
            "command_injection",
            r"(?i)(;|&&|\|\|)\s*(cat|ls|bash|sh|cmd|powershell|wget|curl)",
            "Command injection invoking shell commands",
        ),
        (
            "deserialization",
            r"(?i)java\.lang|org\.apache\.commons|ObjectInputStream",
            "Java deserialization gadget references",
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
            "nosql",
            r"(?i)\$where|\$ne|\$gt|\$regex",
            "NoSQL injection operators",
        ),
        (
            "ssi",
            r"(?i)<!--#(include|exec|echo)",
            "Server-side include directives",
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
