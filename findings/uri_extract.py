"""
Extract URI-like strings from Snaffler finding text.

Covers http(s), file/res/smb schemes, and Windows UNC paths (normalized to file://host/path).
"""

from __future__ import annotations

import re

# https://example.com/path — stop before common delimiters
_HTTP = re.compile(r"https?://[^\s<>'\"`;\]|)]+", re.IGNORECASE)

# file://, smb://
_FILE_SMB = re.compile(r"(?:file|smb)://[^\s<>'\"`;\]|)]+", re.IGNORECASE)

# res://… (EF metadata) — stop at | ; " or whitespace
_RES = re.compile(r"res://[^\s<>'\"`;\]|]+", re.IGNORECASE)

# UNC inside parentheses: (\\server\share\file.ext)
_UNC_PARENS = re.compile(r"\(\s*(?:\\){2}[^)]+\)")

# UNC inside angle brackets (Share lines): <\\server\share>
_UNC_ANGLE = re.compile(r"<(?:\\){2}[^>]+>")

# Standalone UNC: \\host\share\path...
_UNC_STANDALONE = re.compile(r"(?:\\){2}[\w.-]+(?:\\[^\\\s<>'\"`;|)]+)+")


def _trim_trailing(s: str) -> str:
    return s.rstrip(".,;:!?)\\]\"'")


def _unc_to_file_uri(unc: str) -> str:
    r"""Turn \\server\share\path into file://server/share/path."""
    s = unc.strip()
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1].strip()
    # Strip a stray leading '(' from bad matches
    if s.startswith("("):
        s = s[1:].strip()
    while s.startswith("\\"):
        s = s[1:]
    if not s:
        return unc
    parts = re.split(r"[\\/]+", s)
    parts = [p for p in parts if p]
    if not parts:
        return unc
    host = parts[0]
    segs = parts[1:]
    path = "/" + "/".join(segs) if segs else ""
    return f"file://{host}{path}"


def _non_overlapping(
    text: str, patterns: list[tuple[re.Pattern[str], str]]
) -> list[tuple[int, int, str]]:
    """Collect matches; drop overlaps keeping the longer span."""
    raw: list[tuple[int, int, str, int]] = []
    for pat, kind in patterns:
        for m in pat.finditer(text):
            raw.append((m.start(), m.end(), m.group(0), len(m.group(0))))

    raw.sort(key=lambda x: (x[0], -x[3]))

    kept: list[tuple[int, int, str]] = []
    for start, end, s, _ in raw:
        if any(
            not (end <= ks or start >= ke) for ks, ke, _ in kept
        ):
            continue
        kept.append((start, end, s))

    kept.sort(key=lambda x: x[0])
    return kept


def extract_uris(text: str) -> list[str]:
    """
    Return unique normalized URIs in document order.
    UNC paths become file://host/path; schemes stay as-is (trimmed).
    """
    if not text:
        return []

    patterns: list[tuple[re.Pattern[str], str]] = [
        (_HTTP, "http"),
        (_FILE_SMB, "fs"),
        (_RES, "res"),
        (_UNC_PARENS, "unc_p"),
        (_UNC_ANGLE, "unc_a"),
        (_UNC_STANDALONE, "unc_s"),
    ]

    spans = _non_overlapping(text, patterns)

    seen: set[str] = set()
    out: list[str] = []

    for _s, _e, raw in spans:
        raw = _trim_trailing(raw)
        if not raw:
            continue

        if raw.lower().startswith("http://") or raw.lower().startswith("https://"):
            norm = raw
        elif raw.lower().startswith(("file://", "smb://", "res://")):
            norm = raw
        elif raw.startswith("<") and raw.endswith(">") and "\\" in raw:
            norm = _unc_to_file_uri(raw.strip("<>"))
        elif raw.startswith("(") and raw.endswith(")") and "\\" in raw:
            norm = _unc_to_file_uri(raw)
        elif "\\" in raw:
            norm = _unc_to_file_uri(raw)
        else:
            norm = raw

        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)

    return out
