"""
Extract a single URI-like string from Snaffler finding text.

Covers http(s), file/res/smb schemes, and Windows UNC paths (normalized to file://host/path).

Spaces and closing parentheses often appear before YAML tail or prose; we only treat them as an
URI boundary once the path already ends with a plausible file segment (basename with an
extension). Otherwise a lone space may be absorbed so paths like ``...\\dir\\file name.pdf`` keep
going until ``.pdf``. There is at most one URI per finding (the leftmost match; tie-break by
kind then length).
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

from .smb_parse import _looks_like_filename

_HTTP_START = re.compile(r"https?://", re.IGNORECASE)
_FILE_SMB_RES_START = re.compile(r"(?:file|smb|res)://", re.IGNORECASE)

# UNC inside parentheses: opening paren then optional whitespace then \\
_UNC_PARENS_OPEN = re.compile(r"\(\s*((?:\\){2})")

# opening < then \\
_UNC_ANGLE_OPEN = re.compile(r"<((?:\\){2})")

# Any \\ that starts a host-like segment (standalone UNC)
_UNC_DOUBLE = re.compile(r"(?:\\){2}[\w.-]+")


def _strip_url_tail_for_path_check(s: str) -> str:
    """Drop query/fragment before checking basename."""
    return s.split("?", 1)[0].split("#", 1)[0]


def _seg_from_scheme_url(url_sofar: str) -> str:
    """Last path-ish segment from a partially typed scheme URL, for extension heuristic."""
    s = url_sofar.strip()
    if not s or "://" not in s:
        return ""
    p = urlparse(s)
    path = unquote(p.path or "")
    path = path.replace("\\", "/").strip("/")
    if path:
        return path.split("/")[-1]
    # file://share/path sometimes uses netloc-only oddities
    rest = s.split("://", 1)[1]
    rest = _strip_url_tail_for_path_check(rest).replace("\\", "/")
    if "/" in rest:
        return rest.split("/")[-1]
    return rest


def _http_or_scheme_path_terminal_complete(url_sofar: str) -> bool:
    seg = _seg_from_scheme_url(url_sofar)
    return bool(seg and _looks_like_filename(seg))


def _unc_terminal_complete(unc_sofar: str) -> bool:
    r"""UNC body; last backslash segment should look like ``file.ext``."""
    s = unc_sofar.rstrip("\\")
    if not s or "\\" not in s:
        return False
    seg = s.split("\\")[-1]
    return bool(seg and _looks_like_filename(seg))


def _expand_scheme_rest(text: str, start_scheme: int, scheme_m: re.Match[str]) -> str:
    """Grow http(s)/file/smb/res from scheme start until a safe end (extension-aware)."""
    i = scheme_m.end()
    while i < len(text):
        c = text[i]
        so_far = text[start_scheme:i]
        if c in '<>\'"`':
            break
        if c in " \t\n\r)":
            if _http_or_scheme_path_terminal_complete(so_far):
                return so_far
            if c == " " and not _http_or_scheme_path_terminal_complete(so_far):
                i += 1
                continue
            break
        i += 1
    return text[start_scheme:i]


def _expand_unc_body(
    text: str, start: int, *, angle_bracket: bool = False
) -> str:
    r"""Expand from ``\\`` at ``start``. ``angle_bracket`` adds ``>`` as a closing delimiter."""
    if start + 1 >= len(text) or text[start : start + 2] != "\\\\":
        return ""
    i = start
    while i < len(text):
        c = text[i]
        so_far = text[start:i]
        if c in '<>\'"`':
            if angle_bracket and c == ">":
                pass
            else:
                break
        if c in " \t\n\r)" or (angle_bracket and c == ">"):
            if _unc_terminal_complete(so_far):
                return so_far
            if c == " " and not _unc_terminal_complete(so_far):
                i += 1
                continue
            break
        i += 1
    return text[start:i]


def _unc_to_file_uri(unc: str) -> str:
    r"""Turn \\server\share\path into file://server/share/path."""
    s = unc.strip()
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1].strip()
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


def _normalize_raw(raw: str) -> str:
    raw = raw.rstrip()
    low = raw.lower()
    if low.startswith(("http://", "https://", "file://", "smb://", "res://")):
        return raw.strip()
    if raw.startswith("<") and raw.endswith(">") and "\\" in raw:
        return _unc_to_file_uri(raw.strip("<>"))
    if raw.startswith("(") and raw.endswith(")") and "\\" in raw:
        return _unc_to_file_uri(raw)
    if "\\" in raw:
        return _unc_to_file_uri(raw)
    return raw


def _trim_trailing(s: str) -> str:
    return s.rstrip(".,;:!?)\\]\"'")


# Sort key: leftmost start, then preferred kind (lower = better), then longer span
_KIND_PRI = {"http": 0, "fsr": 1, "unc_p": 2, "unc_a": 3, "unc_s": 4}


def _collect_scheme_http(text: str) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for m in _HTTP_START.finditer(text):
        start = m.start()
        s = _expand_scheme_rest(text, start, m)
        s = _trim_trailing(s)
        if s:
            out.append((start, s, "http"))
    return out


def _collect_scheme_fsr(text: str) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for m in _FILE_SMB_RES_START.finditer(text):
        start = m.start()
        s = _expand_scheme_rest(text, start, m)
        s = _trim_trailing(s)
        if s:
            out.append((start, s, "fsr"))
    return out


def _collect_unc_parens(text: str) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for m in _UNC_PARENS_OPEN.finditer(text):
        inner_start = m.start(1)
        body = _expand_unc_body(text, inner_start, angle_bracket=False)
        s = _trim_trailing(body)
        if s:
            out.append((m.start(), s, "unc_p"))
    return out


def _collect_unc_angle(text: str) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for m in _UNC_ANGLE_OPEN.finditer(text):
        inner_start = m.start(1)
        body = _expand_unc_body(text, inner_start, angle_bracket=True)
        s = _trim_trailing(body)
        if s:
            out.append((m.start(), s, "unc_a"))
    return out


def _collect_unc_standalone(text: str) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    for m in _UNC_DOUBLE.finditer(text):
        start = m.start()
        body = _expand_unc_body(text, start, angle_bracket=False)
        s = _trim_trailing(body)
        if s:
            out.append((start, s, "unc_s"))
    return out


def extract_single_uri(text: str) -> str | None:
    """
    Leftmost URI in ``text``, after normalization. At most one path per finding;
    ``extract_uris`` wraps this in a list for storage.
    """
    if not text:
        return None
    buckets: list[tuple[int, str, str]] = []
    buckets.extend(_collect_scheme_http(text))
    buckets.extend(_collect_scheme_fsr(text))
    buckets.extend(_collect_unc_parens(text))
    buckets.extend(_collect_unc_angle(text))
    buckets.extend(_collect_unc_standalone(text))
    if not buckets:
        return None
    buckets.sort(
        key=lambda t: (t[0], _KIND_PRI.get(t[2], 9), -len(t[1])),
    )
    norm = _normalize_raw(buckets[0][1])
    return norm or None


def extract_uris(text: str) -> list[str]:
    """Return 0 or 1 normalized URI (leftmost), for JSON storage and SMB fields."""
    u = extract_single_uri(text)
    return [u] if u else []
