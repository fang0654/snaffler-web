"""
Parse Snaffler text logs (shared by CLI and Django import).

**Tab-separated (TSV) export** — one row per line, fields are tab-delimited in this order:

- **computer** — first column, usually a bracketed host/user string, plus a tab, is the
  per-file line prefix
- **datetime** — ``YYYY-MM-DD HH:MM:SSZ``
- **type** — bracketed kind, e.g. ``[File]`` (``[Info]`` and ``[Error]`` are skipped on import)
- **Severity** — e.g. Green, Yellow, Red
- **plugin** — rule/plugin name, then a column **R**, then **three** tab-separated fields
  (usually empty), then the **rest** of the line is the finding (regex, size, path, etc.) as
  further tab-delimited values. We build stored text as ``<plugin|R>`` and join non-empty tail
  fields with newlines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import BinaryIO, Iterator, TextIO
import pdb
# After the user prefix: ISO datetime, bracket type, remainder.
LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}Z)\s+\[([^\]]+)\]\s+(.*)$"
)
STRUCTURED_RE = re.compile(r"^\{(\w+)\}<([^>]*)>(.*)$", re.DOTALL)

# Snaffler [Info] / [Error] lines are status messages, not file findings — skip on import
_SKIPPED_LINE_KINDS = frozenset({"info", "error"})


def _skip_line_kind(kind: str) -> bool:
    return kind.strip().casefold() in _SKIPPED_LINE_KINDS


@dataclass
class Row:
    dt: str
    kind: str
    severity: str
    finding: str

    def to_json(self) -> dict[str, str]:
        return {
            "dt": self.dt,
            "kind": self.kind,
            "severity": self.severity,
            "finding": self.finding,
        }


def detect_user_prefix(first_lines: list[str]) -> str | None:
    for line in first_lines:
        m = re.match(r"^(\[[^\]]+\]\s+)", line)
        if m:
            return m.group(1)
    return None


# --- TSV: see module docstring (computer \\t datetime \\t type \\t Severity \\t plugin \\t R \\t\\t\\t rest…) ---

def _is_iso_z(s: str) -> bool:
    return bool(
        re.match(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z$",
            s.strip(),
        )
    )


def is_tsv_snaffler_head(first_lines: list[str]) -> bool:
    """True if the file looks like Snaffler TSV (computer\\tdatetime\\t[type]\\t…)."""
    for line in first_lines:
        line = _strip_bom(line.rstrip("\n\r"))
        if not line or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        if not (parts[0].startswith("[") and "]" in parts[0]):
            continue
        if not _is_iso_z(parts[1]):
            continue
        k = parts[2].strip()
        if len(k) >= 2 and k.startswith("[") and k.endswith("]"):
            return True
    return False


def detect_tsv_user_prefix(first_lines: list[str]) -> str | None:
    """Prefix string including tab after the leading [user] block: ``[X]\\t``"""
    for line in first_lines:
        line = _strip_bom(line.rstrip("\n\r"))
        if not line or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        if not (parts[0].startswith("[") and "]" in parts[0]):
            continue
        if not _is_iso_z(parts[1]):
            continue
        k = parts[2].strip()
        if not (len(k) >= 2 and k.startswith("[") and k.endswith("]")):
            continue
        return f"{parts[0]}\t"
    return None


def _strip_bom(s: str) -> str:
    if s and s[0] == "\ufeff":
        return s[1:]
    return s


def _tsv_finding_from_parts(parts: list[str]) -> str:
    """Build stored finding text from TSV column indices (see module docstring)."""
    # if parts[2] == "[File]":
    #     pdb.set_trace()
    n = len(parts)
    if n < 4:
        return "\t".join(parts)
    # Short export: only four fields — the last cell is the whole finding (no per-column Severity/…)
    if n == 4:
        return parts[3]
    # Five fields: computer, dt, [type], Severity, one blob
    if n == 5:
        return parts[4]
    # Wide: 0..3 = computer,dt,[type],Severity — then plugin, R, (often three empties), then rest
    plugin = (parts[4] if n > 4 else "") or ""
    fifth = (parts[5] if n > 5 else "") or ""
    rest = [s for s in (parts[6:] if n > 6 else []) if s]
    if not plugin.strip() and not fifth.strip():
        if rest:
            return "\n".join(rest)
        return ""
    head = f"<{plugin.strip()}|{fifth.strip()}>"
    if not rest:
        return head
    return head + " " + " ".join(rest)


def iter_tsv_rows(lines: Iterator[str], user_prefix: str) -> Iterator[Row]:
    """One Row per TSV line; ``user_prefix`` is ``computer\\t`` (see ``detect_tsv_user_prefix``)."""
    for raw in lines:
        line = _strip_bom(raw.rstrip("\n\r"))
        if not line or not line.startswith(_strip_bom(user_prefix)):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        if not _is_iso_z(parts[1]):
            continue
        
        dt = parts[1].strip()
        kind = parts[2].strip("[]")
        if _skip_line_kind(kind):
            continue
        n = len(parts)
        if n == 4:
            severity = ""
        else:
            severity = parts[3] if n > 3 else ""
        
        finding = _tsv_finding_from_parts(parts)
        if  not severity:
            continue
        yield Row(dt=dt, kind=kind, severity=severity, finding=finding)


def parse_body(body: str) -> tuple[str, str, str]:
    m = STRUCTURED_RE.match(body.strip())
    if not m:
        return "", body.strip(), ""

    severity, angle, rest = m.group(1), m.group(2), m.group(3)
    parts = [f"<{angle}>"]
    tail = rest.strip()
    if tail:
        parts.append(tail)
    finding = "\n".join(parts)
    return severity, finding, rest


def iter_rows(lines: Iterator[str], user_prefix: str) -> Iterator[Row]:
    up = _strip_bom(user_prefix)
    for raw in lines:
        line = _strip_bom(raw.rstrip("\n\r"))
        if not line.startswith(up):
            continue
        rest = line[len(up) :]
        m = LINE_RE.match(rest)
        if not m:
            continue
        dt, kind, body = m.group(1), m.group(2), m.group(3)
        if _skip_line_kind(kind):
            continue
        severity, finding, _ = parse_body(body)
        yield Row(dt=dt, kind=kind, severity=severity, finding=finding)


def iter_text_lines(stream: TextIO | BinaryIO) -> Iterator[str]:
    while True:
        raw = stream.readline()
        if not raw:
            break
        if isinstance(raw, bytes):
            yield _strip_bom(raw.decode("utf-8", errors="replace"))
        else:
            yield _strip_bom(raw)


def read_head_lines(stream: TextIO | BinaryIO, n: int) -> list[str]:
    out: list[str] = []
    for _ in range(n):
        raw = stream.readline()
        if not raw:
            break
        if isinstance(raw, bytes):
            out.append(_strip_bom(raw.decode("utf-8", errors="replace")))
        else:
            out.append(_strip_bom(raw))
    return out


def parse_dt(iso_z: str) -> datetime:
    return datetime.strptime(iso_z, "%Y-%m-%d %H:%M:%SZ").replace(tzinfo=timezone.utc)
