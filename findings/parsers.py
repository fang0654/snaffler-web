"""Parse Snaffler text logs (shared by CLI and Django import)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import BinaryIO, Iterator, TextIO

# After the user prefix: ISO datetime, bracket type, remainder.
LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}Z)\s+\[([^\]]+)\]\s+(.*)$"
)
STRUCTURED_RE = re.compile(r"^\{(\w+)\}<([^>]*)>(.*)$", re.DOTALL)


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


# --- Tab-separated rows (user column and remaining fields are tab-separated) ---

def _is_iso_z(s: str) -> bool:
    return bool(
        re.match(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z$",
            s.strip(),
        )
    )


def is_tsv_snaffler_head(first_lines: list[str]) -> bool:
    """True if the file looks like Snaffler TSV: [context]\\t<ISO-Z>\\t[Kind]..."""
    for line in first_lines:
        line = line.rstrip("\n\r")
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
        line = line.rstrip("\n\r")
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


def _tsv_finding_from_parts(parts: list[str]) -> str:
    """Build finding text: Snaffler-style ``<Plugin|field5|...>`` plus tail for URI/plugin extract."""
    if len(parts) < 4:
        return "\t".join(parts)
    # parts[0] = user, [1]=dt, [2]=[Kind], [3]=severity, [4]=plugin, [5+]=rest
    plugin = parts[4] if len(parts) > 4 else ""
    fifth = parts[5] if len(parts) > 5 else ""
    head = f"<{plugin}|{fifth}>"
    if len(parts) <= 6:
        return head
    # Drop empty TSV fields so the joined finding matches normal logs more closely
    rest = [s for s in parts[6:] if s]
    if not rest:
        return head
    return head + "\n" + "\n".join(rest)


def iter_tsv_rows(lines: Iterator[str], user_prefix: str) -> Iterator[Row]:
    """One Row per TSV data line; user_prefix is ``[context]\\t`` (see``detect_tsv_user_prefix``)."""
    for raw in lines:
        line = raw.rstrip("\n\r")
        if not line or not line.startswith(user_prefix):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        if not _is_iso_z(parts[1]):
            continue
        dt = parts[1].strip()
        kind = parts[2].strip("[]")
        severity = parts[3] if len(parts) > 3 else ""
        finding = _tsv_finding_from_parts(parts)
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
    for raw in lines:
        line = raw.rstrip("\n\r")
        if not line.startswith(user_prefix):
            continue
        rest = line[len(user_prefix) :]
        m = LINE_RE.match(rest)
        if not m:
            continue
        dt, kind, body = m.group(1), m.group(2), m.group(3)
        severity, finding, _ = parse_body(body)
        yield Row(dt=dt, kind=kind, severity=severity, finding=finding)


def iter_text_lines(stream: TextIO | BinaryIO) -> Iterator[str]:
    while True:
        raw = stream.readline()
        if not raw:
            break
        if isinstance(raw, bytes):
            yield raw.decode("utf-8", errors="replace")
        else:
            yield raw


def read_head_lines(stream: TextIO | BinaryIO, n: int) -> list[str]:
    out: list[str] = []
    for _ in range(n):
        raw = stream.readline()
        if not raw:
            break
        if isinstance(raw, bytes):
            out.append(raw.decode("utf-8", errors="replace"))
        else:
            out.append(raw)
    return out


def parse_dt(iso_z: str) -> datetime:
    return datetime.strptime(iso_z, "%Y-%m-%d %H:%M:%SZ").replace(tzinfo=timezone.utc)
