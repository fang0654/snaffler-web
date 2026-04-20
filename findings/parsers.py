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
