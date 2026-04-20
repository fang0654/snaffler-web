#!/usr/bin/env python3
"""
Convert Snaffler text log output into a sortable, filterable HTML report.

Usage:
  python snaffler_html.py -i snaffler.log -o snaffler.html
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

# Run from project root so `findings` resolves when executing this script directly.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from findings.parsers import (  # noqa: E402
    Row,
    detect_user_prefix,
    iter_rows,
    iter_text_lines,
    read_head_lines,
)


REPORT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Snaffler — __TITLE__</title>
  <style>
    :root {
      --bg: #0f1419;
      --panel: #1a2332;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #58a6ff;
      --border: #30363d;
      --green: #3fb950;
      --yellow: #d29922;
      --red: #f85149;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.45;
    }
    header {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border);
      background: var(--panel);
    }
    header h1 {
      margin: 0 0 0.35rem 0;
      font-size: 1.15rem;
      font-weight: 600;
    }
    header .meta { color: var(--muted); font-size: 0.9rem; }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: center;
      padding: 0.75rem 1.25rem;
      border-bottom: 1px solid var(--border);
      background: #111822;
    }
    .toolbar label {
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
      font-size: 0.75rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    input, select {
      background: var(--panel);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.45rem 0.55rem;
      min-width: 8rem;
      font-size: 0.9rem;
    }
    input#q { min-width: 14rem; flex: 1 1 12rem; }
    .counts {
      margin-left: auto;
      font-size: 0.9rem;
      color: var(--muted);
    }
    .wrap { overflow: auto; max-height: calc(100vh - 11rem); }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    thead th {
      position: sticky;
      top: 0;
      background: #151d2a;
      z-index: 1;
      text-align: left;
      padding: 0.55rem 0.65rem;
      border-bottom: 1px solid var(--border);
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }
    thead th:hover { color: var(--accent); }
    tbody td {
      padding: 0.45rem 0.65rem;
      border-bottom: 1px solid #222c3a;
      vertical-align: top;
      word-break: break-word;
    }
    tbody tr:nth-child(even) td { background: rgba(255,255,255,0.02); }
    .dt { white-space: nowrap; color: var(--muted); font-variant-numeric: tabular-nums; }
    .kind { font-weight: 600; }
    .sev-Green { color: var(--green); }
    .sev-Yellow { color: var(--yellow); }
    .sev-Red { color: var(--red); }
    .sev-empty { color: var(--muted); }
    .finding {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.8rem;
      max-height: 4.5em;
      overflow: hidden;
      position: relative;
    }
    .finding.expanded {
      max-height: none;
    }
    button.toggle {
      margin-top: 0.25rem;
      font-size: 0.75rem;
      padding: 0.15rem 0.4rem;
      background: transparent;
      border: 1px solid var(--border);
      color: var(--accent);
      border-radius: 4px;
      cursor: pointer;
    }
    button.toggle:hover { border-color: var(--accent); }
  </style>
</head>
<body>
  <header>
    <h1>Snaffler results</h1>
    <div class="meta">Source: __TITLE__ · <span id="total"></span> parsed lines</div>
  </header>
  <div class="toolbar">
    <label>Type
      <select id="filterKind">
        <option value="">(all)</option>
      </select>
    </label>
    <label>Severity
      <select id="filterSev">
        <option value="">(all)</option>
      </select>
    </label>
    <label style="flex:1 1 14rem; max-width: 28rem;">Search finding
      <input id="q" type="search" placeholder="Substring filter…" autocomplete="off"/>
    </label>
    <div class="counts"><span id="visible">0</span> visible</div>
  </div>
  <div class="wrap">
    <table>
      <thead>
        <tr>
          <th data-key="dt">Datetime</th>
          <th data-key="kind">Type</th>
          <th data-key="severity">Severity</th>
          <th data-key="finding">Finding</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
  <script>
    const DATA = __DATA__;

    const tbody = document.getElementById('tbody');
    const filterKind = document.getElementById('filterKind');
    const filterSev = document.getElementById('filterSev');
    const q = document.getElementById('q');
    const totalEl = document.getElementById('total');
    const visibleEl = document.getElementById('visible');

    const kinds = [...new Set(DATA.map(r => r.kind))].sort();
    const sevs = [...new Set(DATA.map(r => r.severity).filter(Boolean))].sort();
    for (const k of kinds) {
      const o = document.createElement('option');
      o.value = k;
      o.textContent = k;
      filterKind.appendChild(o);
    }
    for (const s of sevs) {
      const o = document.createElement('option');
      o.value = s;
      o.textContent = s;
      filterSev.appendChild(o);
    }

    totalEl.textContent = DATA.length;

    let sortKey = 'dt';
    let sortDir = 1;

    function sevClass(s) {
      if (!s) return 'sev-empty';
      return 'sev-' + s;
    }

    function rowMatches(r) {
      const k = filterKind.value;
      const sv = filterSev.value;
      const needle = q.value.trim().toLowerCase();
      if (k && r.kind !== k) return false;
      if (sv && r.severity !== sv) return false;
      if (needle && !r.finding.toLowerCase().includes(needle)) return false;
      return true;
    }

    function cmp(a, b) {
      const va = a[sortKey] ?? '';
      const vb = b[sortKey] ?? '';
      if (sortKey === 'dt') {
        return sortDir * (va < vb ? -1 : va > vb ? 1 : 0);
      }
      return sortDir * String(va).localeCompare(String(vb), undefined, { sensitivity: 'base' });
    }

    function render() {
      const sorted = [...DATA].sort(cmp);
      tbody.innerHTML = '';
      let vis = 0;
      for (const r of sorted) {
        if (!rowMatches(r)) continue;
        vis++;
        const tr = document.createElement('tr');
        const findingText = r.finding;
        const long = findingText.length > 400;
        const shortText = long ? findingText.slice(0, 400) + '…' : findingText;
        const sc = sevClass(r.severity);
        const td0 = document.createElement('td');
        td0.className = 'dt';
        td0.textContent = r.dt;
        const td1 = document.createElement('td');
        td1.className = 'kind';
        td1.textContent = r.kind;
        const td2 = document.createElement('td');
        td2.className = sc;
        td2.textContent = r.severity || '—';
        const td3 = document.createElement('td');
        td3.className = 'finding-cell';
        tr.appendChild(td0);
        tr.appendChild(td1);
        tr.appendChild(td2);
        tr.appendChild(td3);
        const fc = td3;
        const pre = document.createElement('div');
        pre.className = 'finding' + (long ? '' : ' expanded');
        pre.textContent = long ? shortText : findingText;
        fc.appendChild(pre);
        if (long) {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'toggle';
          btn.textContent = 'Show full';
          btn.addEventListener('click', () => {
            const on = pre.classList.toggle('expanded');
            btn.textContent = on ? 'Show less' : 'Show full';
            pre.textContent = on ? findingText : shortText;
          });
          fc.appendChild(btn);
        }
        tbody.appendChild(tr);
      }
      visibleEl.textContent = vis;
    }

    document.querySelectorAll('thead th').forEach(th => {
      th.addEventListener('click', () => {
        const k = th.getAttribute('data-key');
        if (k === sortKey) sortDir *= -1;
        else { sortKey = k; sortDir = 1; }
        render();
      });
    });
    filterKind.addEventListener('change', render);
    filterSev.addEventListener('change', render);
    q.addEventListener('input', render);
    render();
  </script>
</body>
</html>
"""


def build_html(rows: list[Row], source_label: str) -> str:
    data = [r.to_json() for r in rows]
    payload = json.dumps(data, ensure_ascii=False)
    # Safe inside <script>: avoid closing the tag if a finding contains "</script>"
    payload = payload.replace("<", "\\u003c")
    title = html.escape(source_label)
    return (
        REPORT_HTML.replace("__TITLE__", title)
        .replace("__DATA__", payload)
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build a sortable HTML report from Snaffler text output."
    )
    ap.add_argument(
        "-i",
        "--input",
        required=True,
        help="Snaffler log file (text)",
    )
    ap.add_argument(
        "-o",
        "--output",
        default="snaffler.html",
        help="Output HTML path (default: snaffler.html)",
    )
    args = ap.parse_args()

    with open(args.input, encoding="utf-8", errors="replace") as f:
        head = read_head_lines(f, 5000)
        prefix = detect_user_prefix(head)
        if not prefix:
            print("Could not detect Snaffler user prefix from input.", file=sys.stderr)
            return 1
        f.seek(0)
        rows = list(iter_rows(iter_text_lines(f), prefix))

    out = build_html(rows, args.input)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"Wrote {len(rows)} rows to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
