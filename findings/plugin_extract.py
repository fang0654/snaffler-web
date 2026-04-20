from __future__ import annotations

import re

# Snaffler lines often look like: <PluginName|R|...> or <PluginName|...>
PLUGIN_RE = re.compile(r"<([^|>]+)\|")


def extract_plugin_name(finding: str) -> str:
    """Return text between the first '<' and the first '|', or empty string."""
    if not finding:
        return ""
    m = PLUGIN_RE.search(finding)
    return m.group(1).strip() if m else ""
