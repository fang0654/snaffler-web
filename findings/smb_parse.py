"""
Parse file:// URIs (from UNC normalization) into SMB host, share, and path under share.
"""

from __future__ import annotations


def _looks_like_filename(seg: str) -> bool:
    if "." not in seg or seg.startswith("."):
        return False
    _base, ext = seg.rsplit(".", 1)
    return 1 <= len(ext) <= 8 and len(_base) > 0


def parse_smb_from_file_uri(uri: str) -> dict | None:
    """
    Parse file://host/share/... into host, share, cd_path (under share, no filename),
    and filename when the last segment looks like a file.

    cd_path uses forward slashes; callers may convert to backslashes for smbclient.
    """
    if not uri or not uri.lower().startswith("file://"):
        return None
    rest = uri[7:]
    if "/" not in rest:
        return None
    host, _, path = rest.partition("/")
    host = host.strip()
    path = path.strip("/")
    if not host:
        return None
    if not path:
        return {
            "host": host,
            "share": "",
            "cd_path": "",
            "filename": "",
        }
    parts = [p for p in path.split("/") if p]
    if not parts:
        return {
            "host": host,
            "share": "",
            "cd_path": "",
            "filename": "",
        }
    share = parts[0]
    if len(parts) == 1:
        return {
            "host": host,
            "share": share,
            "cd_path": "",
            "filename": "",
        }
    remainder = parts[1:]
    last = remainder[-1]
    if _looks_like_filename(last):
        cd_parts = remainder[:-1]
        filename = last
    else:
        cd_parts = remainder
        filename = ""
    cd_path = "/".join(cd_parts)
    return {
        "host": host,
        "share": share,
        "cd_path": cd_path,
        "filename": filename,
    }


def smb_fields_from_uris(uris: list[str]) -> tuple[str, str, str]:
    """Return (host, share, cd_path) from the first parseable file:// URI."""
    for u in uris:
        p = parse_smb_from_file_uri(u)
        if p and p["host"] and p["share"]:
            return p["host"], p["share"], p["cd_path"]
    return "", "", ""
