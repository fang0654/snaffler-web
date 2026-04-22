from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import sys
from urllib.parse import parse_qs

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings

from .models import Finding
from .smb_parse import parse_smb_from_file_uri

try:
    import pty

    HAS_PTY = True
except ImportError:
    HAS_PTY = False

# TTY canonical mode often caps input lines (~4096 bytes). Long single-line `cd`
# commands are truncated; split into per-directory cds. Use UTF-8 byte length.
_PTY_CD_LINE_MAX_BYTES = 3800


def _smb_cd_command_lines(cd_path: str, use_dfs: bool = False) -> list[str]:
    """
    smbclient `cd` lines (each without trailing newline). Uses shlex.quote so
    paths with spaces match between echoed $ lines and stdin. If one full-path
    line would exceed the TTY limit, use sequential relative cds (one segment
    per line) from the share root.

    When use_dfs is True and the path has more than one segment, emit two steps:
    cd into the first folder only, then cd with the rest joined (so DFS can
    connect before the remaining path). If that rest line would still exceed
    the TTY limit, use one cd per remaining segment instead.
    """
    if not cd_path:
        return []
    path_norm = cd_path.replace("\\", "/").strip("/")
    if not path_norm:
        return []
    segments = [s for s in path_norm.split("/") if s]
    if not segments:
        return []

    if use_dfs and len(segments) >= 2:
        first = segments[0]
        rest_segs = segments[1:]
        rest_bs = "\\".join(rest_segs)
        rest_cmd = f"cd {shlex.quote(rest_bs)}"
        if len(rest_cmd.encode("utf-8")) <= _PTY_CD_LINE_MAX_BYTES:
            return [
                f"cd {shlex.quote(first)}",
                rest_cmd,
            ]
        lines = [f"cd {shlex.quote(first)}"]
        for seg in rest_segs:
            lines.append(f"cd {shlex.quote(seg)}")
        return lines

    cd_bs_full = path_norm.replace("/", "\\")
    full_cmd = f"cd {shlex.quote(cd_bs_full)}"
    if len(full_cmd.encode("utf-8")) <= _PTY_CD_LINE_MAX_BYTES:
        return [full_cmd]
    lines: list[str] = []
    for seg in segments:
        seg_bs = seg.replace("/", "\\")
        lines.append(f"cd {shlex.quote(seg_bs)}")
    return lines


def _build_smbclient_cmd(
    domain: str,
    username: str,
    password: str,
    host: str,
    smbclient_py_override: str = "",
) -> list[str]:
    if domain:
        target = f"{domain}/{username}:{password}@{host}"
    else:
        target = f"{username}:{password}@{host}"
    exe = (smbclient_py_override or "").strip()
    if not exe:
        exe = str(getattr(settings, "SMBCLIENT_PY", "smbclient.py"))
        if not os.path.isabs(exe):
            found = shutil.which(os.path.basename(exe)) or shutil.which(exe)
            if found:
                exe = found
    if exe.endswith(".py"):
        py = shutil.which("python3") or shutil.which("python") or sys.executable
        return [py, exe, target]
    return [exe, target]


def _format_smbclient_command_display(
    cmd: list[str], domain: str, username: str, host: str
) -> str:
    """Shell-style line for logging; password replaced with ***."""
    if domain:
        masked_target = f"{domain}/{username}:***@{host}"
    else:
        masked_target = f"{username}:***@{host}"
    if len(cmd) == 3:
        parts = [cmd[0], cmd[1], masked_target]
    else:
        parts = [cmd[0], masked_target]
    return " ".join(shlex.quote(p) for p in parts)


def _write_all_fd(fd: int, data: bytes) -> None:
    while data:
        n = os.write(fd, data)
        data = data[n:]


@sync_to_async
def _ws_target_from_query(qs: dict[str, list[str]]) -> tuple[str, str, str]:
    finding_id = (qs.get("finding") or [""])[0].strip()
    uri_idx_s = (qs.get("uri_index") or [""])[0].strip()
    if finding_id and uri_idx_s != "":
        try:
            row = Finding.objects.get(pk=int(finding_id))
            idx = int(uri_idx_s)
            uris = row.uris or []
            if 0 <= idx < len(uris):
                p = parse_smb_from_file_uri(uris[idx])
                if p and p["host"] and p["share"]:
                    return p["host"], p["share"], p["cd_path"]
        except (ValueError, Finding.DoesNotExist):
            pass
    host = (qs.get("host") or [""])[0].strip()
    share = (qs.get("share") or [""])[0].strip()
    cd_path = (qs.get("cd") or [""])[0].strip()
    return host, share, cd_path


class SMBTerminalConsumer(AsyncWebsocketConsumer):
    proc: asyncio.subprocess.Process | None = None
    pump_task: asyncio.Task | None = None
    # PTY master (Unix): read/write here; proc.stdin is None. PIPE mode: use proc.stdin.
    master_fd: int | None = None

    async def connect(self) -> None:
        session = self.scope.get("session")
        if session is None:
            await self.close(code=4000)
            return

        @sync_to_async
        def _creds() -> tuple[str, str, str, str, bool]:
            return (
                session.get("smb_domain", "") or "",
                session.get("smb_username", "") or "",
                session.get("smb_password", "") or "",
                (session.get("smb_smbclient_py") or "").strip(),
                bool(session.get("smb_use_dfs")),
            )

        domain, username, password, smbclient_py, use_dfs = await _creds()
        if not username or not password:
            await self.close(code=4001)
            return

        qs = parse_qs(self.scope.get("query_string", b"").decode())
        host, share, cd_path = await _ws_target_from_query(qs)
        if not host or not share:
            await self.close(code=4002)
            return

        await self.accept()

        cmd = _build_smbclient_cmd(
            domain, username, password, host, smbclient_py_override=smbclient_py
        )
        display = _format_smbclient_command_display(cmd, domain, username, host)
        await self.send(text_data=f"$ {display}\r\n")

        use_pty = HAS_PTY and hasattr(os, "fork")
        slave_fd: int | None = None
        try:
            if use_pty:
                self.master_fd, slave_fd = pty.openpty()
                self.proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    close_fds=True,
                    env={**os.environ, "PYTHONUNBUFFERED": "1"},
                )
                assert slave_fd is not None
                os.close(slave_fd)
                slave_fd = None
            else:
                self.proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    env={**os.environ, "PYTHONUNBUFFERED": "1"},
                )
        except OSError as e:
            if self.master_fd is not None:
                try:
                    os.close(self.master_fd)
                except OSError:
                    pass
                self.master_fd = None
            await self.send(text_data=f"\r\n[spawn error] {e}\r\n")
            await self.close(code=4003)
            return

        self.pump_task = asyncio.create_task(self._pump_output())

        cd_lines = _smb_cd_command_lines(cd_path, use_dfs=use_dfs)

        await self.send(text_data="$ shares\r\n")
        await self.send(text_data=f"$ use {shlex.quote(share)}\r\n")
        if use_dfs:
            await self.send(text_data="$ dfs_mode on\r\n")
        for line in cd_lines:
            await self.send(text_data=f"$ {line}\r\n")

        init = "shares\n"
        init += f"use {share}\n"
        if use_dfs:
            init += "dfs_mode on\n"
        for line in cd_lines:
            init += line + "\n"
        await self._write_input(init.encode())

    async def _write_input(self, data: bytes) -> None:
        if not data:
            return
        if self.master_fd is not None:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _write_all_fd, self.master_fd, data)
        elif self.proc is not None and self.proc.stdin is not None:
            self.proc.stdin.write(data)
            await self.proc.stdin.drain()

    async def _pump_output(self) -> None:
        loop = asyncio.get_event_loop()
        if self.master_fd is not None:
            fd = self.master_fd

            def _read_chunk() -> bytes:
                return os.read(fd, 4096)

            while True:
                try:
                    chunk = await loop.run_in_executor(None, _read_chunk)
                except OSError:
                    break
                if not chunk:
                    break
                await self.send(bytes_data=chunk)
            return

        assert self.proc is not None
        assert self.proc.stdout is not None
        try:
            while True:
                chunk = await self.proc.stdout.read(4096)
                if not chunk:
                    break
                await self.send(bytes_data=chunk)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            await self.send(text_data=f"\r\n[read error] {e}\r\n")

    async def receive(self, text_data=None, bytes_data=None) -> None:
        if bytes_data is not None:
            data = bytes_data
        elif text_data is not None:
            data = text_data.encode("utf-8")
        else:
            return
        if not data:
            return
        if self.master_fd is None and (
            self.proc is None or self.proc.stdin is None
        ):
            return
        try:
            await self._write_input(data)
        except BrokenPipeError:
            pass
        except OSError:
            pass

    async def disconnect(self, close_code: int) -> None:
        if self.pump_task:
            self.pump_task.cancel()
            try:
                await self.pump_task
            except asyncio.CancelledError:
                pass
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None
        if self.proc and self.proc.returncode is None:
            self.proc.kill()
            await self.proc.wait()
