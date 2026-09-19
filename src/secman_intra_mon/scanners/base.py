"""Adapter protocol, capability detection and a safe subprocess helper."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

PROBE_TIMEOUT = 15


class ScannerError(Exception):
    pass


@dataclass
class ToolStatus:
    name: str
    path: str | None
    available: bool
    version: str | None
    needs_root: bool


#: name -> (version probe args, needs root for the phases we use it in)
TOOL_SPECS: dict[str, tuple[list[str], bool]] = {
    "nmap": (["--version"], False),
    "masscan": (["--version"], True),
    "fping": (["-v"], False),
    "arp-scan": (["--version"], True),
    "traceroute": (["--version"], False),
}


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def has_net_raw() -> bool:
    """CAP_NET_RAW check via /proc (Linux); falls back to euid elsewhere."""
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split()[1], 16)
                    cap_net_raw = 13
                    return bool(cap_eff & (1 << cap_net_raw))
    except (OSError, ValueError, IndexError):
        pass
    return is_root()


def _probe_version(path: str, args: list[str]) -> str | None:
    try:
        proc = subprocess.run([path, *args], capture_output=True, text=True, timeout=PROBE_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    first_line = (proc.stdout or proc.stderr).splitlines()
    return first_line[0].strip() if first_line else None


def detect_tools() -> dict[str, ToolStatus]:
    tools: dict[str, ToolStatus] = {}
    for name, (probe_args, needs_root) in TOOL_SPECS.items():
        path = shutil.which(name)
        tools[name] = ToolStatus(
            name=name,
            path=path,
            available=path is not None,
            version=_probe_version(path, probe_args) if path else None,
            needs_root=needs_root,
        )
    return tools


def run_tool(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Run a scanner binary: argv only, no shell, mandatory timeout."""
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"{argv[0]} timed out after {timeout}s: {' '.join(argv[:4])} ...") from exc
    except OSError as exc:
        raise ScannerError(f"failed to execute {argv[0]}: {exc}") from exc


def require_tool(tools: dict[str, ToolStatus], name: str) -> ToolStatus:
    status = tools.get(name)
    if status is None or not status.available:
        raise ScannerError(f"required tool {name!r} not found in PATH — install it or use the Docker image")
    return status
