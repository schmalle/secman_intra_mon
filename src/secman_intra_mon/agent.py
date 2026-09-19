"""Agentic discovery mode (`discover --agentic`).

An LLM planner drives the iterative loop: it observes a compact state
rendering, then proposes ONE action per step from a closed vocabulary:

  scan_network(cidr, profile)   host discovery + service scan of a network
  trace_host(ip)                traceroute a known live host, revealing router hops
  note(text)                    record an observation (no packets)
  stop(reason)                  end the run

Safety architecture: the LLM never constructs commands and never touches
subprocess. Proposals are validated here against the ScopeGuard — the same
choke point the deterministic engine uses — plus depth limits and hard
budgets; the model can narrow the plan, never widen it. Every packet-sending
action requires operator approval unless --yes was given. Every proposal and
verdict lands in an audit log (persisted into scan_runs.params_json).
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from . import discovery
from .discovery import DiscoveryRun, build_plan
from .llm import LlmClient, LlmError
from .models import NetworkResult, NetworkSeed
from .scanners import base, traceroute
from .scope import ScopeError, parse_network

ACTION_PROFILES = ("fast", "default", "full", "masscan")

DEFAULT_MAX_ACTIONS = 30
DEFAULT_MAX_NETWORKS = 10
#: consecutive invalid proposals tolerated before the run is ended
MAX_CONSECUTIVE_INVALID = 3
#: how many known hosts the state rendering includes
STATE_HOST_CAP = 40
STATE_PORT_CAP = 12

SYSTEM_PROMPT = """\
You are the planner of an AUTHORIZED internal-network asset discovery tool.
You observe scan results and propose the next step. You never run commands
yourself: every proposal is validated against a scope guard and depth/budget
limits before execution, and the operator may reject any proposal.

Reply with EXACTLY ONE JSON object, no prose, in one of these shapes:
{"action": "scan_network", "cidr": "<CIDR>", "profile": "fast|default|full|masscan", "reason": "<short>"}
{"action": "trace_host", "ip": "<ip of a known live host>", "reason": "<short>"}
{"action": "note", "text": "<observation>"}
{"action": "stop", "reason": "<why done>"}

Strategy:
- Scan unscanned candidate networks first. Prefer "fast" initially; use
  "default"/"full" on small interesting segments and "masscan" only on large
  flat ones.
- Use trace_host on likely routers — gateway-like addresses (.1/.254),
  hostnames containing gw/rtr/fw/core, hosts with many open ports — to
  reveal adjacent networks as new candidates.
- scan_network targets must be listed candidates or known in-scope networks;
  a candidate's depth must not exceed max_depth.
- Stop when no unscanned candidates remain or further steps look
  unproductive. Do not invent hosts or networks. Keep reasons short."""


@dataclass
class AgentBudgets:
    max_actions: int = DEFAULT_MAX_ACTIONS
    max_networks: int = DEFAULT_MAX_NETWORKS


@dataclass
class AgentRunner:
    """Drives one agentic discovery run. Iterate execute() to receive each
    completed NetworkResult; events flow through on_event; the audit trail
    is available afterwards in .audit."""

    discovery_run: DiscoveryRun
    client: LlmClient
    budgets: AgentBudgets = field(default_factory=AgentBudgets)
    approve: Callable[[str], bool] = lambda _desc: True
    on_event: Callable[[str], None] = lambda _msg: None

    def __post_init__(self) -> None:
        self.audit: list[dict[str, Any]] = []
        self.stop_reason: str | None = None
        self._depths: dict[str, int] = {}
        self._candidates: dict[str, NetworkSeed] = {}
        self._host_network: dict[str, str] = {}
        self._notes: list[str] = []
        self._feedback = ""
        self._actions_used = 0
        self._networks_used = 0
        self._invalid_streak = 0

    # -- main loop ------------------------------------------------------------

    def execute(self) -> Iterator[NetworkResult]:
        run = self.discovery_run
        for entry in build_plan(run):
            run.planned.append(entry)
            self._depths[entry.seed.cidr] = entry.seed.depth
            if entry.allowed:
                self._candidates[entry.seed.cidr] = entry.seed
        self._emit(
            f"agentic discovery: {len(self._candidates)} seed network(s), "
            f"budget {self.budgets.max_actions} actions / {self.budgets.max_networks} networks, "
            f"planner model {self.client.planner_model}"
        )
        while True:
            if self._actions_used >= self.budgets.max_actions:
                self._finish("action budget exhausted")
                break
            action = self._propose()
            if action is None:
                self._finish("planner unavailable")
                break
            valid, reason = self._validate(action)
            self._record(action, valid, reason)
            if not valid:
                self._invalid_streak += 1
                self._feedback = f"invalid action: {reason}"
                self._emit(f"proposal rejected: {reason}")
                if self._invalid_streak >= MAX_CONSECUTIVE_INVALID:
                    self._finish("too many invalid proposals")
                    break
                continue
            self._invalid_streak = 0
            kind = str(action["action"])
            if kind == "stop":
                self._finish(str(action.get("reason") or "planner decided to stop"))
                break
            self._actions_used += 1
            if kind == "note":
                text = str(action.get("text") or "")[:500]
                self._notes.append(text)
                self._emit(f"note: {text}")
                continue
            if not self.approve(self._describe(action)):
                self._feedback = "the operator rejected this action; propose a different one or stop"
                self._emit("rejected by operator")
                continue
            if kind == "scan_network":
                yield self._exec_scan(str(action["cidr"]), str(action["_profile"]))
            else:  # trace_host
                self._exec_trace(str(action["ip"]))

    # -- planner call ---------------------------------------------------------

    def _propose(self) -> dict[str, Any] | None:
        user = json.dumps(self._render_state(), default=str)
        for attempt in (1, 2):
            try:
                reply = self.client.chat_json(
                    SYSTEM_PROMPT, user, model=self.client.planner_model, max_tokens=800
                )
            except LlmError as exc:
                self._emit(f"planner call failed (attempt {attempt}): {exc}")
                continue
            if isinstance(reply, dict) and "action" in reply:
                return reply
            self._emit(f"planner reply has no 'action' (attempt {attempt})")
        return None

    def _render_state(self) -> dict[str, Any]:
        run = self.discovery_run
        scanned = []
        for result in run.results:
            port_counts: dict[int, int] = {}
            for host in result.live_hosts:
                for port in host.open_ports:
                    port_counts[port.port] = port_counts.get(port.port, 0) + 1
            top_ports = sorted(port_counts, key=lambda p: port_counts[p], reverse=True)[:8]
            scanned.append(
                {
                    "cidr": result.seed.cidr,
                    "depth": result.seed.depth,
                    "live_hosts": len(result.live_hosts),
                    "top_open_ports": top_ports,
                    "error": result.error,
                }
            )
        known_hosts = []
        for ip, cidr in list(self._host_network.items())[:STATE_HOST_CAP]:
            known = next((h for h in run.all_hosts if h.ip == ip), None)
            known_hosts.append(
                {
                    "ip": ip,
                    "network": cidr,
                    "hostname": known.hostname if known else None,
                    "mac_vendor": known.mac_vendor if known else None,
                    "open_ports": [p.port for p in known.open_ports][:STATE_PORT_CAP] if known else [],
                }
            )
        return {
            "budget": {
                "actions_left": self.budgets.max_actions - self._actions_used,
                "networks_left": self.budgets.max_networks - self._networks_used,
            },
            "max_depth": run.options.max_depth,
            "unscanned_candidates": [
                {"cidr": seed.cidr, "via": seed.discovered_via, "depth": seed.depth}
                for seed in self._candidates.values()
            ],
            "scanned_networks": scanned,
            "known_hosts": known_hosts,
            "notes": self._notes[-10:],
            "feedback": self._feedback,
            "instruction": "Reply with exactly one JSON action.",
        }

    # -- validation (the hard boundary) ----------------------------------------

    def _validate(self, action: dict[str, Any]) -> tuple[bool, str]:
        kind = action.get("action")
        if kind not in ("scan_network", "trace_host", "note", "stop"):
            return False, f"unknown action {kind!r} — use scan_network, trace_host, note or stop"
        if kind in ("note", "stop"):
            return True, "ok"
        if kind == "scan_network":
            return self._validate_scan(action)
        return self._validate_trace(action)

    def _validate_scan(self, action: dict[str, Any]) -> tuple[bool, str]:
        cidr = action.get("cidr")
        if not isinstance(cidr, str) or not cidr.strip():
            return False, "scan_network needs a 'cidr' string"
        profile = str(action.get("profile") or "fast").lower()
        if profile not in ACTION_PROFILES:
            return False, f"unknown profile {profile!r} (choose from {', '.join(ACTION_PROFILES)})"
        try:
            network = parse_network(cidr)
        except ScopeError as exc:
            return False, str(exc)
        key = str(network)
        if key in self.discovery_run.visited:
            return False, f"{key} was already scanned"
        allowed, reason = self.discovery_run.guard.assess(network)
        if not allowed:
            return False, f"scope guard rejects {key}: {reason}"
        depth = self._depths.get(key, 0)
        max_depth = self.discovery_run.options.max_depth
        if depth > max_depth:
            return False, f"{key} is at depth {depth}, beyond --max-depth {max_depth}"
        if self._networks_used >= self.budgets.max_networks:
            return False, "network budget exhausted — use trace_host, note or stop"
        if profile == "masscan":
            status = self.discovery_run.tools.get("masscan")
            if not base.has_net_raw() or status is None or not status.available:
                return False, "profile masscan is unavailable (needs root/CAP_NET_RAW and masscan)"
        action["cidr"] = key
        action["_profile"] = profile
        return True, "ok"

    def _validate_trace(self, action: dict[str, Any]) -> tuple[bool, str]:
        ip = action.get("ip")
        if not isinstance(ip, str):
            return False, "trace_host needs an 'ip' string"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"invalid ip {ip!r}"
        if not self.discovery_run.guard.ip_allowed(addr):
            return False, f"scope guard rejects {ip}"
        if ip not in self._host_network:
            return False, f"{ip} is not a discovered live host — trace only known hosts"
        status = self.discovery_run.tools.get("traceroute")
        if status is None or not status.available:
            return False, "traceroute is not available on this host"
        return True, "ok"

    # -- execution --------------------------------------------------------------

    def _exec_scan(self, cidr: str, profile: str) -> NetworkResult:
        network = parse_network(cidr)
        seed = self._candidates.pop(cidr, None)
        if seed is None:
            seed = NetworkSeed(cidr=cidr, discovered_via="agent", depth=self._depths.get(cidr, 0))
        self.discovery_run.visited.add(cidr)
        self._networks_used += 1
        self._emit(f"scan_network {cidr} (profile {profile}, depth {seed.depth})")
        try:
            result = discovery._process_network(network, seed, self.discovery_run, profile=profile)
        except base.ScannerError as exc:
            result = NetworkResult(seed=seed, error=str(exc))
        self.discovery_run.results.append(result)
        if result.error is None:
            self._feedback = ""
            for host in result.live_hosts:
                self._host_network.setdefault(host.ip, cidr)
            self._emit(f"{cidr}: {len(result.live_hosts)} live host(s)")
        else:
            self._feedback = f"scan of {cidr} failed: {result.error}"
            self._emit(f"{cidr}: scan failed: {result.error}")
        return result

    def _exec_trace(self, ip: str) -> None:
        parent_cidr = self._host_network[ip]
        parent_depth = self._depths.get(parent_cidr, 0)
        self._emit(f"trace_host {ip}")
        hops = traceroute.trace_hops(ip)
        parent = parse_network(parent_cidr)
        new_seeds = discovery._candidates_from_hops(
            hops, parent, parent_depth + 1, self.discovery_run.guard, self.discovery_run.visited
        )
        added = 0
        for seed in new_seeds:
            if seed.cidr not in self._candidates:
                self._candidates[seed.cidr] = seed
                self._depths.setdefault(seed.cidr, seed.depth)
                added += 1
        self._feedback = ""
        self._emit(f"trace {ip}: {len(hops)} hop(s), {added} new candidate network(s)")

    # -- helpers ------------------------------------------------------------------

    def _describe(self, action: dict[str, Any]) -> str:
        kind = action["action"]
        reason = str(action.get("reason") or "").strip()
        suffix = f" — {reason}" if reason else ""
        if kind == "scan_network":
            return f"scan_network {action['cidr']} profile={action.get('_profile', 'fast')}{suffix}"
        return f"trace_host {action.get('ip')}{suffix}"

    def _record(self, action: dict[str, Any], valid: bool, verdict: str) -> None:
        self.audit.append(
            {
                "step": len(self.audit) + 1,
                "action": {k: v for k, v in action.items() if not k.startswith("_")},
                "accepted": valid,
                "verdict": verdict,
                "model": self.client.planner_model,
            }
        )

    def _emit(self, message: str) -> None:
        self.on_event(message)

    def _finish(self, reason: str) -> None:
        self.stop_reason = reason
        self._emit(f"agent stopped: {reason}")
