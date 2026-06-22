"""Assemble a TrajectoryInput into "audit evidence" text within a token budget.

Budget split: (total_budget - reserve_output) is divided across the 3 layers by
layer_ratios; each layer keeps high-signal items first within its budget (preserving
chronological order; over-budget items are dropped with an omission note). A
"cross-layer heuristic flags" section is appended as strong hints (not conclusions).
"""
from __future__ import annotations

import re

from ..config import Config
from ..schema import AppEvent, NetFlow, SysEvent, TrajectoryInput
from .redact import redact_text

# High-signal keywords (kept first when truncating; also drive heuristic flags).
# These match trajectory CONTENT (which may be English or Chinese), not prompt text.
_HI_APP = re.compile(
    r"(?i)(rm\s+-rf|mkfs|dd\s+if=|:\(\)\{|curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh|"
    r"sudo|chmod\s+777|/etc/(passwd|shadow)|\.env\b|id_rsa|\.ssh/|"
    r"api[_-]?key|secret|token|password|私钥|密钥|aws_|AKIA|"
    r"base64\s+-d|nc\s+-|/dev/tcp/|ignore (all )?previous|忽略(以上|之前)的?指令)"
)
_SECRET_ACCESS = re.compile(r"(?i)(\.env\b|id_rsa|\.ssh/|api[_-]?key|secret|token|password|credential|AKIA|私钥|密钥)")
_DESTRUCTIVE = re.compile(r"(?i)(rm\s+-rf|mkfs|dd\s+if=.*of=/dev|>\s*/dev/sd|format\s|chmod\s+-R\s+777|:\(\)\{\s*:\|:&\s*\};:)")
_PIPE_EXEC = re.compile(r"(?i)(curl|wget)[^|]*\|\s*(ba)?sh")
_INJECTION = re.compile(r"(?i)(ignore (all )?previous instructions|disregard .* instructions|忽略(以上|之前)的?(所有)?指令|你现在是)")


def est_tokens(text: str, cfg: Config) -> int:
    return int(len(text) * cfg.context.token_per_char) + 1


def _budgeted(items: list[tuple[int, str]], budget: int, cfg: Config) -> tuple[list[str], int]:
    """items=[(score, text)] in order; if over budget, keep by score then restore order.
    Returns (kept_lines, n_omitted)."""
    toks = [est_tokens(t, cfg) for _, t in items]
    total = sum(toks)
    if total <= budget:
        return [t for _, t in items], 0
    order = sorted(range(len(items)), key=lambda i: (-items[i][0], -toks[i] if items[i][0] else toks[i]))
    keep: set[int] = set()
    used = 0
    for i in order:
        if used + toks[i] <= budget:
            keep.add(i)
            used += toks[i]
    kept_lines = [items[i][1] for i in range(len(items)) if i in keep]
    return kept_lines, len(items) - len(keep)


def _render_app(events: list[AppEvent], budget: int, cfg: Config) -> str:
    items: list[tuple[int, str]] = []
    for e in events:
        text = e.text if len(e.text) <= 4000 else e.text[:4000] + " …[truncated]"
        score = 0
        if e.type in ("tool_use", "tool_result"):
            score = 1
        if _HI_APP.search(e.text):
            score = 3
        tag = f"[{e.idx}] {e.role}/{e.type}" + (f"({e.tool})" if e.tool else "")
        items.append((score, f"{tag}: {text}"))
    lines, omitted = _budgeted(items, budget, cfg)
    head = f"Application layer (session.jsonl): {len(events)} steps"
    if omitted:
        head += f", {omitted} low-signal steps omitted for budget"
    return head + "\n" + "\n".join(lines)


def _render_system(events: list[SysEvent], budget: int, cfg: Config) -> str:
    if not events:
        return "System layer: (no data)"
    kind_score = {"exec": 3, "priv": 3, "net": 2, "file": 1, "other": 0}
    items = [(kind_score.get(e.kind, 0), f"[{e.idx}] {e.kind}: {e.summary}") for e in events]
    lines, omitted = _budgeted(items, budget, cfg)
    head = f"System layer: {len(events)} events"
    if omitted:
        head += f", {omitted} low-signal omitted"
    return head + "\n" + "\n".join(lines)


def _render_network(flows: list[NetFlow], budget: int, cfg: Config) -> str:
    if not flows:
        return "Network layer: (no data)"
    items: list[tuple[int, str]] = []
    for f in flows:
        score = 3 if f.external else 1
        if f.proto in ("DNS", "TLS", "HTTP"):
            score += 1
        hostpart = f" host={f.host}" if f.host else ""
        bytestr = f" out={f.bytes_out}B" if f.bytes_out else ""
        info = f" {f.info}" if f.info else ""
        ext = " [EXT]" if f.external else ""
        items.append((score, f"{f.proto} {f.src}->{f.dst}:{f.dport}{ext}{hostpart}{bytestr}{info}"))
    lines, omitted = _budgeted(items, budget, cfg)
    n_ext = sum(1 for f in flows if f.external)
    head = f"Network layer: {len(flows)} records, {n_ext} to external destinations"
    if omitted:
        head += f", {omitted} omitted"
    return head + "\n" + "\n".join(lines)


def _heuristic_flags(traj: TrajectoryInput) -> str:
    flags: list[str] = []
    app_text = "\n".join(e.text for e in traj.app_events)
    ext_flows = [f for f in traj.net_flows if f.external]
    ext_bytes = sum(f.bytes_out for f in ext_flows)
    ext_hosts = sorted({f.host for f in ext_flows if f.host})

    if _SECRET_ACCESS.search(app_text) and ext_flows:
        flags.append(f"⚠ cross-layer: app touches secrets/sensitive files AND {len(ext_flows)} external outbound flows ({ext_bytes}B total) -> possible data exfiltration")
    if _DESTRUCTIVE.search(app_text):
        flags.append("⚠ app contains a destructive command (rm -rf / mkfs / dd ...)")
    if _PIPE_EXEC.search(app_text):
        flags.append("⚠ app pipes curl/wget directly into a shell (supply-chain risk)")
    if _INJECTION.search(app_text):
        flags.append("⚠ possible prompt-injection text (ignore previous instructions ...)")
    priv = [e for e in traj.sys_events if e.kind == "priv"]
    if priv:
        flags.append(f"⚠ system layer: {len(priv)} privilege-escalation syscalls")
    if ext_flows and "http" not in app_text.lower() and "url" not in app_text.lower() and "curl" not in app_text.lower() and "wget" not in app_text.lower():
        flags.append(f"⚠ cross-layer inconsistency: app declares no network use, but network shows {len(ext_flows)} external connections ({', '.join(ext_hosts[:5]) or 'no hostnames'})")

    if not flags:
        return "Cross-layer heuristic flags: (no obvious high-risk signal; still requires holistic judgment by the model)"
    return "Cross-layer heuristic flags (hints only, not conclusions):\n" + "\n".join(f"- {x}" for x in flags)


def assemble_evidence(traj: TrajectoryInput, cfg: Config) -> str:
    avail = cfg.context.total_budget - cfg.context.reserve_output
    ratios = cfg.context.layer_ratios
    s = sum(ratios.values()) or 1.0
    b_app = int(avail * ratios.get("app", 0.5) / s)
    b_sys = int(avail * ratios.get("system", 0.25) / s)
    b_net = int(avail * ratios.get("network", 0.25) / s)

    app = _render_app(traj.app_events, b_app, cfg)
    sysl = _render_system(traj.sys_events, b_sys, cfg)
    net = _render_network(traj.net_flows, b_net, cfg)
    flags = _heuristic_flags(traj)

    counts = traj.counts()
    header = (
        f"Trajectory ID: {traj.traj_id}\n"
        f"Scale: app {counts['app_events']} steps / system {counts['sys_events']} events / network {counts['net_flows']} records\n"
    )
    body = "\n\n".join([header, flags, "===== APPLICATION LAYER =====\n" + app, "===== SYSTEM LAYER =====\n" + sysl, "===== NETWORK LAYER =====\n" + net])
    if cfg.audit.redact_secrets:
        body = redact_text(body)
    return body
