"""解析应用层 session.jsonl -> list[AppEvent].

主路径 = OpenClaw schema (已对照真实样例):
  外层信封: {type, id, timestamp, parentId, message:{...}}
  - type=="message": message.role ∈ {user, assistant, toolResult};
      content 为 block 列表, block.type ∈ {text, thinking, toolCall}
      toolCall: {name, arguments}; toolResult 消息含 toolName/isError
  - type ∈ {session, model_change, thinking_level_change, custom}: 元数据
保留通用回退 (OpenAI/Anthropic 风格), 兼容其它来源.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from ..schema import AppEvent

_HEX_A = re.compile(r"^a\d+$")


def _parse_ts(rec: dict[str, Any]) -> Optional[float]:
    for k in ("ts", "timestamp", "time", "created_at", "createdAt"):
        v = rec.get(k)
        if v is None:
            continue
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            try:
                return float(v)
            except ValueError:
                pass
            try:
                from datetime import datetime
                return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
            except Exception:
                return None
    return None


def _stringify(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, dict):
                parts.append(str(c.get("text") or c.get("content") or json.dumps(c, ensure_ascii=False)))
            else:
                parts.append(str(c))
        return "\n".join(parts)
    return json.dumps(content, ensure_ascii=False)


def _block_to_event(block: Any, role: str, ts: Optional[float], idx: int, raw: dict) -> Optional[AppEvent]:
    if not isinstance(block, dict):
        return AppEvent(idx=idx, ts=ts, role=role, type="message", text=str(block), raw=raw)
    bt = block.get("type", "")
    if bt == "text":
        return AppEvent(idx=idx, ts=ts, role=role, type="message", text=str(block.get("text", "")), raw=raw)
    if bt in ("thinking", "reasoning"):
        return AppEvent(idx=idx, ts=ts, role=role, type="thinking", text=str(block.get("text") or block.get("thinking") or ""), raw=raw)
    if bt in ("toolCall", "tool_use", "tool_call", "function_call"):
        name = block.get("name") or block.get("tool") or (block.get("function") or {}).get("name")
        args = block.get("arguments")
        if args is None:
            args = block.get("input") or (block.get("function") or {}).get("arguments")
        return AppEvent(idx=idx, ts=ts, role=role or "assistant", type="tool_use", tool=name,
                        text=f"call tool {name}: {json.dumps(args, ensure_ascii=False)}", raw=raw)
    if bt in ("toolResult", "tool_result", "tool_response"):
        return AppEvent(idx=idx, ts=ts, role="tool", type="tool_result",
                        tool=block.get("toolName") or block.get("name"),
                        text=_stringify(block.get("content") or block.get("output")), raw=raw)
    # 未知 block
    txt = str(block.get("text") or json.dumps(block, ensure_ascii=False))
    return AppEvent(idx=idx, ts=ts, role=role, type=bt or "block", text=txt, raw=raw)


def _extract_one(rec: dict[str, Any], start_idx: int) -> list[AppEvent]:
    ts = _parse_ts(rec)
    rtype = rec.get("type")

    # ---- OpenClaw 信封: 消息在 rec["message"] ----
    if rtype == "message" and isinstance(rec.get("message"), dict):
        m = rec["message"]
        role = m.get("role", "")
        content = m.get("content")
        if role == "toolResult":
            text = _stringify(content)
            flag = " [error]" if m.get("isError") else ""
            return [AppEvent(idx=start_idx, ts=ts, role="tool", type="tool_result",
                             tool=m.get("toolName"), text=f"[tool result {m.get('toolName')}{flag}] {text}", raw=rec)]
        events: list[AppEvent] = []
        idx = start_idx
        if isinstance(content, list):
            for b in content:
                ev = _block_to_event(b, role, ts, idx, rec if idx == start_idx else {})
                if ev and ev.text.strip():
                    events.append(ev)
                    idx += 1
        elif content is not None:
            events.append(AppEvent(idx=idx, ts=ts, role=role or "unknown", type="message", text=_stringify(content), raw=rec))
        return events

    # ---- OpenClaw 元数据信封 (降噪) ----
    if rtype == "session":
        return [AppEvent(idx=start_idx, ts=ts, role="system", type="session", text=f"[session] cwd={rec.get('cwd')}", raw=rec)]
    if rtype in ("model_change", "thinking_level_change"):
        return []  # 噪声
    if rtype == "custom":
        return [AppEvent(idx=start_idx, ts=ts, role="system", type="custom", text=f"[custom] {json.dumps(rec.get('data'), ensure_ascii=False)[:500]}", raw=rec)]

    # ---- 通用回退: OpenAI/Anthropic 风格 ----
    return _extract_generic(rec, start_idx, ts)


def _extract_generic(rec: dict[str, Any], start_idx: int, ts: Optional[float]) -> list[AppEvent]:
    msg = rec.get("message") if isinstance(rec.get("message"), dict) else None
    role = (rec.get("role") or (msg or {}).get("role") or rec.get("type") or "").lower()
    content = rec.get("content")
    if content is None and msg is not None:
        content = msg.get("content")
    events: list[AppEvent] = []
    idx = start_idx
    for tc in (rec.get("tool_calls") or (msg or {}).get("tool_calls") or []):
        ev = _block_to_event({"type": "tool_call", **tc}, role or "assistant", ts, idx, rec)
        events.append(ev)
        idx += 1
    if isinstance(content, list):
        for b in content:
            ev = _block_to_event(b, role, ts, idx, rec if idx == start_idx else {})
            if ev and ev.text.strip():
                events.append(ev)
                idx += 1
    elif content is not None or not events:
        etype = "tool_result" if role == "tool" else "message"
        events.append(AppEvent(idx=idx, ts=ts, role=role or "unknown", type=etype, tool=rec.get("name"), text=_stringify(content), raw=rec))
    return events


def parse_session(path: str | Path) -> list[AppEvent]:
    path = Path(path)
    events: list[AppEvent] = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                events.append(AppEvent(idx=len(events), role="unknown", type="raw", text=line[:2000]))
                continue
            if isinstance(rec, list):
                for sub in rec:
                    if isinstance(sub, dict):
                        events.extend(_extract_one(sub, len(events)))
            elif isinstance(rec, dict):
                events.extend(_extract_one(rec, len(events)))
    for i, e in enumerate(events):
        e.idx = i
    return events
