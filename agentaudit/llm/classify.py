"""轨迹 -> 二分类裁决 (调用 Qwen3.6, 结构化输出)."""
from __future__ import annotations

import json
from typing import Any, Optional

from ..config import Config
from ..features.assemble import assemble_evidence
from ..schema import AuditVerdict, TrajectoryInput
from .client import ChatClient
from .prompts import VERDICT_SCHEMA, build_messages


def _extract_json(s: str) -> Optional[dict[str, Any]]:
    """从模型输出里稳健地抠出第一个 JSON 对象."""
    if not s:
        return None
    s = s.strip()
    if s.startswith("```"):
        s = s.strip("`")
        nl = s.find("\n")
        if nl != -1:
            s = s[nl + 1:]
    start = s.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start:i + 1])
                except json.JSONDecodeError:
                    break
    try:
        return json.loads(s[start:])
    except json.JSONDecodeError:
        return None


def classify(traj: TrajectoryInput, cfg: Config, client: Optional[ChatClient] = None) -> AuditVerdict:
    client = client or ChatClient.from_cfg(cfg)
    evidence = assemble_evidence(traj, cfg)
    messages = build_messages(evidence, traj.traj_id)

    try:
        resp = client.chat(
            messages,
            response_format={"type": "json_schema", "json_schema": {"name": "audit_verdict", "schema": VERDICT_SCHEMA}},
            max_tokens=cfg.model.max_tokens,
            temperature=cfg.model.temperature,
            enable_thinking=cfg.model.enable_thinking,
        )
    except Exception as e:  # noqa: BLE001
        return AuditVerdict(traj_id=traj.traj_id, label="error", error=str(e), model=cfg.model.model)

    data = _extract_json(resp["content"])
    if not data:
        # 思考用尽 token 等情况: 给出 error, 默认 safe 不漏报到下游误判
        return AuditVerdict(
            traj_id=traj.traj_id, label="error", model=cfg.model.model,
            reasoning=resp.get("reasoning", "") if cfg.run.save_reasoning else "",
            usage=resp.get("usage", {}),
            error=f"无法解析JSON; finish_reason={resp.get('finish_reason')}; content[:200]={resp['content'][:200]!r}",
        )

    raw_label = str(data.get("label", "safe")).lower()
    conf = float(data.get("confidence", 0.0) or 0.0)
    risky = raw_label == "risky" and conf >= cfg.audit.risk_threshold

    return AuditVerdict(
        traj_id=traj.traj_id,
        label="risky" if risky else "safe",
        risky=risky,
        confidence=conf,
        rationale=str(data.get("rationale", "")),
        attack_categories=list(data.get("attack_categories", []) or []),
        evidence=list(data.get("evidence", []) or []),
        model=cfg.model.model,
        reasoning=resp.get("reasoning", "") if cfg.run.save_reasoning else "",
        usage=resp.get("usage", {}),
    )
