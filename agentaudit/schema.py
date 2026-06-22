"""统一数据模型 (pydantic v2).

三层原始日志被各自的解析器规整成 AppEvent / SysEvent / NetFlow,
汇合为一个 TrajectoryInput; 分类器产出 AuditVerdict.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Layer(str, Enum):
    APP = "app"
    SYSTEM = "system"
    NETWORK = "network"


# ----------------------------------------------------------------------------
# 应用层 (session.jsonl): 智能体的每一步 = (action, observation)
# ----------------------------------------------------------------------------
class AppEvent(BaseModel):
    idx: int
    ts: Optional[float] = None
    role: str = ""                 # user | assistant | tool | system
    type: str = ""                 # message | tool_use | tool_result | reasoning ...
    tool: Optional[str] = None     # 工具名 (bash / write_file / web_fetch ...)
    text: str = ""                 # 规整后的可读文本 (命令 / 消息 / 工具返回)
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)


# ----------------------------------------------------------------------------
# 系统层 (auditd / syslog / strace ...): 实际落到 OS 的行为
# ----------------------------------------------------------------------------
class SysEvent(BaseModel):
    idx: int
    ts: Optional[float] = None
    kind: str = "other"            # exec | file | net | priv | other
    summary: str = ""              # 单行摘要
    raw: str = ""


# ----------------------------------------------------------------------------
# 网络层 (pcap): 聚合后的连接 / DNS / TLS-SNI / HTTP
# ----------------------------------------------------------------------------
class NetFlow(BaseModel):
    ts_start: Optional[float] = None
    proto: str = ""                # TCP | UDP | DNS | TLS | HTTP
    src: str = ""
    dst: str = ""
    dport: Optional[int] = None
    host: Optional[str] = None     # SNI / HTTP Host / DNS qname
    bytes_out: int = 0
    bytes_in: int = 0
    info: str = ""                 # 附加信息 (HTTP 方法+路径 / DNS 类型 ...)
    external: bool = False         # 目的地是否为公网 (非私网/回环)


class TrajectoryInput(BaseModel):
    traj_id: str
    app_events: list[AppEvent] = Field(default_factory=list)
    sys_events: list[SysEvent] = Field(default_factory=list)
    net_flows: list[NetFlow] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        return {
            "app_events": len(self.app_events),
            "sys_events": len(self.sys_events),
            "net_flows": len(self.net_flows),
        }


# ----------------------------------------------------------------------------
# 输出: 审计裁决. 阶段一只强约束 label/confidence/rationale;
# attack_categories 命中「恶意操作字典表」分类, 阶段二复用.
# ----------------------------------------------------------------------------
class AuditVerdict(BaseModel):
    traj_id: str
    label: str = "safe"            # "safe" | "risky"
    risky: bool = False
    confidence: float = 0.0
    rationale: str = ""
    # 命中的恶意操作分类 (来自字典表; 阶段一可空)
    attack_categories: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    # 记账 / 溯源
    model: str = ""
    reasoning: str = ""            # 模型思考链 (provenance)
    usage: dict[str, Any] = Field(default_factory=dict)
    error: str = ""

    def to_row(self) -> dict[str, Any]:
        """落盘用的扁平行 (results.jsonl)."""
        d = self.model_dump()
        return d
