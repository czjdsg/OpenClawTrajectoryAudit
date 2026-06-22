"""配置加载: 读 config.yaml -> 强类型 Config (带默认值)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


class ModelCfg(BaseModel):
    base_url: str = "http://localhost:8000/v1"
    model: str = "qwen3.6"
    api_key: str = "EMPTY"
    temperature: float = 0.0
    max_tokens: int = 2048
    enable_thinking: bool = True
    request_timeout_s: int = 600
    max_retries: int = 3


class ContextCfg(BaseModel):
    total_budget: int = 240000
    reserve_output: int = 4000
    layer_ratios: dict[str, float] = Field(
        default_factory=lambda: {"app": 0.5, "system": 0.25, "network": 0.25}
    )
    token_per_char: float = 0.35
    use_server_tokenizer: bool = False


class DiscoveryCfg(BaseModel):
    layout: str = "dir_per_trajectory"
    app_glob: list[str] = Field(default_factory=lambda: ["session.jsonl"])
    system_glob: list[str] = Field(default_factory=lambda: ["sys*.log", "audit*.log"])
    network_glob: list[str] = Field(default_factory=lambda: ["*.pcap", "*.pcapng"])


class AuditCfg(BaseModel):
    decision_rule: str = "any_step_unsafe"
    risk_threshold: float = 0.5
    redact_secrets: bool = False
    syscall_filter: str = "security"   # "security"=只留安全相关syscall(默认), "all"=全留


class RunCfg(BaseModel):
    concurrency: int = 4
    output_dir: str = "/data/agent-audit/outputs"
    save_reasoning: bool = True


class Config(BaseModel):
    model: ModelCfg = Field(default_factory=ModelCfg)
    context: ContextCfg = Field(default_factory=ContextCfg)
    discovery: DiscoveryCfg = Field(default_factory=DiscoveryCfg)
    audit: AuditCfg = Field(default_factory=AuditCfg)
    run: RunCfg = Field(default_factory=RunCfg)


def load_config(path: str | os.PathLike | None = None) -> Config:
    p = Path(path) if path else _DEFAULT_PATH
    if not p.exists():
        return Config()
    data: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return Config.model_validate(data)
