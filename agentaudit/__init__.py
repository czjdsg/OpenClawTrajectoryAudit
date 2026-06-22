"""agent-audit: 用 Qwen3.6-35B 对 OpenClaw 智能体轨迹做跨层(应用/系统/网络)安全审计.

阶段一: 轨迹级二分类 (safe / risky).
设计对齐 AgentDoG (arXiv:2601.18491), 决策规则 "任一步骤不安全 => 轨迹不安全".
"""

__version__ = "0.1.0"
