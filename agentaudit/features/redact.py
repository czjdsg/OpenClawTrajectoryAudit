"""可选脱敏. 默认关闭 —— 审计判"泄露"恰恰需要看到密钥原文.
仅在结果落盘或对外分享时按需开启 (config.audit.redact_secrets).
"""
from __future__ import annotations

import re

_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|bearer)\s*[:=]\s*\S+"), r"\1=<REDACTED>"),
    (re.compile(r"sk-[A-Za-z0-9]{16,}"), "<REDACTED_KEY>"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "<REDACTED_AWS>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "<REDACTED_PRIVKEY>"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<REDACTED_EMAIL>"),
]


def redact_text(text: str) -> str:
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text
