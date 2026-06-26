"""OpenAI 兼容客户端 (基于 requests), 对接本地 vLLM (Qwen3.6).

要点:
- 取回 message.reasoning (Qwen3.6 推理模型的思考链, 作审计溯源);
- 支持 response_format=json_schema 做结构化输出;
- 通过 chat_template_kwargs.enable_thinking 控制是否开思考;
- 简单重试.
"""
from __future__ import annotations

import time
from typing import Any, Optional

import requests

from ..config import Config


class ChatClient:
    def __init__(self, base_url: str, model: str, api_key: str = "EMPTY",
                 timeout_s: int = 600, max_retries: int = 3):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        # 只连本地 vLLM: 用 trust_env=False 忽略环境里的 http(s)_proxy(如 clash 127.0.0.1:8990),
        # 否则断网时本地请求会被路由到挂掉的代理 -> 全部失败。
        self._sess = requests.Session()
        self._sess.trust_env = False

    @classmethod
    def from_cfg(cls, cfg: Config) -> "ChatClient":
        m = cfg.model
        return cls(m.base_url, m.model, m.api_key, m.request_timeout_s, m.max_retries)

    def chat(
        self,
        messages: list[dict[str, Any]],
        response_format: Optional[dict] = None,
        max_tokens: int = 2048,
        temperature: float = 0.0,
        enable_thinking: Optional[bool] = None,
        extra_body: Optional[dict] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format:
            body["response_format"] = response_format
        if enable_thinking is not None:
            body["chat_template_kwargs"] = {"enable_thinking": enable_thinking}
        if extra_body:
            body.update(extra_body)

        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        url = f"{self.base_url}/chat/completions"
        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                r = self._sess.post(url, json=body, headers=headers, timeout=self.timeout_s)
                r.raise_for_status()
                data = r.json()
                msg = data["choices"][0]["message"]
                return {
                    "content": msg.get("content") or "",
                    "reasoning": msg.get("reasoning") or msg.get("reasoning_content") or "",
                    "finish_reason": data["choices"][0].get("finish_reason"),
                    "usage": data.get("usage", {}),
                    "raw": data,
                }
            except Exception as e:  # noqa: BLE001
                last_err = e
                if attempt < self.max_retries - 1:
                    time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"chat 请求失败 ({self.max_retries} 次): {last_err}")

    def count_tokens(self, text: str) -> Optional[int]:
        """用 vLLM /tokenize 精确计数 (可选). 失败返回 None."""
        try:
            r = self._sess.post(
                f"{self.base_url.rsplit('/v1', 1)[0]}/tokenize",
                json={"model": self.model, "prompt": text},
                timeout=30,
            )
            r.raise_for_status()
            return r.json().get("count")
        except Exception:
            return None

    def health(self) -> bool:
        try:
            r = self._sess.get(f"{self.base_url}/models", timeout=10)
            return r.status_code == 200
        except Exception:
            return False
