"""把实际送入模型的完整 prompt (请求参数 + system + user 全文) 导出为文本文件, 便于人工查看.

用法:
    python scripts/dump_prompt.py <轨迹目录> [输出文件]
例:
    python scripts/dump_prompt.py /data/example-s7/extracted/<md5>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentaudit.config import load_config  # noqa: E402
from agentaudit.features.assemble import assemble_evidence  # noqa: E402
from agentaudit.ingest.discover import TrajectoryPaths, _first_match  # noqa: E402
from agentaudit.llm.prompts import VERDICT_SCHEMA, build_messages  # noqa: E402
from agentaudit.pipeline import load_trajectory  # noqa: E402


def dump(traj_dir: Path, out: Path, cfg) -> Path:
    paths = TrajectoryPaths(
        traj_id=traj_dir.name, root=traj_dir,
        app_path=_first_match(traj_dir, cfg.discovery.app_glob),
        system_path=_first_match(traj_dir, cfg.discovery.system_glob),
        network_path=_first_match(traj_dir, cfg.discovery.network_glob),
    )
    traj = load_trajectory(paths)
    ev = assemble_evidence(traj, cfg)
    msgs = build_messages(ev, traj.traj_id)
    sys_msg, user_msg = msgs[0]["content"], msgs[1]["content"]
    approx = int((len(sys_msg) + len(user_msg)) * cfg.context.token_per_char)

    req_params = {
        "model": cfg.model.model,
        "temperature": cfg.model.temperature,
        "max_tokens": cfg.model.max_tokens,
        "chat_template_kwargs": {"enable_thinking": cfg.model.enable_thinking},
        "response_format": {"type": "json_schema", "json_schema": {"name": "audit_verdict", "schema": VERDICT_SCHEMA}},
    }
    sep = "#" * 100
    parts = [
        "=" * 100,
        f"轨迹 {traj.traj_id}   层={paths.available()}   规模={traj.counts()}",
        f"system={len(sys_msg)} 字符 | user={len(user_msg)} 字符 | 合计 ≈ {approx} tokens",
        "=" * 100,
        "",
        "###### 请求参数 (messages 之外, client 实际发送) ######",
        json.dumps(req_params, ensure_ascii=False, indent=2),
        "",
        sep, "###### messages[0] = SYSTEM ######", sep,
        sys_msg,
        "",
        sep, "###### messages[1] = USER (跨层证据全文) ######", sep,
        user_msg,
    ]
    out.write_text("\n".join(parts), encoding="utf-8")
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cfg = load_config()
    traj_dir = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else traj_dir.parent.parent / f"prompt_dump_{traj_dir.name[:12]}.txt"
    p = dump(traj_dir, out, cfg)
    print(f"已写入: {p}  ({p.stat().st_size} 字节)")


if __name__ == "__main__":
    main()
