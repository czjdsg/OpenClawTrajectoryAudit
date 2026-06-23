"""基准: 跑全数据集, 统计各层 token 开销 + 每条推理时间(串行, 干净延迟)。
用法: python scripts/bench.py <dataset_dir> [results.csv] [out_dir]
输出: <out_dir>/bench.csv + 控制台汇总。
"""
from __future__ import annotations

import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agentaudit.config import load_config  # noqa: E402
from agentaudit.features.assemble import assemble_evidence  # noqa: E402
from agentaudit.ingest.discover import discover  # noqa: E402
from agentaudit.llm.classify import _extract_json  # noqa: E402
from agentaudit.llm.client import ChatClient  # noqa: E402
from agentaudit.llm.prompts import SYSTEM_PROMPT, VERDICT_SCHEMA, build_messages  # noqa: E402
from agentaudit.pipeline import load_trajectory  # noqa: E402


def main():
    cfg = load_config()
    ds = sys.argv[1] if len(sys.argv) > 1 else "/data/example-s7-0623/extracted"
    labels = {}
    lpath = sys.argv[2] if len(sys.argv) > 2 else "/data/example-s7-0623/results.csv"
    if Path(lpath).exists():
        labels = {r["md5"]: r["label"] for r in csv.DictReader(open(lpath))}
    out = Path(sys.argv[3] if len(sys.argv) > 3 else "/data/example-s7-0623/outputs_bench")
    out.mkdir(parents=True, exist_ok=True)

    tpc = cfg.context.token_per_char
    sysprompt_tok = int(len(SYSTEM_PROMPT) * tpc)
    client = ChatClient.from_cfg(cfg)
    print(f"[*] 数据集 {ds} | 模型 {cfg.model.model} | thinking={cfg.model.enable_thinking} | 串行计时")
    print(f"[*] system prompt 固定 ~{sysprompt_tok} tokens")

    trajs = discover(ds, cfg.discovery)
    rows = []
    wall0 = time.time()
    for i, tp in enumerate(trajs, 1):
        t0 = time.time()
        traj = load_trajectory(tp, cfg.audit.syscall_filter == "security")
        parse_s = time.time() - t0
        app_t = int(sum(min(len(e.text), 4000) + 20 for e in traj.app_events) * tpc)
        sys_t = int(sum(len(e.summary) + 8 for e in traj.sys_events) * tpc)
        net_t = int(sum(len(f"{f.proto} {f.dst} {f.host or ''} {f.info}") for f in traj.net_flows) * tpc)
        ev = assemble_evidence(traj, cfg)
        msgs = build_messages(ev, tp.traj_id)
        t1 = time.time()
        try:
            resp = client.chat(msgs, response_format={"type": "json_schema", "json_schema": {"name": "v", "schema": VERDICT_SCHEMA}},
                               max_tokens=cfg.model.max_tokens, temperature=cfg.model.temperature, enable_thinking=cfg.model.enable_thinking)
            infer_s = time.time() - t1
            u = resp.get("usage", {})
            data = _extract_json(resp["content"]) or {}
            pred = "risky" if str(data.get("label", "")).lower() == "risky" else ("safe" if data.get("label") else "?")
            prompt_tok = u.get("prompt_tokens"); comp_tok = u.get("completion_tokens")
        except Exception as e:  # noqa: BLE001
            infer_s = time.time() - t1; pred = "error"; prompt_tok = comp_tok = None
            print("  err", tp.traj_id[:10], e)
        sys_type = tp.system_path.name if tp.system_path else "-"
        rows.append(dict(md5=tp.traj_id, label=labels.get(tp.traj_id, ""), pred=pred, sys_type=sys_type,
                         app_tok=app_t, sys_tok=sys_t, net_tok=net_t, est_prompt=sysprompt_tok + app_t + sys_t + net_t,
                         prompt_tokens=prompt_tok, completion_tokens=comp_tok, parse_s=round(parse_s, 1), infer_s=round(infer_s, 1)))
        r = rows[-1]
        print(f"  [{i}/{len(trajs)}] {tp.traj_id[:10]} {sys_type:12} pred={pred:5} "
              f"prompt={prompt_tok} comp={comp_tok} parse={r['parse_s']}s infer={r['infer_s']}s")
    wall = time.time() - wall0

    with (out / "bench.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    def col(k):
        return [r[k] for r in rows if isinstance(r[k], (int, float))]
    n = len(rows)
    pt = col("prompt_tokens"); ct = col("completion_tokens"); inf = col("infer_s")
    print("\n==================== 汇总 ====================")
    print(f"轨迹数 {n} | 总墙钟(串行) {wall:.0f}s | 平均 {wall/n:.1f}s/条")
    print(f"prompt_tokens(实测): 均 {sum(pt)//len(pt) if pt else 0} | 中位 {sorted(pt)[len(pt)//2] if pt else 0} | 最大 {max(pt) if pt else 0}")
    print(f"completion_tokens : 均 {sum(ct)//len(ct) if ct else 0} | 最大 {max(ct) if ct else 0}")
    print(f"推理时间 infer_s   : 均 {sum(inf)/len(inf):.1f}s | 中位 {sorted(inf)[len(inf)//2]:.1f}s | 最大 {max(inf):.1f}s")
    print(f"各层 token(估算)占比: 应用 {sum(col('app_tok'))} | 系统 {sum(col('sys_tok'))} | 网络 {sum(col('net_tok'))} | sysprompt {sysprompt_tok*n}")
    tot_layer = sum(col('app_tok')) + sum(col('sys_tok')) + sum(col('net_tok')) or 1
    print(f"               比例: 应用 {100*sum(col('app_tok'))//tot_layer}% / 系统 {100*sum(col('sys_tok'))//tot_layer}% / 网络 {100*sum(col('net_tok'))//tot_layer}%")
    win = [r for r in rows if "sysmon" in r["sys_type"]]
    lin = [r for r in rows if "audit" in r["sys_type"]]
    if win:
        print(f"Windows({len(win)}条): infer 均 {sum(r['infer_s'] for r in win)/len(win):.1f}s, prompt 均 {sum(r['prompt_tokens'] for r in win if r['prompt_tokens'])//len(win)}")
    if lin:
        print(f"Linux({len(lin)}条):   infer 均 {sum(r['infer_s'] for r in lin)/len(lin):.1f}s, prompt 均 {sum(r['prompt_tokens'] for r in lin if r['prompt_tokens'])//len(lin)}")
    print(f"[*] 明细: {out/'bench.csv'}")


if __name__ == "__main__":
    main()
