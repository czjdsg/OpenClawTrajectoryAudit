"""批量审计: 发现数据集中的轨迹, 并发跑分类, 落盘 results.jsonl + summary."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .config import Config
from .ingest.discover import discover
from .llm.client import ChatClient
from .pipeline import audit_one
from .schema import AuditVerdict


def run_dataset(dataset_dir: str, cfg: Config) -> list[AuditVerdict]:
    trajs = discover(dataset_dir, cfg.discovery)
    if not trajs:
        print(f"[!] 在 {dataset_dir} 未发现轨迹 (检查 config.discovery 的 glob)")
        return []

    out_dir = Path(cfg.run.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"
    client = ChatClient.from_cfg(cfg)

    print(f"[*] 发现 {len(trajs)} 条轨迹, 并发 {cfg.run.concurrency}, 模型 {cfg.model.model}")
    if not client.health():
        print(f"[!] 警告: {cfg.model.base_url} /models 不可达, 请确认 vLLM 在跑")

    verdicts: list[AuditVerdict] = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=cfg.run.concurrency) as ex, results_path.open("w", encoding="utf-8") as fout:
        futs = {ex.submit(audit_one, tp, cfg, client): tp for tp in trajs}
        for n, fut in enumerate(as_completed(futs), 1):
            tp = futs[fut]
            try:
                v = fut.result()
            except Exception as e:  # noqa: BLE001
                v = AuditVerdict(traj_id=tp.traj_id, label="error", error=str(e))
            verdicts.append(v)
            fout.write(json.dumps(v.to_row(), ensure_ascii=False) + "\n")
            fout.flush()
            mark = {"risky": "🔴", "safe": "🟢", "error": "⚠️"}.get(v.label, "?")
            print(f"  [{n}/{len(trajs)}] {mark} {v.traj_id}  conf={v.confidence:.2f}  {v.rationale[:60]}")

    n_risky = sum(1 for v in verdicts if v.risky)
    n_err = sum(1 for v in verdicts if v.label == "error")
    summary = {
        "dataset": dataset_dir,
        "model": cfg.model.model,
        "total": len(verdicts),
        "risky": n_risky,
        "safe": len(verdicts) - n_risky - n_err,
        "error": n_err,
        "elapsed_s": round(time.time() - t0, 1),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[*] 完成: risky={n_risky} safe={summary['safe']} error={n_err}, 用时 {summary['elapsed_s']}s")
    print(f"[*] 结果: {results_path}")
    return verdicts
