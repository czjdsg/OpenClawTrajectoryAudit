"""批量审计: 发现轨迹, 并发跑分类, 落盘 results.jsonl + summary。支持断点续跑(被中断后重启会跳过已完成)。"""
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


def _read_rows(path: Path) -> list[dict]:
    rows: list[dict] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def run_dataset(dataset_dir: str, cfg: Config) -> list[AuditVerdict]:
    trajs = discover(dataset_dir, cfg.discovery)
    if not trajs:
        print(f"[!] 在 {dataset_dir} 未发现轨迹 (检查 config.discovery 的 glob)")
        return []

    out_dir = Path(cfg.run.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"
    client = ChatClient.from_cfg(cfg)

    # 断点续跑: 跳过已成功 (非 error) 的轨迹
    done = {r.get("traj_id") for r in _read_rows(results_path) if r.get("label") != "error"}
    pending = [tp for tp in trajs if tp.traj_id not in done]

    print(f"[*] 发现 {len(trajs)} 条, 已完成 {len(done)} (跳过), 待跑 {len(pending)}; 并发 {cfg.run.concurrency}, 模型 {cfg.model.model}")
    if pending and not client.health():
        print(f"[!] 警告: {cfg.model.base_url} /models 不可达, 请确认 vLLM 在跑")

    t0 = time.time()
    if pending:
        with ThreadPoolExecutor(max_workers=cfg.run.concurrency) as ex, results_path.open("a", encoding="utf-8") as fout:
            futs = {ex.submit(audit_one, tp, cfg, client): tp for tp in pending}
            for n, fut in enumerate(as_completed(futs), 1):
                tp = futs[fut]
                try:
                    v = fut.result()
                except Exception as e:  # noqa: BLE001
                    v = AuditVerdict(traj_id=tp.traj_id, label="error", error=str(e))
                fout.write(json.dumps(v.to_row(), ensure_ascii=False) + "\n")
                fout.flush()
                mark = {"risky": "🔴", "safe": "🟢", "error": "⚠️"}.get(v.label, "?")
                print(f"  [{n}/{len(pending)}] {mark} {v.traj_id[:12]} conf={v.confidence:.2f} cats={v.attack_categories} {v.rationale[:40]}")

    # 汇总: 读全量文件, 每个 traj 取最后一条非 error
    latest: dict[str, dict] = {}
    for r in _read_rows(results_path):
        tid = r.get("traj_id")
        if tid not in latest or r.get("label") != "error":
            latest[tid] = r
    verdicts = [AuditVerdict(**{k: val for k, val in r.items() if k in AuditVerdict.model_fields}) for r in latest.values()]
    n_risky = sum(1 for v in verdicts if v.risky)
    n_err = sum(1 for v in verdicts if v.label == "error")
    summary = {
        "dataset": dataset_dir, "model": cfg.model.model,
        "total": len(verdicts), "risky": n_risky,
        "safe": len(verdicts) - n_risky - n_err, "error": n_err,
        "elapsed_s": round(time.time() - t0, 1),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    # 提交格式 md5,label
    try:
        from .eval import export_submission
        sub = export_submission(str(results_path), str(out_dir / "submission.csv"))
        sub_note = f"{sub['n']} 行" + (f", ⚠{sub['errors']} 条 error 按0占位(建议重跑消除)" if sub["errors"] else "")
    except Exception as e:  # noqa: BLE001
        sub_note = f"导出失败: {e}"
    print(f"[*] 汇总: total={summary['total']} risky={n_risky} safe={summary['safe']} error={n_err}, 本轮用时 {summary['elapsed_s']}s")
    print(f"[*] 结果: {results_path}")
    print(f"[*] 提交文件(md5,label): {out_dir / 'submission.csv'} ({sub_note})")
    return verdicts
