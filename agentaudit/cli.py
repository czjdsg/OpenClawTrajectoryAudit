"""命令行入口.

  python -m agentaudit health
  python -m agentaudit selftest
  python -m agentaudit inspect <轨迹目录> [--no-model]
  python -m agentaudit audit <数据集目录> [--out DIR]
  python -m agentaudit eval <results.jsonl> <labels.(jsonl|csv)>
  python -m agentaudit export <results.jsonl> <submission.csv>   # 导出 md5,label 提交格式
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_config
from .eval import evaluate, export_submission, print_report
from .features.assemble import assemble_evidence
from .ingest.discover import TrajectoryPaths, _first_match
from .llm.classify import classify
from .llm.client import ChatClient
from .pipeline import load_trajectory
from .runner import run_dataset


def cmd_health(args):
    cfg = load_config(args.config)
    ok = ChatClient.from_cfg(cfg).health()
    print(f"{cfg.model.base_url}  model={cfg.model.model}  -> {'OK' if ok else '不可达'}")


def cmd_inspect(args):
    cfg = load_config(args.config)
    d = Path(args.traj)
    paths = TrajectoryPaths(
        traj_id=d.name, root=d,
        app_path=_first_match(d, cfg.discovery.app_glob),
        system_path=_first_match(d, cfg.discovery.system_glob),
        network_path=_first_match(d, cfg.discovery.network_glob),
    )
    print(f"[*] 轨迹 {paths.traj_id}, 层: {paths.available()}")
    traj = load_trajectory(paths, cfg.audit.syscall_filter == "security")
    evidence = assemble_evidence(traj, cfg)
    print("\n========== 汇编后的审计证据 (送入模型的内容) ==========\n")
    print(evidence)
    if not args.no_model:
        print("\n========== 模型裁决 ==========\n")
        v = classify(traj, cfg)
        print(json.dumps(v.to_row(), ensure_ascii=False, indent=2))


def cmd_audit(args):
    cfg = load_config(args.config)
    if args.out:
        cfg.run.output_dir = args.out
    run_dataset(args.dataset, cfg)


def cmd_eval(args):
    print_report(evaluate(args.results, args.labels))


def cmd_export(args):
    info = export_submission(args.results, args.out)
    note = f"  ⚠ 含 {info['errors']} 条 error(按0占位, 建议先重跑消除)" if info["errors"] else ""
    print(f"已导出 {info['n']} 行 (md5,label) -> {info['out']}{note}")


def cmd_selftest(args):
    from . import sample as sample_mod

    cfg = load_config(args.config)
    examples = Path(__file__).resolve().parent.parent / "examples" / "synthetic"
    ds = sample_mod.make_samples(examples)
    cfg.run.output_dir = str(examples / "outputs")
    print(f"[*] 合成样例: {ds}")
    run_dataset(ds, cfg)
    results = Path(cfg.run.output_dir) / "results.jsonl"
    labels = Path(ds) / "labels.jsonl"
    if results.exists() and labels.exists():
        print()
        print_report(evaluate(str(results), str(labels)))


def main():
    ap = argparse.ArgumentParser(prog="agentaudit", description="OpenClaw 轨迹跨层安全审计 (Qwen3.6)")
    ap.add_argument("--config", default=None, help="config.yaml 路径")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health", help="检查模型服务连通性").set_defaults(func=cmd_health)
    sub.add_parser("selftest", help="合成样例端到端自测 + 评估").set_defaults(func=cmd_selftest)

    p = sub.add_parser("inspect", help="解析+汇编单条轨迹证据(可不调模型)")
    p.add_argument("traj", help="单条轨迹目录")
    p.add_argument("--no-model", action="store_true", help="只看汇编证据, 不调用模型")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("audit", help="批量审计数据集")
    p.add_argument("dataset", help="数据集目录")
    p.add_argument("--out", default=None, help="输出目录 (覆盖 config)")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("eval", help="对照标签算指标")
    p.add_argument("results", help="results.jsonl")
    p.add_argument("labels", help="labels.jsonl 或 .csv")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("export", help="导出 md5,label 提交格式 CSV")
    p.add_argument("results", help="results.jsonl")
    p.add_argument("out", nargs="?", default="submission.csv", help="输出 CSV (默认 submission.csv)")
    p.set_defaults(func=cmd_export)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
