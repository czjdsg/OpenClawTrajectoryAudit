#!/usr/bin/env bash
# ============================================================================
# 规则兜底收尾: 时间不够、模型审计跑不完时用。
#   1) 中断正在跑的模型审计 (tmux 会话 audit)  —— 已判好的逐条已落盘, 一条不丢
#   2) 剩余 + error 的轨迹用"规则判定"补齐 (不调模型, 秒级)
#   3) 一并写回同一 results.jsonl, 重新生成 submission.csv / summary.json
#
# 用法: bash finish_with_rules.sh <extracted目录> <outputs目录>
#   例: bash scripts/finish_with_rules.sh /data/fulldata/extracted /data/fulldata/outputs
#
# 规则判定特性(22样例实测): 召回=1.0(0漏报), 精确≈0.5, F1≈0.67 —— 召回优先, 尾部不漏攻击。
# ============================================================================
set -euo pipefail

DATASET="${1:?用法: finish_with_rules.sh <extracted目录> <outputs目录>}"
OUTDIR="${2:?用法: finish_with_rules.sh <extracted目录> <outputs目录>}"
CODE=/data/agent-audit
SESSION="${AUDIT_TMUX:-audit}"   # 模型审计所在 tmux 会话名(run_audit.sh 默认用 audit)

# 1. 中断模型审计(若在跑). results.jsonl 是逐条 flush 的, 中断只丢飞行中的≤并发数条, 它们会被规则补判。
if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "[*] 中断模型审计 tmux 会话 '$SESSION' ..."
  tmux kill-session -t "$SESSION"
  sleep 2
else
  echo "[*] 未发现运行中的 '$SESSION' 会话(可能已自然结束/未启动), 直接进入规则兜底"
fi

done_n=$(grep -c . "$OUTDIR/results.jsonl" 2>/dev/null || echo 0)
total_n=$(ls -d "$DATASET"/*/ 2>/dev/null | wc -l)
echo "[*] 模型侧已落盘约 $done_n 行 / 共 $total_n 条; 剩余用规则兜底补齐"

# 2+3. 规则补齐(断网可用, 不走代理/不调模型)
cd "$CODE"
PYTHONPATH="$CODE" python3 -m agentaudit rulefill "$DATASET" --out "$OUTDIR"

echo "[*] 完成。提交文件: $OUTDIR/submission.csv ; 汇总: $OUTDIR/summary.json (含 by_method: 模型/规则 各多少条)"
