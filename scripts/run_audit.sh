#!/bin/bash
# 启动全量审计(检查 vLLM -> 挂 tmux 跑, 支持断点续跑)。
# 用法: bash scripts/run_audit.sh <解压目录> [输出目录]
set -e
EXT="${1:?用法: run_audit.sh <解压目录> [输出目录]}"
OUT="${2:-/data/fulldata/outputs}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$OUT"

# 1. 检查 vLLM (--noproxy 防止断网下走死代理)
if ! curl -s --noproxy '*' --max-time 8 http://localhost:8000/v1/models >/dev/null 2>&1; then
  echo "[!] vLLM 未就绪 (localhost:8000)。先启动:"
  echo "      bash /data/serve_qwen36.sh   # 等到日志出现 'Application startup complete'(约4分钟)"
  exit 1
fi
echo "[*] vLLM OK。"

# 2. tmux 里启动(断点续跑: 重复本命令会自动跳过已完成)
total=$(find "$EXT" -maxdepth 1 -mindepth 1 -type d | wc -l)
done=$(grep -c . "$OUT/results.jsonl" 2>/dev/null || echo 0)
echo "[*] 数据 $total 条, 已完成 $done 条, 启动续跑 (tmux 会话 'audit')..."
tmux kill-session -t audit 2>/dev/null || true
# python -u(关缓冲)+ tee: 输出同时进 tmux 窗口(attach 可见实时) 和 run.log(持久化)
tmux new-session -d -s audit "cd '$HERE' && PYTHONPATH='$HERE' python3 -u -m agentaudit audit '$EXT' --out '$OUT' 2>&1 | tee '$OUT/run.log'"
sleep 2
if tmux has-session -t audit 2>/dev/null; then
  echo "[*] 已启动。看进度:  bash scripts/status.sh $OUT"
  echo "[*] 进 tmux 看实时:  tmux attach -t audit   (Ctrl-b 然后 d 退出但不杀)"
else
  echo "[!] 启动失败, 看 $OUT/run.log"
fi
