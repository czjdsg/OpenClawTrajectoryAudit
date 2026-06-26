#!/bin/bash
# 看审计进度/结果概况。用法: bash scripts/status.sh [输出目录] [解压目录(可选,用于算总数)]
OUT="${1:-/data/fulldata/outputs}"
EXT="${2:-}"
RES="$OUT/results.jsonl"

echo "=== vLLM ==="
if curl -s --noproxy '*' --max-time 8 http://localhost:8000/v1/models >/dev/null 2>&1; then
  echo "  ✅ OK (localhost:8000)"
else
  echo "  ✗ 不可达 -> bash /data/serve_qwen36.sh"
fi

echo "=== 审计进程 (tmux) ==="
tmux has-session -t audit 2>/dev/null && echo "  ✅ 'audit' 会话在跑" || echo "  ⚠ 'audit' 会话不在(已完成 或 中断->重跑 run_audit.sh 续跑)"

echo "=== NPU ==="
npu-smi info 2>/dev/null | grep 910B2 | awk '{print "  Chip "$2" 功耗 "$5"W (>120≈在推理)"}' 2>/dev/null

echo "=== 进度 / 结果 ==="
python3 - "$RES" "$EXT" <<'PY'
import json, os, sys, glob
res, ext = sys.argv[1], sys.argv[2]
rows = []
if os.path.exists(res):
    for line in open(res):
        line = line.strip()
        if line:
            try: rows.append(json.loads(line))
            except Exception: pass
total = len(glob.glob(os.path.join(ext, "*/"))) if ext else None
risky = sum(1 for r in rows if r.get("risky"))
err = sum(1 for r in rows if r.get("label") == "error")
done = len(rows)
print(f"  已完成 {done}{'/'+str(total) if total else ''} 条 | risky {risky} | safe {done-risky-err} | error {err}")
if err:
    print("  ⚠ error 轨迹(重跑 run_audit.sh 会自动重试):")
    for r in rows:
        if r.get("label") == "error":
            print("     ", r["traj_id"][:14], (r.get("error","") or "")[:80])
print("  最近 5 条:")
for r in rows[-5:]:
    print(f"     {r['traj_id'][:14]} {r.get('label','?'):6} conf={r.get('confidence','?')} {r.get('attack_categories',[])[:2]}")
PY

echo "=== summary.json ==="
cat "$OUT/summary.json" 2>/dev/null | tr -d '\n'; echo
