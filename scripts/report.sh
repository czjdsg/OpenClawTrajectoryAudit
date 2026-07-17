#!/bin/bash
# 全量跑完后的质检报告: 类别分布 / 置信度分布 / 救回的超长批次 / 疑似漏报抽查。
# 用法: bash scripts/report.sh [results.jsonl]
RES="${1:-/data/fulldata/outputs/results.jsonl}"
python3 - "$RES" <<'PY'
import json, sys, collections
res = sys.argv[1]
rows = []
for line in open(res, encoding="utf-8"):
    line = line.strip()
    if line:
        try: rows.append(json.loads(line))
        except Exception: pass

# 去重: 每个 traj_id 取最后一条非 error (同 _summarize 口径)
latest = {}
had_error = set()
for r in rows:
    t = r.get("traj_id")
    if r.get("label") == "error":
        had_error.add(t)
    if t not in latest or r.get("label") != "error":
        latest[t] = r
V = list(latest.values())
risky = [r for r in V if r.get("risky")]
safe  = [r for r in V if r.get("label") == "safe"]
err   = [r for r in V if r.get("label") == "error"]

print(f"=== 总览 ===  total {len(V)} | risky {len(risky)} | safe {len(safe)} | error {len(err)}")

print("\n=== risky 的 12 类命中分布 (一条可命中多类) ===")
cat = collections.Counter(c for r in risky for c in (r.get("attack_categories") or []))
for c, n in cat.most_common():
    print(f"  {n:5d}  {c}")
none_cat = sum(1 for r in risky if not (r.get("attack_categories") or []))
if none_cat: print(f"  {none_cat:5d}  <判 risky 但没标类别 — 值得看 rationale>")

print("\n=== risky 置信度分布 ===")
b = collections.Counter()
for r in risky:
    c = r.get("confidence") or 0
    b[">=0.9" if c>=0.9 else "0.7-0.9" if c>=0.7 else "0.5-0.7" if c>=0.5 else "<0.5"] += 1
for k in [">=0.9","0.7-0.9","0.5-0.7","<0.5"]:
    print(f"  {k:8s} {b[k]}")

print("\n=== 救回的超长批次 (曾 error, 最终成功) ===")
saved = [r for r in V if r.get("traj_id") in had_error and r.get("label") != "error"]
sr = sum(1 for r in saved if r.get("risky"))
print(f"  共 {len(saved)} 条: risky {sr} / safe {len(saved)-sr}")
for r in saved[:25]:
    print(f"    {r['traj_id'][:14]} {r.get('label','?'):5} conf={r.get('confidence','?')} {(r.get('attack_categories') or [])[:2]} | {(r.get('rationale') or '')[:60]}")

print("\n=== 抽查: 低置信 risky (最可能误报) ===")
low = sorted(risky, key=lambda r: r.get("confidence") or 0)[:10]
for r in low:
    print(f"    {r['traj_id'][:14]} conf={r.get('confidence','?')} {(r.get('attack_categories') or [])[:2]} | {(r.get('rationale') or '')[:70]}")

print("\n=== 抽查: rationale 提到网络/命令/权限却判 safe (可能漏报) ===")
import re
kw = re.compile(r"(curl|wget|外连|外联|下载|反弹|reverse|base64|chmod|sudo|powershell|encoded|c2|exfil|外发)", re.I)
susp = [r for r in safe if kw.search((r.get("rationale") or ""))][:10]
for r in susp:
    print(f"    {r['traj_id'][:14]} conf={r.get('confidence','?')} | {(r.get('rationale') or '')[:80]}")
if not susp: print("    (无命中，说明 safe 的判词里没有明显危险信号)")
PY
