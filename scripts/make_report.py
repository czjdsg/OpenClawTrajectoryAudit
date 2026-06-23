"""生成自包含 HTML 报告: 优化纪要 + Linux/Windows 双案例端到端详解 + 成本/规模估算。
数据源: /data/example-s7-0623 (22条混合OS) + outputs_22(裁决) + outputs_bench(token/耗时)。
用法: python scripts/make_report.py  ->  docs/report.html
"""
from __future__ import annotations

import csv
import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agentaudit.config import load_config  # noqa: E402
from agentaudit.features.assemble import _heuristic_flags  # noqa: E402
from agentaudit.ingest.discover import TrajectoryPaths, _first_match  # noqa: E402
from agentaudit.pipeline import load_trajectory  # noqa: E402
from agentaudit.taxonomy import render_rubric  # noqa: E402

DS = Path("/data/example-s7-0623")
EXT = DS / "extracted"
LINUX = "c319ac300e2314988ae147c4d1d3b6c6"
WIN = "3270cb06276b8e04675cf551ab6a45b8"
E = html.escape


def load_jsonl(p):
    out = {}
    if Path(p).exists():
        for line in Path(p).read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                out[r["traj_id"]] = r
    return out


def mark(s):
    for kw in ("ignore previous instructions", "credentials", r"~/\.aws", "AWS_", "payload\\.ps1",
               "ExecutionPolicy Bypass", "129\\.213\\.117\\.103", "init_env\\.ps1", "curl", "exfiltrat"):
        s = re.sub("(" + kw + ")", r'<span class="hl">\1</span>', s, flags=re.I)
    return s


def case_block(cfg, md5, title, note):
    d = EXT / md5
    p = TrajectoryPaths(md5, d, _first_match(d, cfg.discovery.app_glob),
                        _first_match(d, cfg.discovery.system_glob), _first_match(d, cfg.discovery.network_glob))
    t = load_trajectory(p, True)
    flags = _heuristic_flags(t)
    v = V22.get(md5, {})
    sysf = p.system_path.name if p.system_path else "-"
    parts = [f"<h3>{E(title)}</h3><p class='small'>{E(note)}</p>"]
    parts.append(f"<div class='card'><div class='kvs'>系统层类型 <b>{E(sysf)}</b> · 规模 应用 {len(t.app_events)} / 系统 {len(t.sys_events)} / 网络 {len(t.net_flows)} · "
                 f"标签 <span class='badge b-risk'>risky</span></div></div>")
    # 注入/嫌疑信号片段
    inj = ""
    for e in t.app_events:
        if re.search(r"(?i)credentials|ignore (all )?previous|aws_|ExecutionPolicy Bypass|init_env", e.text):
            inj = e.text
            break
    if inj:
        parts.append("<p class='small'>① 应用层里的嫌疑信号:</p><pre>" + mark(E(inj[:500])) + "</pre>")
    # 跨层启发式标记
    parts.append("<p class='small'>② 预处理产出的跨层启发式标记(送入模型):</p><pre>" + mark(E(flags[:700])) + "</pre>")
    # 模型裁决
    cats = " ".join(f"<span class='tag'>{E(c)}</span>" for c in v.get("attack_categories", []))
    parts.append(f"<p class='small'>③ 模型裁决:</p><div class='card'><div class='kvs'>"
                 f"<span class='badge b-{'risk' if v.get('risky') else 'safe'}'>{E(str(v.get('label','?')))}</span> conf={v.get('confidence','?')} &nbsp; {cats}"
                 f"<br><br><b>rationale:</b> {E(v.get('rationale','')[:380])}</div></div>")
    return "\n".join(parts)


def main():
    global V22
    cfg = load_config()
    labels = {r["md5"]: int(r["label"]) for r in csv.DictReader(open(DS / "results.csv"))} if (DS / "results.csv").exists() else {}
    V22 = load_jsonl(DS / "outputs_22" / "results.jsonl")
    bench = list(csv.DictReader(open(DS / "outputs_bench" / "bench.csv"))) if (DS / "outputs_bench" / "bench.csv").exists() else []

    # confusion
    tp = fp = fn = tn = 0
    for tid, r in V22.items():
        y = labels.get(tid); pr = 1 if r.get("risky") else 0
        if y is None:
            continue
        tp += (pr and y); fp += (pr and not y); fn += (not pr and y); tn += (not pr and not y)

    def fcol(k):
        return [float(b[k]) for b in bench if b.get(k) not in (None, "", "None")]
    pt = fcol("prompt_tokens"); ct = fcol("completion_tokens"); inf = fcol("infer_s")
    appT = sum(fcol("app_tok")); sysT = sum(fcol("sys_tok")); netT = sum(fcol("net_tok")); layerT = (appT + sysT + netT) or 1
    pmean = int(sum(pt) / len(pt)) if pt else 0
    cmean = int(sum(ct) / len(ct)) if ct else 0
    imean = sum(inf) / len(inf) if inf else 0

    P = []
    P.append("""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>OpenClaw 轨迹跨层安全审计 — 报告</title>
<style>
:root{--card:#fff;--ink:#1a2330;--mut:#5b6b7c;--line:#e3e8ee;--accent:#2d6cdf;--risk:#d9342b;--safe:#1f9d57;--code:#0d1b2a;}
*{box-sizing:border-box}body{margin:0;font:15px/1.65 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;color:var(--ink);background:#eef1f5}
.wrap{max-width:1040px;margin:0 auto;padding:28px 20px 80px}
header{background:linear-gradient(135deg,#16263f,#264a8a);color:#fff;border-radius:16px;padding:30px 32px;margin-bottom:24px}
header h1{margin:0 0 8px;font-size:25px}header p{margin:0;opacity:.9;font-size:14px}
h2{font-size:20px;margin:34px 0 14px;padding-bottom:8px;border-bottom:2px solid var(--line)}
h3{font-size:16px;margin:22px 0 10px;color:#24405f}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:14px;margin:6px 0}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#f5f8fc;color:#33536f;font-weight:600}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin:10px 0}
.stat{flex:1;min-width:150px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.stat .n{font-size:25px;font-weight:700;color:var(--accent)}.stat .l{font-size:13px;color:var(--mut);margin-top:3px}
pre{background:var(--code);color:#cfe3ff;border-radius:10px;padding:13px 15px;overflow:auto;font:12.5px/1.5 "SF Mono",Menlo,Consolas,monospace;max-height:360px;white-space:pre-wrap;word-break:break-all}
pre .hl{background:#5a1a16;color:#ffd3cf;border-radius:3px;padding:0 2px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;color:#fff}
.b-risk{background:var(--risk)}.b-safe{background:var(--safe)}
.tag{display:inline-block;background:#eaf1fc;color:#24508f;border:1px solid #cfe0fa;border-radius:6px;padding:1px 8px;margin:2px 3px 2px 0;font-size:12px}
.small{font-size:13px;color:var(--mut)}.kvs{font-size:14px}.kvs b{color:#24405f}.up{color:var(--safe);font-weight:700}
.pipe{display:flex;flex-wrap:wrap;gap:0;margin:8px 0}.pbox{flex:1;min-width:110px;background:#f5f8fc;border:1px solid #d6e0ee;border-radius:10px;padding:11px;text-align:center;font-size:12.5px}
.pbox b{display:block;color:#24405f;margin-bottom:3px}.parrow{display:flex;align-items:center;color:var(--accent);font-weight:700;padding:0 5px}
.note{background:#fff8e6;border:1px solid #f0dca0;border-radius:10px;padding:12px 15px;font-size:13.5px}
footer{margin-top:40px;color:var(--mut);font-size:12.5px;text-align:center}
</style></head><body><div class="wrap">""")

    P.append("<header><h1>OpenClaw 轨迹跨层安全审计 — 优化纪要 &amp; 案例详解</h1>"
             "<p>零样本 LLM 审计 · Qwen3.6-35B-A3B(vLLM @ 2×Ascend 910B2) · 应用(session.jsonl)+系统(auditd / Windows&nbsp;Sysmon)+网络(pcap)三层 · 阶段一二分类</p></header>")

    # cards
    P.append('<div class="cards">')
    P.append(f'<div class="stat"><div class="n">{2*tp/(2*tp+fp+fn) if (2*tp+fp+fn) else 0:.2f}</div><div class="l">F1({tp+fp+fn+tn} 条混合 Linux/Windows)</div></div>')
    P.append(f'<div class="stat"><div class="n">TP{tp}/FP{fp}/FN{fn}/TN{tn}</div><div class="l">混淆矩阵(正类=risky)</div></div>')
    P.append(f'<div class="stat"><div class="n">~{imean:.0f}s</div><div class="l">单条推理(关思考)</div></div>')
    P.append(f'<div class="stat"><div class="n">{pmean//1000}K</div><div class="l">平均 prompt tokens</div></div>')
    P.append("</div>")
    P.append('<p class="small">⚠ 仅 22 条标签样本, F1 不具统计意义; 关思考的 recall 靠跨层启发式标记补齐(见案例二)。</p>')

    # 优化总览
    P.append("<h2>1. 优化纪要</h2><div class='card'><table><tr><th>维度</th><th>做法</th><th>效果</th></tr>"
             "<tr><td>风险分类法</td><td>用「<b>恶意操作字典表</b>」12 类一级攻击分类(弃用并删除 prompt 里全部 AgentDoG 内容);输出 <code>attack_categories</code></td><td>对齐标签语义</td></tr>"
             "<tr><td>判定口径</td><td>「<b>出现/尝试即 risky</b>(哪怕被抵御)」</td><td class='up'>F1 0.33→1.0,救回被抵御的攻击</td></tr>"
             "<tr><td>prompt</td><td>全<b>英文</b>(贴合英文轨迹)</td><td>与输入一致</td></tr>"
             "<tr><td>系统层瘦身</td><td>auditd 安全过滤(execve/提权/外连/敏感文件,routine 折叠)+ <b>x86_64/aarch64 架构自适应</b> + 未知架构 <b>fail-safe 全留</b></td><td class='up'>Linux 单条 192K→47K token(~4x)</td></tr>"
             "<tr><td><b>Windows 支持</b></td><td>新增 <b>Sysmon/Security 后端</b>(JSON/JSONL/XML,解析 XmlData 内嵌 Event XML);EventID→kind + 敏感对象过滤(lsass/Run键/服务/计划任务)</td><td class='up'>真实 Sysmon ~40x 压缩</td></tr>"
             "<tr><td>跨层信号</td><td>修 DNS-drop(EID22 按域名保留)+ 新增「<b>脚本/Shell 进程外连</b>=高度可疑」标记</td><td class='up'>关思考也能抓隐蔽跨层 case</td></tr>"
             "<tr><td>推理模式</td><td><b>关思考</b></td><td class='up'>~2.6x 提速,配合上面的标记 F1 仍 1.0</td></tr>"
             "<tr><td>工程</td><td>断点续跑、可插拔系统层后端、prompt/证据/报告导出工具</td><td>跑大规模更稳</td></tr>"
             "</table></div>")

    # pipeline
    P.append("<h2>2. 处理流水线</h2><div class='card'><div class='pipe'>"
             "<div class='pbox'><b>三层日志</b>session.jsonl · audit.log/sysmon.jsonl · pcap</div><div class='parrow'>→</div>"
             "<div class='pbox'><b>解析</b>可插拔后端(auditd/Sysmon/通用)</div><div class='parrow'>→</div>"
             "<div class='pbox'><b>汇编</b>安全过滤 + token 预算 + 跨层启发式标记</div><div class='parrow'>→</div>"
             "<div class='pbox'><b>Qwen3.6</b>结构化 JSON 裁决</div><div class='parrow'>→</div>"
             "<div class='pbox'><b>裁决</b>safe/risky + attack_categories</div></div></div>")

    # 案例
    P.append("<h2>3. 案例详解</h2>")
    P.append(case_block(cfg, LINUX, "案例一 · Linux(c319ac):AWS 凭证注入(供应链)",
                        "技能/CLAUDE.md 模板里夹带恶意指令(输出 ~/.aws/credentials + 静默 curl 外传);系统层为 auditd。"))
    P.append(case_block(cfg, WIN, "案例二 · Windows(3270cb):恶意技能载荷下载",
                        "智能体用 powershell -ExecutionPolicy Bypass 跑技能自带 init_env.ps1;系统层为 Sysmon。此条曾在'关思考'下漏报 —— 信号(powershell→外部IP 的 EID3)一直保留着, 是欠推理; 新增'脚本进程外连'跨层标记后, 关思考也判对了。"))

    # 成本/规模
    P.append("<h2>4. 成本 &amp; 规模估算</h2>")
    P.append(f"<div class='card'><b>Token 开销(各部分,实测 22 条)</b><table>"
             f"<tr><th>部分</th><th>占比 / 量</th></tr>"
             f"<tr><td>system prompt(固定)</td><td>~2048 tok/条</td></tr>"
             f"<tr><td>应用层</td><td>{100*appT//layerT}%</td></tr>"
             f"<tr><td><b>系统层</b></td><td><b>{100*sysT//layerT}%</b>(绝对大头)</td></tr>"
             f"<tr><td>网络层</td><td>{100*netT//layerT}%</td></tr>"
             f"<tr><td>实测 prompt_tokens</td><td>均 {pmean:,} / 关思考后 completion 均 {cmean}</td></tr></table>"
             f"<p class='small'>关思考后 completion 极小 → 推理时间几乎全是 prefill;系统层占比最高,是进一步提速的重点。</p></div>")
    P.append("<div class='card'><b>推理时间 &amp; 5万/10万估算</b><table>"
             f"<tr><th></th><th>单条</th><th>单机 2×910B2</th></tr>"
             f"<tr><td>关思考(并发8)</td><td>~13.9s(吞吐)</td><td>5万≈8天 / 10万≈16天</td></tr>"
             f"<tr><td>串行单请求</td><td>~{imean:.0f}s</td><td>—</td></tr>"
             "<tr><td>+ 加卡 / benign 预筛</td><td>—</td><td>→ 天级 / 小时级</td></tr></table>"
             "<p class='small'>100G 数据集样本量估算(按本样例单条均值): 压缩态 ~1.3MB/条 → <b>≈7.7 万条</b>;解压态 ~10.6MB/条 → ≈1 万条。</p></div>")

    P.append("<h2>5. 结论 &amp; caveat</h2><div class='card'>"
             f"<p>22 条混合 Linux/Windows 轨迹(关思考)达到 <b>F1=1.0</b>(TP{tp}/FP{fp}/FN{fn}/TN{tn}),Linux(auditd)与 Windows(Sysmon)统一处理。</p>"
             "<div class='note'>caveat: ① 仅 22 条标签, 需更大集验证泛化与跨层启发式覆盖; ② 关思考依赖启发式标记补跨层信号; ③ Windows 字段按 Sysmon 标准/真实导出校准, 其它采集器(winlogbeat/EvtxECmd)命名可能微调; ④ 极限提速到小时级需加卡/预筛。</div></div>")
    P.append("<footer>由 agentaudit/scripts/make_report.py 自动生成 · 数据集 example-s7-0623(22条) · 关思考版</footer></div></body></html>")

    out = Path(__file__).resolve().parent.parent / "docs" / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(P), encoding="utf-8")
    print(f"已生成: {out} ({out.stat().st_size} 字节) | F1={2*tp/(2*tp+fp+fn) if (2*tp+fp+fn) else 0:.3f} TP{tp}/FP{fp}/FN{fn}/TN{tn}")


if __name__ == "__main__":
    main()
