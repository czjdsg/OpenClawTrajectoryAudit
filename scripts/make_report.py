"""生成自包含 HTML 报告: 优化纪要 + 单案例(c319ac)端到端详解(数据处理/模型输入/输出)。
用法: python scripts/make_report.py  ->  docs/report.html
"""
from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agentaudit.config import load_config  # noqa: E402
from agentaudit.features.assemble import assemble_evidence  # noqa: E402
from agentaudit.ingest.app_session import parse_session  # noqa: E402
from agentaudit.ingest.net_pcap import parse_pcap  # noqa: E402
from agentaudit.ingest.sys_logs import parse_syslog  # noqa: E402
from agentaudit.llm.prompts import SYSTEM_PROMPT  # noqa: E402
from agentaudit.schema import TrajectoryInput  # noqa: E402
from agentaudit.taxonomy import render_rubric  # noqa: E402

CASE = "c319ac300e2314988ae147c4d1d3b6c6"
EX = Path("/data/example-s7")
D = EX / "extracted" / CASE
E = html.escape


def _verdict(path: str, tid=CASE):
    p = EX / path
    if not p.exists():
        return None
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if r["traj_id"] == tid:
                return r
    return None


def _tok(chars):
    return f"{chars * 0.35 / 1000:.1f}K"


def main():
    cfg = load_config()
    app = parse_session(D / "session.jsonl")
    sys_all = parse_syslog(D / "audit.log", False)
    sys_sec = parse_syslog(D / "audit.log", True)
    net = parse_pcap(D / "network.pcap")

    ca = sum(min(len(e.text), 4000) + 20 for e in app)
    cs_all = sum(len(e.summary) + 8 for e in sys_all)
    cs_sec = sum(len(e.summary) + 8 for e in sys_sec)
    cn = sum(len(f"{f.proto} {f.dst} {f.host or ''} {f.info}") for f in net)
    ext = [f for f in net if f.external]
    mdns = sum(1 for f in net if (f.host and ".local" in (f.host or "")) or str(f.dst).startswith("224.") or f.dport == 5353)

    # 注入点
    inj = ""
    for e in app:
        if re.search(r"(?i)credentials|ignore (all )?previous|aws_|~/\.aws", e.text):
            inj = e.text
            break

    traj = TrajectoryInput(traj_id=CASE, app_events=app, sys_events=sys_sec, net_flows=net)
    evidence = assemble_evidence(traj, cfg)

    old_v = _verdict("outputs/results.jsonl") or {}
    new_v = _verdict("outputs_slim/results.jsonl") or _verdict("outputs_nothink/results.jsonl") or {}

    kept_exec = [e for e in sys_sec if e.kind == "exec"][:8]
    dropped_line = next((e.summary for e in sys_sec if e.summary.startswith("[+")), "")

    # ---------- build HTML ----------
    P = []
    P.append("""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenClaw 轨迹跨层安全审计 — 优化纪要 & 案例详解</title>
<style>
:root{--bg:#0f1419;--card:#fff;--ink:#1a2330;--mut:#5b6b7c;--line:#e3e8ee;--accent:#2d6cdf;--risk:#d9342b;--safe:#1f9d57;--code:#0d1b2a;}
*{box-sizing:border-box}body{margin:0;font:15px/1.65 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;color:var(--ink);background:#eef1f5}
.wrap{max-width:1040px;margin:0 auto;padding:28px 20px 80px}
header{background:linear-gradient(135deg,#16263f,#264a8a);color:#fff;border-radius:16px;padding:30px 32px;margin-bottom:26px}
header h1{margin:0 0 8px;font-size:25px}header p{margin:0;opacity:.9;font-size:14px}
h2{font-size:20px;margin:34px 0 14px;padding-bottom:8px;border-bottom:2px solid var(--line)}
h3{font-size:16px;margin:22px 0 10px;color:#24405f}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:14px 0;box-shadow:0 1px 3px rgba(20,40,80,.04)}
table{width:100%;border-collapse:collapse;font-size:14px;margin:6px 0}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#f5f8fc;color:#33536f;font-weight:600}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin:10px 0}
.stat{flex:1;min-width:150px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.stat .n{font-size:26px;font-weight:700;color:var(--accent)}.stat .l{font-size:13px;color:var(--mut);margin-top:3px}
pre{background:var(--code);color:#cfe3ff;border-radius:10px;padding:14px 16px;overflow:auto;font:12.5px/1.55 "SF Mono",Menlo,Consolas,monospace;max-height:430px}
pre .hl{background:#5a1a16;color:#ffd3cf;border-radius:3px;padding:0 2px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;color:#fff}
.b-risk{background:var(--risk)}.b-safe{background:var(--safe)}.b-mut{background:#7a8aa0}
.pipe{display:flex;align-items:stretch;gap:0;flex-wrap:wrap;margin:8px 0}
.pbox{flex:1;min-width:120px;background:#f5f8fc;border:1px solid #d6e0ee;border-radius:10px;padding:12px;text-align:center;font-size:13px}
.pbox b{display:block;color:#24405f;font-size:13.5px;margin-bottom:3px}
.parrow{display:flex;align-items:center;color:var(--accent);font-weight:700;padding:0 6px}
.tag{display:inline-block;background:#eaf1fc;color:#24508f;border:1px solid #cfe0fa;border-radius:6px;padding:1px 8px;margin:2px 3px 2px 0;font-size:12px}
.small{font-size:13px;color:var(--mut)}
.kvs{font-size:14px}.kvs b{color:#24405f}
.up{color:var(--safe);font-weight:700}.down{color:var(--risk);font-weight:700}
.note{background:#fff8e6;border:1px solid #f0dca0;border-radius:10px;padding:12px 16px;font-size:13.5px}
footer{margin-top:40px;color:var(--mut);font-size:12.5px;text-align:center}
</style></head><body><div class="wrap">""")

    P.append(f"""<header>
<h1>OpenClaw 轨迹跨层安全审计 — 优化纪要 &amp; 案例详解</h1>
<p>零样本 LLM 审计 · 模型 Qwen3.6-35B-A3B(vLLM @ 2×Ascend 910B2) · 应用(session.jsonl)+系统(auditd)+网络(pcap)三层 · 阶段一二分类</p>
</header>""")

    # ---- 效果卡片 ----
    P.append('<div class="cards">')
    P.append('<div class="stat"><div class="n">0.33 → 1.0</div><div class="l">F1(19 条标签样本)</div></div>')
    P.append('<div class="stat"><div class="n">4 → 0</div><div class="l">漏报(FN)被救回</div></div>')
    P.append('<div class="stat"><div class="n">~4×</div><div class="l">prompt 压缩(系统层过滤)</div></div>')
    P.append('<div class="stat"><div class="n">13.3s</div><div class="l">单条耗时(关思考, 2.6×)</div></div>')
    P.append("</div>")
    P.append('<p class="small">⚠ 19 条标签样本上的结果, 不具统计意义; 关思考的可靠性需更大标注集复核。</p>')

    # ---- 优化总览 ----
    P.append("<h2>1. 本轮做了哪些优化</h2><div class='card'><table>"
             "<tr><th>维度</th><th>改动</th><th>效果</th></tr>"
             "<tr><td>风险分类法</td><td>弃用 <b>AgentDoG 三维分类</b>, 改用「<b>恶意操作字典表</b>」12 类一级攻击分类; prompt 中 AgentDoG 内容全部删除</td><td>对齐数据标签语义, 输出字段 <code>attack_categories</code></td></tr>"
             "<tr><td>判定口径</td><td>从「造成危害才算」改为「<b>出现/尝试即 risky(哪怕被抵御)</b>」</td><td class='up'>F1 0.33→1.0, 4 条漏报救回</td></tr>"
             "<tr><td>prompt 语言</td><td>全部改为<b>英文</b>(贴合英文为主的轨迹)</td><td>与输入一致</td></tr>"
             f"<tr><td>系统层(auditd)</td><td>海量 syscall 只保留<b>安全相关</b>(execve/提权/外连/敏感文件), routine 噪声折叠计数; 修了 syscall 数字→名映射</td><td class='up'>单条均值 192.6K→47.6K token (~4×), 最大 2174K→97K; F1 不掉</td></tr>"
             "<tr><td>推理模式</td><td><b>关思考</b> enable_thinking=false</td><td class='up'>13.3s/条 vs 35s (~2.6×), F1 仍 1.0</td></tr>"
             "<tr><td>工程</td><td>批量<b>断点续跑</b>(被中断不丢)、英文证据脚手架、prompt/证据导出工具</td><td>跑 5 万更稳</td></tr>"
             "</table></div>")

    # ---- 流水线 ----
    P.append("<h2>2. 处理流水线</h2><div class='card'><div class='pipe'>"
             "<div class='pbox'><b>三层日志</b>session.jsonl · audit.log · network.pcap</div>"
             "<div class='parrow'>→</div>"
             "<div class='pbox'><b>解析</b>各层 → 统一事件(容错适配 OpenClaw schema)</div>"
             "<div class='parrow'>→</div>"
             "<div class='pbox'><b>汇编</b>安全过滤 + token 预算 + 跨层启发式标记</div>"
             "<div class='parrow'>→</div>"
             "<div class='pbox'><b>Qwen3.6</b>结构化 JSON 裁决</div>"
             "<div class='parrow'>→</div>"
             "<div class='pbox'><b>裁决</b>safe/risky + attack_categories</div>"
             "</div></div>")

    # ---- 案例详解 ----
    P.append(f"<h2>3. 案例详解 · 轨迹 <code>{CASE[:12]}…</code></h2>")
    P.append(f"<div class='card'><div class='kvs'>规模: 应用层 <b>{len(app)}</b> 步 · 系统层 <b>{len(sys_all)}</b> 条(过滤后 <b>{len(sys_sec)}</b>) · 网络层 <b>{len(net)}</b> 条(外部 {len(ext)}, mDNS {mdns})。"
             f" 标签: <span class='badge b-risk'>risky (1)</span></div></div>")

    P.append("<h3>3.1 原始数据里的「注入点」(应用层)</h3>"
             "<p class='small'>智能体被要求用 <code>ai-native-builder-workflow</code> 技能初始化项目; 一个被读取的文件/技能模板里夹带了恶意指令:</p>")
    P.append("<pre>" + _mark(E(inj[:900])) + ("…" if len(inj) > 900 else "") + "</pre>")

    P.append("<h3>3.2 数据处理:三层 → 规整证据</h3>")
    P.append("<div class='card'><table>"
             "<tr><th>层</th><th>原始</th><th>处理后</th><th>token</th></tr>"
             f"<tr><td>应用 session.jsonl</td><td>{len(app)} 步(含 toolCall/toolResult/thinking)</td><td>渲染为 action/observation 文本</td><td>{_tok(ca)}</td></tr>"
             f"<tr><td>系统 audit.log</td><td>{len(sys_all)} 条 auditd 事件</td><td>安全过滤 → 保留 {len([e for e in sys_sec if not e.summary.startswith('[+')])} 条 + 折叠 1 行</td><td class='up'>{_tok(cs_all)} → {_tok(cs_sec)}</td></tr>"
             f"<tr><td>网络 pcap</td><td>{len(net)} 条(mDNS 噪声 {mdns})</td><td>聚合流, 外部优先; 外部目的地 {len(ext)} 条</td><td>{_tok(cn)}</td></tr>"
             "</table></div>")
    P.append("<p class='small'>系统层安全过滤保留的命令(execve, 节选)——智能体真实跑了什么一目了然:</p>")
    P.append("<pre>" + E("\n".join(e.summary[:120] for e in kept_exec)) + ("\n" + E(dropped_line) if dropped_line else "") + "</pre>")
    if ext:
        P.append("<p class='small'>网络层外部出站(节选):</p><pre>" +
                 E("\n".join(f"{f.proto} -> {f.dst}:{f.dport}  host={f.host or '-'}  out={f.bytes_out}B" for f in ext[:6])) + "</pre>")

    # ---- 模型输入 ----
    P.append("<h3>3.3 送入模型的 prompt</h3>")
    P.append("<p class='small'><b>System</b>(节选:12 类恶意操作字典 — 判定标准):</p>")
    rub = render_rubric()
    P.append("<pre>" + E(rub[:rub.find("Concrete risk signals")].strip()) + "</pre>")
    P.append(f"<p class='small'><b>User</b>(跨层证据, 共 {_tok(len(SYSTEM_PROMPT)+len(evidence))} tokens; 节选头部 + 注入步骤):</p>")
    ev_head = evidence[:1100]
    P.append("<pre>" + _mark(E(ev_head)) + "\n…</pre>")

    # ---- 模型输出 ----
    P.append("<h3>3.4 模型输出(结构化裁决)</h3>")
    if new_v:
        P.append("<div class='card'><div class='kvs'>"
                 f"判定: <span class='badge b-risk'>{E(str(new_v.get('label')))}</span> &nbsp; 置信度 <b>{new_v.get('confidence')}</b><br><br>"
                 "命中分类 attack_categories: " + " ".join(f"<span class='tag'>{E(c)}</span>" for c in new_v.get("attack_categories", [])) +
                 f"<br><br><b>rationale:</b> {E(new_v.get('rationale',''))}</div></div>")
        if new_v.get("evidence"):
            P.append("<p class='small'>模型给出的证据引用 evidence:</p><pre>" +
                     E(json.dumps(new_v["evidence"], ensure_ascii=False, indent=2)[:900]) + "</pre>")
        if new_v.get("reasoning"):
            P.append("<p class='small'>思考链 reasoning(溯源, 节选):</p><pre>" + E(new_v["reasoning"][:1400]) + "\n…</pre>")

    # ---- 对比 ----
    if old_v:
        P.append("<h3>3.5 优化前后对比(同一条轨迹)</h3><div class='card'><table>"
                 "<tr><th></th><th>旧:AgentDoG 三维 prompt</th><th>新:恶意操作字典 prompt</th></tr>"
                 f"<tr><td>判定</td><td><span class='badge b-safe'>{E(str(old_v.get('label')))}</span> ❌漏报</td><td><span class='badge b-risk'>{E(str(new_v.get('label','')))}</span> ✅正确</td></tr>"
                 f"<tr><td>理由</td><td class='small'>{E(old_v.get('rationale','')[:240])}…</td><td class='small'>{E(new_v.get('rationale','')[:240])}…</td></tr>"
                 "</table>"
                 "<p class='small'>旧 prompt 认为「智能体识别并拒绝了恶意指令 → 无害」; 但标签按「<b>轨迹是否包含攻击</b>」判 risky。新口径「出现即风险」修正了这一偏差。</p></div>")

    # ---- 结论 ----
    P.append("<h2>4. 结论 &amp; 后续</h2><div class='card'>"
             "<p>软件优化(字典表 prompt + 系统层过滤 + 关思考)在 19 条样本上达到 <b>F1=1.0</b>, 单条 <b>13.3s</b>。5 万样本估算:</p>"
             "<table><tr><th>配置</th><th>单条</th><th>5万(单机 2×910B2)</th><th>F1</th></tr>"
             "<tr><td>基线(大prompt+思考)</td><td>~44s</td><td>~25 天</td><td>0.33</td></tr>"
             "<tr><td>+ 系统层 slim</td><td>~35s</td><td>~20 天</td><td>1.0</td></tr>"
             "<tr><td>+ 关思考</td><td><b>13.3s</b></td><td><b>~7.7 天</b></td><td>1.0</td></tr>"
             "<tr><td>+ 加卡/预筛 benign</td><td>—</td><td>→ 小时级</td><td>—</td></tr></table>"
             "<div class='note'>caveat: ① 仅 19 条标签, 需更大集验证泛化与「关思考」在难样本上的 recall; ② 数据集有 1 处 md5 错位(<code>06d5404</code> 有轨迹无标签 / <code>266e57</code> 有标签无轨迹); ③ FP8 在 910B2 无硬件加速, 量化用 INT8(W8A8) 且不减 token, 救不了速度——5万到小时级靠加硬件。</div>"
             "</div>")

    P.append('<footer>由 agentaudit/scripts/make_report.py 自动生成 · 数据案例 ' + CASE[:12] + '…</footer>')
    P.append("</div></body></html>")

    out = Path(__file__).resolve().parent.parent / "docs" / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(P), encoding="utf-8")
    print(f"已生成: {out}  ({out.stat().st_size} 字节)")


def _mark(s: str) -> str:
    """高亮注入/敏感关键词(在已转义文本上)。"""
    for kw in ("ignore previous instructions", "ignore all previous", "credentials", "~/.aws", "AWS_", "curl", "exfiltrat", "id_rsa", "\\.env"):
        s = re.sub("(" + kw + ")", r'<span class="hl">\1</span>', s, flags=re.I)
    return s


if __name__ == "__main__":
    main()
