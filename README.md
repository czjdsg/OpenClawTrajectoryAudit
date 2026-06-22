# agent-audit — OpenClaw 轨迹跨层安全审计框架 (v0.1)

用已部署的 **Qwen3.6-35B**(vLLM, OpenAI 兼容) 对 OpenClaw 自主智能体的执行轨迹做**跨层安全审计**。
**阶段一**目标:轨迹级**二分类**(`safe` / `risky`)。

设计对齐 **AgentDoG**(arXiv:2601.18491)——三维风险分类法(来源 where × 失效模式 how × 危害 what)
与"任一步骤不安全 ⇒ 整条轨迹不安全"的判定规则;并在其基础上**扩展到三层日志的跨层关联**
(应用 + 系统 + 网络),用更大的 Qwen3.6-35B 做**零样本**判别替代其微调的 Qwen2.5-7B。

> 相关工作:AgentDoG (2601.18491)、ATBench、OpenClaw 安全审计 (2602.14364)。

## 输入:一条轨迹 = 三层日志
| 层 | 文件 | 含义 | 解析器 |
|----|------|------|--------|
| 应用层 | `session.jsonl` | 智能体每步意图/动作 (action·observation) | `ingest/app_session.py` |
| 系统层 | `audit*.log` 等 | 落到 OS 的 syscall (exec/file/net/priv) | `ingest/sys_logs.py` |
| 网络层 | `*.pcap` | 真正出站的流量 (连接/DNS/SNI/HTTP/字节) | `ingest/net_pcap.py`(scapy/tshark) |

## 流水线
```
discover → ingest(3层) → normalize(schema) → assemble(token预算+高信号优先+跨层启发式)
        → Qwen3.6 classify(结构化JSON) → verdict(+reasoning溯源) → results.jsonl → eval
```

## 安装
```bash
bash scripts/install_deps.sh        # scapy / PyYAML (requests/pydantic 已有)
# 可选: dnf install wireshark  (tshark, 更全的 pcap 解析)
```

## 用法
```bash
python -m agentaudit health                       # 检查 vLLM 连通
python -m agentaudit selftest                      # 合成 benign/exfil 两条轨迹, 端到端自测+评估
python -m agentaudit inspect <轨迹目录> --no-model   # 只看"汇编后送入模型的证据"(调 prompt 神器)
python -m agentaudit audit   <数据集目录>            # 批量审计 -> outputs/results.jsonl
python -m agentaudit eval    outputs/results.jsonl labels.jsonl   # 算 acc/P/R/F1
```
数据集默认布局:每个子目录一条轨迹,内含 `session.jsonl` / `audit*.log` / `*.pcap`(改 `config.yaml` 的 glob 适配真实布局)。

## 关键设计
- **跨层关联是核心价值**:`assemble.py` 不仅分层呈现,还产出"跨层启发式标记"(如"读密钥+大量外部出站 ⇒ 疑似外泄"),给模型强线索但不替它下结论。
- **吃满 262K 上下文**:token 预算按层分配(默认 app/sys/net = 50/25/25),超预算时按**高信号优先**截断并标注省略,保证大轨迹可塞入。
- **结构化输出**:vLLM `response_format=json_schema` 直接产出可解析的二分类裁决;模型的 `reasoning` 思考链作为审计**溯源**保存(AgentDoG 的 "beyond binary" 理念)。
- **容错解析**:三层 schema 未定时也能跑(best-effort),拿到样例后在解析器里加分支即可。
- **前向兼容**:输出 schema 已含三维标签槽位,阶段二(细粒度诊断)直接复用。

## 配置 (`config.yaml`)
模型端点、token 预算与分层比例、发现 glob、风险阈值、并发、是否脱敏/存思考链 —— 调优主要改这里。

## 拿到真实样例后要重访的假设
1. **`session.jsonl` 字段**:`app_session.py:_extract_one()` 现兼容 Anthropic/OpenAI 两种风格,按真实 schema 校准。
2. **系统层格式 & syscall 数字映射**:`sys_logs.py` 现按关键字粗分;真实 auditd 多为数字 syscall,需补映射表。
3. **轨迹目录布局 / 文件命名**:改 `config.discovery`。
4. **阈值与校准**:用带标签样例跑 `eval`,调 `risk_threshold` 平衡 P/R(审计通常偏召回)。

## 路线图(阶段二+)
- 细粒度三维诊断(source/mode/harm)+ 命中步骤定位
- 少样本示例 / 在 ATBench 上评测 / 必要时微调
- 超长轨迹分块审计 + 步级聚合(呼应 AgentDoG 的步级 unsafe 聚合)
- 网络层深化:JA3/JA4 指纹、C2 域名情报、明文敏感数据匹配

## 模块树
```
agentaudit/
  schema.py        统一数据模型           config.py      配置
  taxonomy.py      AgentDoG 三维分类法+信号清单
  ingest/          discover / app_session / sys_logs / net_pcap
  features/        assemble(预算+跨层启发式) / redact
  llm/             client / prompts / classify
  pipeline.py runner.py eval.py cli.py
  sample.py        合成样例
```
