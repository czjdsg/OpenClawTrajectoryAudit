# 全量数据离线审计 · 操作手册 (RUNBOOK)

适用:在**断网**机器上对全量 OpenClaw 轨迹跑安全审计。
全程**不需要外网**:模型、镜像、依赖、代码都在本机。下面所有路径以本机为准。

> 关键路径速查
> - 代码:`/data/agent-audit`
> - 启动 vLLM:`bash /data/serve_qwen36.sh`
> - 模型:`/data/models/Qwen3.6-35B-A3B`
> - 配置:`/data/agent-audit/config.yaml`
> - 辅助脚本:`/data/agent-audit/scripts/{prepare_data,run_audit,status}.sh`

---

## 0. 断网前必做的检查清单(务必在**还在线**时完成!)

最重要的一条:**确认 vLLM 能起来**。模型推理在本地,但 docker 镜像/容器一旦损坏,断网就无法重拉,整个审计做不了。

```bash
# (1) 启动 vLLM, 等约4分钟到 "Application startup complete"
bash /data/serve_qwen36.sh
docker logs -f vllm-qwen36          # 看到 Application startup complete 即就绪, Ctrl-C 退出看

# (2) 健康检查(--noproxy 必须有, 否则会走代理)
curl -s --noproxy '*' http://localhost:8000/v1/models   # 应返回 model "qwen3.6"

# (3) 依赖在
cd /data/agent-audit && PYTHONPATH=$PWD python3 -c "import scapy,yaml,requests,pydantic,agentaudit; print('deps OK')"

# (4) 端到端冒烟(合成样例, 不需要真实数据)
PYTHONPATH=$PWD python3 -m agentaudit selftest    # 出现 F1 行即全链路通

# (5) 磁盘够 (输出 + 解压都要空间)
df -h /data
```

> ⚠️ 若 `bash /data/serve_qwen36.sh` 报 `docker: ... layer does not exist`,或 `docker images` 是空的 —— docker 镜像损坏。**已有冷备份 `/root/vllm-ascend-v0.21.0rc1.tar`(系统盘),断网也能恢复**(见 §5 docker 恢复)。出发前确认 vLLM 能起来。
>
> 备注:vLLM 容器已设 `--restart unless-stopped`,机器重启会自动拉起;启动脚本已带 `HF_HUB_OFFLINE=1`,断网不会去找 HuggingFace;镜像 tar 备份在系统盘(与 /data 的 docker 仓库不同盘,跨盘冗余)。

---

## 1. 准备数据(解压成"每条一目录")

把全量样本 zip(每个 `<md5>.zip`)放一个目录,例如 `/data/fulldata/zips/`,然后:

```bash
cd /data/agent-audit
bash scripts/prepare_data.sh /data/fulldata/zips /data/fulldata/extracted
```

完成后 `/data/fulldata/extracted/<md5>/` 下应是 `session.jsonl` + (`audit.log` 或 `sysmon.jsonl`) + `network.pcap`。脚本末尾会打印各层文件计数,核对一下数量。
(标签文件 `results.csv` 若有,放 `/data/fulldata/results.csv` 备用于评估。)

---

## 2. 启动审计

```bash
cd /data/agent-audit
bash scripts/run_audit.sh /data/fulldata/extracted /data/fulldata/outputs
```

脚本会:先检查 vLLM → 在 **tmux 会话 `audit`** 里启动审计 → 输出到 `/data/fulldata/outputs/`。

- **为什么 tmux**:任务跨会话存活、不被回收(本机后台任务会被定时 kill,tmux 不会)。
- **断点续跑**:任务中断了?**重复同一条 `run_audit.sh` 命令**即可 —— 自动跳过已完成的,只补未完成的 + 重试 error 的。可以放心反复跑。

手动等价命令(脚本挂了时用):
```bash
mkdir -p /data/fulldata/outputs
tmux new-session -d -s audit "cd /data/agent-audit && PYTHONPATH=/data/agent-audit python3 -m agentaudit audit /data/fulldata/extracted --out /data/fulldata/outputs > /data/fulldata/outputs/run.log 2>&1"
```

---

## 3. 看进度

```bash
bash scripts/status.sh /data/fulldata/outputs /data/fulldata/extracted
```
一眼看到:vLLM 是否 OK、tmux 是否在跑、NPU 功耗(>120W≈在推理)、已完成/总数、risky/safe/error 计数、最近 5 条、error 明细。

零散命令:
```bash
grep -c . /data/fulldata/outputs/results.jsonl          # 已完成条数
ls -d /data/fulldata/extracted/*/ | wc -l                # 总条数
tmux attach -t audit                                      # 进 tmux 看实时(Ctrl-b 再 d 退出, 不杀任务)
tail -f /data/fulldata/outputs/run.log                    # 日志(注:python 块缓冲, 进度行会滞后, 以 results 计数为准)
npu-smi info | grep 910B2                                 # 模型是否在干活
```

---

## 4. 看结果

```bash
# 汇总
cat /data/fulldata/outputs/summary.json        # total / risky / safe / error / elapsed_s

# 只列 risky
python3 -c "import json;[print(r['traj_id'], r['confidence'], r['attack_categories']) for r in map(json.loads,open('/data/fulldata/outputs/results.jsonl')) if r['risky']]"

# 有标签时评估 (F1 / 混淆矩阵)
cd /data/agent-audit
PYTHONPATH=$PWD python3 -m agentaudit eval /data/fulldata/outputs/results.jsonl /data/fulldata/results.csv
```

`results.jsonl` 每行一条:`label`(safe/risky/error)、`risky`、`confidence`、`attack_categories`、`rationale`、`reasoning`(关思考时为空)、`usage`、`error`。

调试某条"喂给模型的内容":
```bash
PYTHONPATH=$PWD python3 -m agentaudit inspect /data/fulldata/extracted/<md5> --no-model
```

---

## 5. 异常处理

| 现象 | 处理 |
|------|------|
| **A. 任务/ tmux 没了** | 重跑 `bash scripts/run_audit.sh ...` —— 自动续跑(已完成的跳过) |
| **B. 大量变 error / 连不上模型** | vLLM 挂了。`curl -s --noproxy '*' localhost:8000/v1/models` 验证 → 挂了就 `bash /data/serve_qwen36.sh` 等就绪 → 重跑 run_audit.sh |
| **C. 个别条 error** | resume 会自动重试(error 不算完成)。反复 error 的:`inspect <md5> --no-model` 看解析炸在哪;results 里该条 `error` 字段有原因。某条 pcap 损坏 → 该条网络层空、其余层照判,不影响整批 |
| **D. vLLM 起不来 / `layer does not exist` / `docker images` 空** | docker 镜像损坏,**只能在线修**(见下方"docker 恢复")。所以务必出发前在 §0 确认过 |
| **E. 磁盘满** | `df -h /data`;清旧 outputs / 解压目录 |
| **F. 机器重启** | vLLM 容器会自动回来(--restart);没回来 `docker start vllm-qwen36`。审计任务**不会**自动回来 → 重跑 run_audit.sh 续跑 |
| **G. 想提速 / 分批** | 已是关思考。可改 `config.yaml` 的 `run.concurrency`;或把 extracted 拆成几个子目录、分别 `--out` 并行跑 |

### docker 恢复(镜像损坏 / `docker images` 空 / vLLM 起不来)
镜像冷备份在**系统盘** `/root/vllm-ascend-v0.21.0rc1.tar`(18G),**断网也能恢复**:
```bash
# 情况1: 只是镜像没了(store 没坏)—— 直接从备份加载
docker load -i /root/vllm-ascend-v0.21.0rc1.tar && bash /data/serve_qwen36.sh

# 情况2: 报 "layer does not exist"(overlay2 存储损坏)—— 先重置存储再加载
systemctl stop docker docker.socket
rm -rf /data/docker/overlay2 /data/docker/image /data/docker/buildkit   # 清损坏存储(会清空所有镜像)
systemctl start docker
docker load -i /root/vllm-ascend-v0.21.0rc1.tar                          # 离线恢复
bash /data/serve_qwen36.sh                                                # 起 vLLM, 等 ready

# 兜底(备份 tar 也丢了且在线): docker pull quay.io/ascend/vllm-ascend:v0.21.0rc1-openeuler
```

---

## 6. 当前配置默认值(`config.yaml`)
- 模型端点 `http://localhost:8000/v1`,model `qwen3.6`,`temperature 0`
- `enable_thinking: false`(关思考, ~13s/条;想更准可改 true, 但慢很多)
- `audit.syscall_filter: security`(系统层安全过滤;`all` 则不过滤)
- `run.concurrency: 8`(并发请求数)
- token 预算 `total_budget 240000`,动态 water-filling 按需分配(各层不会被固定比例误截断)

## 7. 估算(单机 2×910B2, 关思考)
- ~13.9s/条(并发8);5万 ≈ 8 天 / 10万 ≈ 16 天(可加卡/分批缩短)。
- 100G 数据 ≈ 5–8 万条(压缩态)。
