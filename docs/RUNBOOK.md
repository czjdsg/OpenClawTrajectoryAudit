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

正式数据为外层包(如 `alldata-s7.zip` / `alldata_7`),内含若干 **`<md5>.zip` 或 `<md5>.tar.gz`**,可能还有 README/results.csv。两步:

```bash
mkdir -p /data/fulldata && cd /data/fulldata
unzip -q /路径/alldata-s7.zip               # -> 解出一个目录(内含 <md5>.zip / <md5>.tar.gz)
bash /data/agent-audit/scripts/prepare_data.sh /data/fulldata/alldata-s7 /data/fulldata/extracted
```

`prepare_data.sh` 自动识别 `*.zip` / `*.tar.gz` / `*.tgz`(README/csv 自动忽略),并且:
- **可断点续跑**:顶层已有文件的 `<md5>/` 直接跳过,磁盘满/中断后重跑不会从头再解一遍;
- **自动拍平**:部分归档内层多套一层目录,而 `discover` 只看 `<md5>/` 顶层文件(不递归),不拍平整条会被静默跳过 —— 脚本会把深层文件上提,并在末尾统计"拍平 N 条"。

完成后 `/data/fulldata/extracted/<md5>/` 下应是 `session.jsonl` + (`audit.log` 或 `sysmon.jsonl`) + `network.pcap`;脚本末尾打印目录数/空目录数/各层文件计数,**核对数量**(空目录会被 discover 跳过,是"解压出来但没文件"的信号)。
> 注:解出的目录名取决于外层包内结构(如 `alldata-s7/`),用 `ls /data/fulldata` 确认后填到上面第二行。
(标签文件 `results.csv` 若随包提供,放 `/data/fulldata/results.csv` 备用于 §4 评估。)

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
tmux new-session -d -s audit "cd /data/agent-audit && PYTHONPATH=/data/agent-audit python3 -u -m agentaudit audit /data/fulldata/extracted --out /data/fulldata/outputs 2>&1 | tee /data/fulldata/outputs/run.log"
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
tmux attach -t audit                                      # 进 tmux 看实时滚动(Ctrl-b 再 d 退出, 不杀任务)
tail -f /data/fulldata/outputs/run.log                    # 看日志(已 python -u 关缓冲, 实时; 计数仍以 results.jsonl 为准)
npu-smi info | grep 910B2                                 # 模型是否在干活
```

---

## 4. 看结果 / 导出提交文件

**提交结果文件 `md5,label`(与样例 results.csv 同格式)跑完会自动生成**:`/data/fulldata/outputs/submission.csv`。
也可随时手动(重)导出:
```bash
cd /data/agent-audit
PYTHONPATH=$PWD python3 -m agentaudit export /data/fulldata/outputs/results.jsonl /data/fulldata/outputs/submission.csv
head -3 /data/fulldata/outputs/submission.csv     # md5,label  (label: risky=1, safe=0)
```
> ⚠️ 导出前确认 error=0(`bash scripts/status.sh`)。有 error 时这些条会按 `label=0` 占位 —— 先重跑 `run_audit.sh` 消除 error 再导出。

其它:
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
| **G. 想提速 / 分批** | **别调并发**:实测 GPU 在并发~8已算力饱和,调到16反而更慢(306s→430s)。真正的提速杠杆只有:① 加卡/加机(算力线性涨)② 砍 prompt(系统层占~82% token,收紧 `syscall_filter`/敏感路径白名单)③ 启发式预筛跳过明显 benign。分批只是把任务拆到多机/多卡,单机拆 `--out` 并行无意义(同一张卡) |
| **H. 时间不够 / 跑不完** | 用**规则兜底收尾**:中断模型、剩余用规则判定补齐,见 §8 |

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
- 实测 ~14–18s/条(并发8, 同设置自身会因调度顺序±~30%抖动);5万 ≈ 8–10 天 / 10万 ≈ 16–21 天。
- 100G 数据 ≈ 5–8 万条(压缩态)→ 约 8–17 天。
- **并发只能到 8**:实测 8/16/32 = 306/430/393s, 没一档比8快(GPU 在~8已算力饱和, 服务端并行还硬顶~15-16)。提速只能加卡/砍prompt/预筛, 调并发无效。

---

## 8. 时间不够: 规则兜底收尾(模型跑不完时用)

若到了 deadline(如~10天)模型还没跑完,**不要硬等**:中断模型,已判好的保留,剩余轨迹用**规则判定**(不调模型,秒级)补齐,凑齐完整 submission。

```bash
cd /data/agent-audit
bash scripts/finish_with_rules.sh /data/fulldata/extracted /data/fulldata/outputs
```

脚本做三件事:① `tmux kill-session audit` 中断模型(结果逐条 flush 落盘,**已判的一条不丢**,只有飞行中的≤8条会被规则重判)② 剩余 + error 的轨迹跑 `agentaudit rulefill` 规则判定 ③ 重新生成 `submission.csv` / `summary.json`(`by_method` 字段显示模型/规则各判了多少条)。

手动等价:
```bash
tmux kill-session -t audit 2>/dev/null         # 中断模型(可选, 不在跑就跳过)
cd /data/agent-audit
PYTHONPATH=$PWD python3 -m agentaudit rulefill /data/fulldata/extracted --out /data/fulldata/outputs
```

**规则判定是什么**:用跨层启发式信号(破坏性命令 / 密钥+外连 / 提示注入 / 脚本外连 / 提权 / 跨层矛盾),带严重度权重判 risky/safe,`model` 字段标 `rule:v1` 以便溯源区分。

**效果(22样例实测)**:**召回=1.0(0 漏报)**、精确≈0.5、F1≈0.67 —— 刻意**召回优先**(安全审计宁可多报不可漏报)。组合 F1 取决于模型跑了多少:模型 0%→0.67(纯规则)、~45%→0.86、100%→1.0。即**模型判过的尾部用规则补,只多报、不漏报**。

> 规则兜底是**保底**不是替代:能让模型多跑就多跑(F1 更高),实在跑不完才用它收尾。规则结果可单独筛出来复核:`python3 -c "import json;[print(r['traj_id'],r['rationale']) for r in map(json.loads,open('OUT/results.jsonl')) if str(r.get('model','')).startswith('rule') and r['risky']]"`
