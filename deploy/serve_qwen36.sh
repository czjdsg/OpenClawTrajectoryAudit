#!/bin/bash
# 启动 vLLM (vllm-ascend) 部署 Qwen3.6-35B-A3B，OpenAI 兼容接口，端口 8000
# 硬件: 2x Ascend 910B2 (NPU 逻辑号 4 / 6), TP=2
set -e

IMAGE="quay.io/ascend/vllm-ascend:v0.21.0rc1-openeuler"
NAME="vllm-qwen36"
MODEL="/models/Qwen3.6-35B-A3B"

# 已存在同名容器则先删
docker rm -f "$NAME" 2>/dev/null || true

docker run -itd --name "$NAME" \
  --restart unless-stopped \
  --shm-size=32g \
  --network host \
  --device /dev/davinci4 --device /dev/davinci6 \
  --device /dev/davinci_manager --device /dev/devmm_svm --device /dev/hisi_hdc \
  -v /usr/local/dcmi:/usr/local/dcmi \
  -v /usr/local/bin/npu-smi:/usr/local/bin/npu-smi \
  -v /usr/local/Ascend/driver/lib64/:/usr/local/Ascend/driver/lib64/ \
  -v /usr/local/Ascend/driver/version.info:/usr/local/Ascend/driver/version.info \
  -v /etc/ascend_install.info:/etc/ascend_install.info \
  -v /data/models:/models \
  -e ASCEND_RT_VISIBLE_DEVICES=0,1 \
  -e HF_HUB_OFFLINE=1 -e TRANSFORMERS_OFFLINE=1 -e VLLM_USE_MODELSCOPE=false \
  "$IMAGE" \
  vllm serve "$MODEL" \
    --tensor-parallel-size 2 \
    --max-model-len 262144 \
    --reasoning-parser qwen3 \
    --served-model-name qwen3.6 \
    --gpu-memory-utilization 0.9 \
    --port 8000

echo "容器已后台启动。查看加载日志: docker logs -f $NAME"
echo "首次加载较慢(权重+图编译)。出现 'Application startup complete' 即就绪。"

# ===== 万一首次启动报错的回退手段(逐个加到上面 vllm serve 后面再试) =====
#  --enforce-eager                 # 关闭 ACL graph 图模式(图编译报错时)
#  --max-model-len 8192            # 降低上下文(显存/KV 不够时)
#  --enable-expert-parallel        # MoE 专家并行(吞吐优化)
#  --limit-mm-per-prompt '{"image":0,"video":0}'  # 纯文本场景禁多模态、省显存
