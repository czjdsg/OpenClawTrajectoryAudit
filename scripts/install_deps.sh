#!/bin/bash
# 安装 agent-audit 依赖. requests/pydantic 基础环境已有.
set -e
echo ">>> pip 安装 scapy / PyYAML ..."
pip install -U scapy PyYAML requests pydantic

echo
echo ">>> (可选) 安装 tshark 以获得更全的 pcap 解析 (TLS-SNI / HTTP host 等):"
echo "    openEuler:  sudo dnf install -y wireshark"
echo "    Ubuntu:     sudo apt-get install -y tshark"
echo
echo "完成. 自测: python -m agentaudit selftest"
