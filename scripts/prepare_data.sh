#!/bin/bash
# 解压全量样本 zip 成"每条一目录"(每个 <md5>.zip -> extracted/<md5>/)。
# 用法: bash scripts/prepare_data.sh <zip所在目录> <解压目标目录>
set -e
ZIPDIR="${1:?用法: prepare_data.sh <zip目录> <解压目标目录>}"
OUT="${2:?用法: prepare_data.sh <zip目录> <解压目标目录>}"
mkdir -p "$OUT"
n=0; fail=0
shopt -s nullglob
zips=("$ZIPDIR"/*.zip)
[ ${#zips[@]} -gt 0 ] || { echo "[!] $ZIPDIR 下没有 .zip"; exit 1; }
for z in "${zips[@]}"; do
  m="$(basename "$z" .zip)"
  mkdir -p "$OUT/$m"
  if unzip -o -q "$z" -d "$OUT/$m/" 2>/dev/null; then n=$((n+1)); else echo "[!] 解压失败: $z"; fail=$((fail+1)); fi
done
echo "[*] 完成: 解压 $n 条 (失败 $fail) -> $OUT"
echo "[*] 抽查首条文件: $(ls "$OUT"/*/ 2>/dev/null | grep -vE '/$|^$' | head -3 | tr '\n' ' ')"
echo "[*] 各层文件统计:"
echo "    session.jsonl: $(find "$OUT" -name session.jsonl | wc -l) 条"
echo "    audit.log(Linux): $(find "$OUT" -name audit.log | wc -l) 条"
echo "    sysmon.jsonl(Windows): $(find "$OUT" -name sysmon.jsonl | wc -l) 条"
echo "    network.pcap: $(find "$OUT" -name network.pcap | wc -l) 条"
