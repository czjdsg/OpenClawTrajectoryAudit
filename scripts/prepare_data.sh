#!/bin/bash
# 解压全量样本成"每条一目录"(每个 <md5>.{zip,tar.gz,tgz} -> extracted/<md5>/)。
# 用法: bash scripts/prepare_data.sh <归档目录> <解压目标目录>
set -e
SRC="${1:?用法: prepare_data.sh <归档目录(.zip/.tar.gz/.tgz)> <解压目标目录>}"
OUT="${2:?用法: prepare_data.sh <归档目录(.zip/.tar.gz/.tgz)> <解压目标目录>}"
mkdir -p "$OUT"
shopt -s nullglob

archives=("$SRC"/*.zip "$SRC"/*.tar.gz "$SRC"/*.tgz)
[ ${#archives[@]} -gt 0 ] || { echo "[!] $SRC 下没有 .zip/.tar.gz/.tgz"; exit 1; }
echo "[*] 发现 ${#archives[@]} 个归档 -> $OUT"

n=0; skip=0; fail=0; flat=0
for a in "${archives[@]}"; do
  b="$(basename "$a")"
  case "$b" in
    *.tar.gz) m="${b%.tar.gz}" ;;
    *.tgz)    m="${b%.tgz}"    ;;
    *.zip)    m="${b%.zip}"    ;;
  esac
  d="$OUT/$m"

  # 已解压过(顶层已有文件)就跳过 -> 可断点续跑, 中途磁盘满/被打断后重跑不会从头再来
  if [ -n "$(find "$d" -maxdepth 1 -type f -print -quit 2>/dev/null)" ]; then
    skip=$((skip+1)); continue
  fi

  mkdir -p "$d"
  ok=0
  case "$b" in
    *.zip) unzip -o -q "$a" -d "$d/" 2>/dev/null && ok=1 ;;
    *)     tar xzf "$a" -C "$d/" 2>/dev/null && ok=1 ;;
  esac
  if [ $ok -ne 1 ]; then echo "[!] 解压失败: $a"; fail=$((fail+1)); continue; fi

  # 拍平: discover 只看 <md5>/ 顶层文件(不递归), 归档内多套一层目录时必须上提, 否则整条被跳过
  if [ -z "$(find "$d" -maxdepth 1 -type f -print -quit 2>/dev/null)" ]; then
    find "$d" -mindepth 2 -type f -exec mv -f -t "$d/" {} + 2>/dev/null || true
    find "$d" -mindepth 1 -type d -empty -delete 2>/dev/null || true
    flat=$((flat+1))
  fi
  n=$((n+1))
done

echo "[*] 完成: 新解压 $n 条 (跳过已有 $skip, 失败 $fail, 其中拍平 $flat) -> $OUT"
echo "[*] 目录数 $(find "$OUT" -mindepth 1 -maxdepth 1 -type d | wc -l), 其中空目录 $(find "$OUT" -mindepth 1 -maxdepth 1 -type d -empty | wc -l) (空的会被 discover 跳过)"
echo "[*] 各层文件统计(顶层可见才算数):"
echo "    session.jsonl:    $(find "$OUT" -mindepth 2 -maxdepth 2 -name 'session.jsonl' | wc -l) 条"
echo "    audit.log(Linux): $(find "$OUT" -mindepth 2 -maxdepth 2 -name 'audit*.log' | wc -l) 条"
echo "    sysmon(Windows):  $(find "$OUT" -mindepth 2 -maxdepth 2 -name '*sysmon*.jsonl' | wc -l) 条"
echo "    network.pcap:     $(find "$OUT" -mindepth 2 -maxdepth 2 -name '*.pcap*' | wc -l) 条"
deep=$(find "$OUT" -mindepth 3 -name 'session.jsonl' | wc -l)
[ "$deep" -gt 0 ] && echo "[!] 警告: 还有 $deep 条 session.jsonl 埋在更深层, discover 看不到 — 检查归档结构"
exit 0
