"""解析系统层日志 -> list[SysEvent].

主路径 = Linux auditd (enriched) (已对照真实样例):
  - 多行共享 audit(ts:SEQ) 事件号 -> 按 SEQ 合并为一条逻辑事件
  - 行尾 enriched `SYSCALL=execve` 给可读系统调用名 (无需数字映射)
  - PROCTITLE=<hex> 解码出真实命令行 (高信号)
  - 过滤 DAEMON_*/CONFIG_CHANGE 等噪声, 仅保留含 SYSCALL/EXECVE 的事件
  - 相同摘要去重 (sendto/read 等高频噪声折叠为 ×N)
保留通用回退 (JSONL / 纯文本 syslog).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from ..schema import SysEvent

_AUDIT_ID = re.compile(r"audit\((\d+\.\d+):(\d+)\)")
_TYPE = re.compile(r"^type=(\w+)")
_FIELD = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')

_SYSCALL_KIND = {
    "exec": {"execve", "execveat"},
    "priv": {"setuid", "setreuid", "setresuid", "setgid", "setresgid", "setfsuid", "capset", "ptrace"},
    "net": {"connect", "sendto", "sendmsg", "recvfrom", "recvmsg", "socket", "bind", "accept", "accept4", "listen"},
    "file": {"open", "openat", "openat2", "creat", "unlink", "unlinkat", "rename", "renameat", "renameat2",
             "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "truncate", "mkdir", "mkdirat", "link", "symlink"},
}
_NAME2KIND = {n: k for k, names in _SYSCALL_KIND.items() for n in names}


def _classify_syscall(name: str) -> str:
    return _NAME2KIND.get(name.lower(), "other")


def _decode_proctitle(v: str) -> str:
    try:
        return bytes.fromhex(v).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except ValueError:
        return v


def _fields(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, q, u in _FIELD.findall(line):
        if k not in out:  # 保留首次出现 (raw 优先于 enriched 同名)
            out[k] = q if q else u
    return out


def _parse_auditd(lines: list[str]) -> list[SysEvent]:
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for line in lines:
        mid = _AUDIT_ID.search(line)
        if not mid:
            continue
        ts, seq = float(mid.group(1)), mid.group(2)
        mtype = _TYPE.match(line)
        typ = mtype.group(1) if mtype else "?"
        g = groups.get(seq)
        if g is None:
            g = {"ts": ts, "types": set(), "f": {}, "paths": []}
            groups[seq] = g
            order.append(seq)
        g["types"].add(typ)
        f = _fields(line)
        if typ == "SYSCALL":
            for k in ("SYSCALL", "comm", "exe", "success", "key"):
                if k in f:
                    g["f"][k] = f[k]
            if "SYSCALL" not in f and "syscall" in f:
                g["f"]["SYSCALL"] = "syscall#" + f["syscall"]
        elif typ == "PROCTITLE" and "proctitle" in f:
            g["f"]["cmd"] = _decode_proctitle(f["proctitle"])
        elif typ == "EXECVE":
            args = [f[k] for k in sorted(f) if re.fullmatch(r"a\d+", k)]
            if args:
                g["f"].setdefault("cmd", " ".join(args))
        elif typ == "PATH" and "name" in f:
            g["paths"].append(f["name"])
        elif typ == "SOCKADDR":
            g["f"]["saddr"] = f.get("SADDR") or f.get("saddr", "")

    # 合并 -> 摘要 -> 去重
    seen: dict[str, dict[str, Any]] = {}
    seen_order: list[str] = []
    for seq in order:
        g = groups[seq]
        if "SYSCALL" not in g["types"] and "EXECVE" not in g["types"]:
            continue
        f = g["f"]
        name = f.get("SYSCALL", "?")
        parts = [name]
        if f.get("comm"):
            parts.append(f"comm={f['comm']}")
        if f.get("cmd"):
            parts.append(f"cmd='{f['cmd'][:240]}'")
        elif f.get("exe"):
            parts.append(f"exe={f['exe']}")
        if g["paths"]:
            uniq = list(dict.fromkeys(g["paths"]))[:4]
            parts.append("path=" + ",".join(uniq))
        if f.get("saddr"):
            parts.append(f"saddr={f['saddr'][:80]}")
        if f.get("key") and f["key"] not in ("(null)",):
            parts.append(f"key={f['key']}")
        summary = " ".join(parts)
        kind = _classify_syscall(name)
        if summary in seen:
            seen[summary]["count"] += 1
        else:
            seen[summary] = {"count": 1, "ts": g["ts"], "kind": kind}
            seen_order.append(summary)

    events: list[SysEvent] = []
    for summary in seen_order:
        info = seen[summary]
        cnt = info["count"]
        text = summary + (f"  (×{cnt})" if cnt > 1 else "")
        events.append(SysEvent(idx=len(events), ts=info["ts"], kind=info["kind"], summary=text))
    return events


# ----------------------------------------------------- 通用回退 (非 auditd)
_KW = {
    "exec": ("execve", "exec "),
    "priv": ("setuid", "setgid", "capset", "sudo", "su:", "ptrace"),
    "net": ("connect", "sendto", "socket", "bind", "saddr="),
    "file": ("openat", "open(", "unlink", "rename", "chmod", "write(", "read("),
}


def _classify_text(text: str) -> str:
    low = text.lower()
    for kind, kws in _KW.items():
        if any(kw in low for kw in kws):
            return kind
    return "other"


def _parse_generic(lines: list[str]) -> list[SysEvent]:
    events: list[SysEvent] = []
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if line.lstrip().startswith("{"):
            try:
                rec = json.loads(line)
                fields = [f"{k}={rec[k]}" for k in ("syscall", "action", "exe", "comm", "cmd", "path", "name", "dport", "result") if rec.get(k) not in (None, "")]
                summary = " ".join(fields) or json.dumps(rec, ensure_ascii=False)[:400]
                events.append(SysEvent(idx=len(events), kind=_classify_text(summary), summary=summary))
                continue
            except json.JSONDecodeError:
                pass
        events.append(SysEvent(idx=len(events), kind=_classify_text(line), summary=line[:400]))
    return events


def parse_syslog(path: str | Path) -> list[SysEvent]:
    path = Path(path)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    head = "\n".join(lines[:50])
    if "msg=audit(" in head:
        return _parse_auditd(lines)
    return _parse_generic(lines)
