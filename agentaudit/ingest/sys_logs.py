"""解析系统层日志 -> list[SysEvent].

主路径 = Linux auditd (enriched):
  - 多行共享 audit(ts:SEQ) -> 按 SEQ 合并为一条逻辑事件
  - 行尾 enriched `SYSCALL=execve` 给可读系统调用名
  - PROCTITLE=<hex> 解码出真实命令行
  - 仅保留含 SYSCALL/EXECVE 的事件; 相同摘要去重

安全过滤 (security_only=True, 默认): auditd 海量 syscall 里 ~96% 是智能体正常运转的
噪声(工作区内读写、对网关收发)。只保留**安全相关**事件:
  execve/提权 syscall / connect-bind / 命中审计规则 key / 访问敏感路径的文件操作;
其余按 kind 计数折叠成一行, 既大幅压 token 又不丢"曾有大量常规活动"的上下文。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..schema import SysEvent

_AUDIT_ID = re.compile(r"audit\((\d+\.\d+):(\d+)\)")
_TYPE = re.compile(r"^type=(\w+)")
_FIELD = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')

_SYSCALL_KIND = {
    "exec": {"execve", "execveat"},
    "priv": {"setuid", "setreuid", "setresuid", "setgid", "setregid", "setresgid", "setfsuid", "capset", "ptrace",
             "mount", "umount2", "chroot", "pivot_root", "init_module", "finit_module", "delete_module", "reboot"},
    "net": {"connect", "sendto", "sendmsg", "recvfrom", "recvmsg", "socket", "bind", "accept", "accept4", "listen"},
    "file": {"open", "openat", "openat2", "creat", "unlink", "unlinkat", "rename", "renameat", "renameat2",
             "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "truncate", "mkdir", "mkdirat", "link", "symlink"},
}
_NAME2KIND = {n: k for k, names in _SYSCALL_KIND.items() for n in names}

# x86_64 syscall 号 -> 名 (auditd 未 enrich、只有数字 syscall=NN 时用; arch=c000003e)
_SYSNO_X86 = {
    "0": "read", "1": "write", "2": "open", "41": "socket", "42": "connect", "43": "accept", "44": "sendto",
    "45": "recvfrom", "46": "sendmsg", "47": "recvmsg", "49": "bind", "50": "listen", "59": "execve",
    "76": "truncate", "82": "rename", "83": "mkdir", "85": "creat", "86": "link", "87": "unlink", "88": "symlink",
    "90": "chmod", "91": "fchmod", "92": "chown", "93": "fchown", "101": "ptrace", "105": "setuid", "106": "setgid",
    "113": "setreuid", "114": "setregid", "117": "setresuid", "119": "setresgid", "122": "setfsuid", "126": "capset",
    "161": "chroot", "165": "mount", "169": "reboot", "175": "init_module", "257": "openat", "258": "mkdirat",
    "260": "fchownat", "263": "unlinkat", "264": "renameat", "268": "fchmodat", "288": "accept4",
    "313": "finit_module", "316": "renameat2", "322": "execveat", "437": "openat2",
}

# 安全敏感文件路径 (访问这些才保留 file 事件; 工作区内常规文件不留)
_SENSITIVE_PATH = re.compile(
    r"(?i)("
    r"/etc/(passwd|shadow|gshadow|sudoers|crontab|ssh/)|"
    r"\.ssh/|id_rsa|id_ed25519|id_dsa|id_ecdsa|authorized_keys|"
    r"\.env(\.|/|$)|\.aws/|\.kube/|\.docker/config|\.git-credentials|\.netrc|\.pgpass|\.npmrc|"
    r"/root/|\.bash_history|/proc/\d+/(mem|environ|maps)|"
    r"credential|secret|private.{0,3}key|\.pem$|\.key$"
    r")"
)
# connect/bind 保留(新建连接), sendto/recvfrom 等流式收发是噪声丢弃
_KEEP_NET = {"connect", "bind"}


def _classify_syscall(name: str) -> str:
    return _NAME2KIND.get(name.lower(), "other")


def _is_relevant(name: str, kind: str, paths: list[str], key: str | None) -> bool:
    if kind in ("exec", "priv"):
        return True
    if name.lower() in _KEEP_NET:
        return True
    if kind == "file" and any(_SENSITIVE_PATH.search(p) for p in paths):
        return True
    return False


def _decode_proctitle(v: str) -> str:
    try:
        return bytes.fromhex(v).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except ValueError:
        return v


def _fields(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, q, u in _FIELD.findall(line):
        if k not in out:
            out[k] = q if q else u
    return out


def _parse_auditd(lines: list[str], security_only: bool) -> list[SysEvent]:
    groups: dict[str, dict] = {}
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
                g["f"]["SYSCALL"] = _SYSNO_X86.get(f["syscall"], "syscall#" + f["syscall"])
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

    seen: dict[str, dict] = {}
    seen_order: list[str] = []
    dropped: dict[str, int] = {}
    for seq in order:
        g = groups[seq]
        if "SYSCALL" not in g["types"] and "EXECVE" not in g["types"]:
            continue
        f = g["f"]
        name = f.get("SYSCALL", "?")
        kind = _classify_syscall(name)
        if security_only and not _is_relevant(name, kind, g["paths"], f.get("key")):
            dropped[kind] = dropped.get(kind, 0) + 1
            continue
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
        if summary in seen:
            seen[summary]["count"] += 1
        else:
            seen[summary] = {"count": 1, "ts": g["ts"], "kind": kind}
            seen_order.append(summary)

    events: list[SysEvent] = []
    for summary in seen_order:
        info = seen[summary]
        text = summary + (f"  (×{info['count']})" if info["count"] > 1 else "")
        events.append(SysEvent(idx=len(events), ts=info["ts"], kind=info["kind"], summary=text))
    if dropped:
        drop_str = ", ".join(f"{k}:{v}" for k, v in sorted(dropped.items(), key=lambda x: -x[1]))
        events.append(SysEvent(idx=len(events), kind="other",
                               summary=f"[+ {sum(dropped.values())} 条常规 syscall 被安全过滤折叠: {drop_str} (工作区内读写/网关收发等噪声)]"))
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


def parse_syslog(path: str | Path, security_only: bool = True) -> list[SysEvent]:
    path = Path(path)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if "msg=audit(" in "\n".join(lines[:50]):
        return _parse_auditd(lines, security_only)
    return _parse_generic(lines)
