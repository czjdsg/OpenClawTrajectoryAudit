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

import ipaddress
import json
import re
import xml.etree.ElementTree as ET
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


# ===================================================== Windows 事件日志 / Sysmon
# 系统层在 Windows 上 = Windows 事件日志(Sysmon 最全)。.evtx 二进制需先导出 JSON/JSONL/XML
# (Get-WinEvent ... | ConvertTo-Json / winlogbeat / EvtxECmd)。下面吃导出后的结构化事件。
# EventID 跨架构稳定, 不像 Linux auditd 的数字 syscall 还分 x86/arm。
_WIN_EXEC = {1, 4688}                                  # 进程创建 (CommandLine = 高信号)
_WIN_NET = {3, 22, 5156, 5158}                         # 网络连接 / DNS / WFP
_WIN_FILE = {11, 15, 23, 26}                           # 文件创建/流/删除
_WIN_REG = {12, 13, 14}                                # 注册表
# 注入 / 抓凭据(lsass) / 篡改 / 提权 / 服务安装 / 计划任务 / 加账号 等高危
_WIN_DANGER = {8, 10, 25, 4672, 4673, 4674, 7045, 4697, 4698, 4699, 4700, 4702, 4720, 4728, 4732}

# Windows 敏感对象(替换 Linux 的 /etc/shadow、.ssh): 凭据库/系统hive/lsass/可疑落地等
_WIN_SENSITIVE = re.compile(
    r"(?i)(\\SAM\b|\\SYSTEM\b|\\SECURITY\b|ntds\.dit|lsass|\\System32\\config|"
    r"Login Data|\.kdbx|\.ssh\\|id_rsa|\\Credentials\\|\\Vault\\|\\Microsoft\\Protect\\|"
    r"sethc\.exe|utilman\.exe|cookies\.sqlite|\\Temp\\[^\\]*\.(exe|dll|ps1|bat|scr))"
)
# 持久化位置(注册表 Run/服务/IFEO/Winlogon/计划任务)
_WIN_PERSIST = re.compile(
    r"(?i)(\\CurrentVersion\\Run|\\RunOnce|\\Services\\|Image File Execution Options|"
    r"\\Winlogon\\|TaskCache|\\Policies\\Explorer\\Run|AppInit_DLLs)"
)


def _int(v):
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return None


def _is_external_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)
    except ValueError:
        return False


def _win_extract(rec: dict) -> tuple[int | None, dict]:
    """抽 (EventID, 字段dict), 兼容嵌套(Event/System/EventData/Data)与扁平/winlog/EvtxECmd 形态。"""
    if isinstance(rec.get("Event"), dict):
        ev = rec["Event"]
        sysd = ev.get("System", {}) if isinstance(ev.get("System"), dict) else {}
        eid = sysd.get("EventID")
        if isinstance(eid, dict):
            eid = eid.get("#text") or eid.get("Value")
        data: dict = {}
        ed = ev.get("EventData", {})
        dl = ed.get("Data") if isinstance(ed, dict) else None
        if isinstance(dl, list):
            for d in dl:
                if isinstance(d, dict) and (d.get("Name") or d.get("@Name")):
                    data[d.get("Name") or d.get("@Name")] = d.get("#text") or d.get("Value") or d.get("text") or ""
        elif isinstance(ed, dict):
            data = dict(ed)
        return _int(eid), data
    eid = rec.get("EventID") or rec.get("EventId") or rec.get("Id")
    wl = rec.get("winlog") if isinstance(rec.get("winlog"), dict) else {}
    if eid is None:
        eid = wl.get("event_id")
    data = rec.get("EventData") or rec.get("event_data") or wl.get("event_data") or rec
    if not isinstance(data, dict):
        data = rec
    return _int(eid), data


def _win_kind(eid: int, data: dict) -> str:
    if eid in _WIN_EXEC:
        return "exec"
    if eid in _WIN_DANGER:
        return "priv"
    if eid in _WIN_NET:
        return "net"
    if eid in _WIN_REG:
        return "priv" if _WIN_PERSIST.search(str(data.get("TargetObject", ""))) else "other"
    if eid in _WIN_FILE:
        return "file"
    return "other"


def _win_relevant(eid: int, kind: str, data: dict) -> bool:
    if kind in ("exec", "priv"):
        return True
    if kind == "net":
        return _is_external_ip(str(data.get("DestinationIp") or data.get("DestAddress") or ""))
    if kind == "file":
        return bool(_WIN_SENSITIVE.search(str(data.get("TargetFilename") or data.get("TargetObject") or "")))
    return False


def _win_summary(eid: int, data: dict) -> str:
    parts = [f"EID{eid}"]
    for key, lab in (("Image", "img"), ("CommandLine", "cmd"), ("DestinationIp", "dst"),
                     ("DestinationPort", "dport"), ("DestinationHostname", "host"), ("QueryName", "dns"),
                     ("TargetFilename", "file"), ("TargetObject", "reg"), ("Details", "val"),
                     ("SourceImage", "src"), ("TargetImage", "tgt"), ("GrantedAccess", "acc"),
                     ("ServiceName", "svc"), ("User", "user")):
        v = data.get(key)
        if v not in (None, ""):
            parts.append(f"{lab}={str(v)[:200]}")
    return " ".join(parts)


def _parse_win_xml(text: str) -> list[dict]:
    out: list[dict] = []
    for ch in re.findall(r"<Event[ >].*?</Event>", text, re.S):
        try:
            root = ET.fromstring(re.sub(r'\sxmlns="[^"]*"', "", ch))
        except ET.ParseError:
            continue
        sysd = root.find("System")
        eid = sysd.findtext("EventID") if sysd is not None else None
        data = {}
        ed = root.find("EventData")
        if ed is not None:
            for d in ed.findall("Data"):
                if d.get("Name"):
                    data[d.get("Name")] = d.text or ""
        out.append({"Event": {"System": {"EventID": eid}, "EventData": {"Data": [{"Name": k, "#text": v} for k, v in data.items()]}}})
    return out


def _parse_windows(text: str, security_only: bool) -> list[SysEvent]:
    recs: list[dict] = []
    t = text.strip()
    if t[:1] in ("[", "{"):                              # 整体 JSON (数组/对象)
        try:
            obj = json.loads(t)
            recs = obj if isinstance(obj, list) else [obj]
        except json.JSONDecodeError:
            recs = []
    if not recs and "{" in t:                            # JSON Lines
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    if not recs and "<Event" in t:                       # Windows Event XML
        recs = _parse_win_xml(text)
    if not recs:
        return [SysEvent(idx=0, kind="other", summary="[Windows 系统层: 无法解析; 支持 Sysmon/Security 的 JSON/JSONL/XML 导出]")]

    seen: dict[str, dict] = {}
    order: list[str] = []
    dropped: dict[str, int] = {}
    for rec in recs:
        if not isinstance(rec, dict):
            continue
        eid, data = _win_extract(rec)
        if eid is None:
            continue
        kind = _win_kind(eid, data)
        if security_only and not _win_relevant(eid, kind, data):
            dropped[kind] = dropped.get(kind, 0) + 1
            continue
        s = _win_summary(eid, data)
        if s in seen:
            seen[s]["count"] += 1
        else:
            seen[s] = {"count": 1, "kind": kind}
            order.append(s)
    events: list[SysEvent] = []
    for s in order:
        info = seen[s]
        events.append(SysEvent(idx=len(events), kind=info["kind"],
                               summary=s + (f"  (×{info['count']})" if info["count"] > 1 else "")))
    if dropped:
        ds = ", ".join(f"{k}:{v}" for k, v in sorted(dropped.items(), key=lambda x: -x[1]))
        events.append(SysEvent(idx=len(events), kind="other",
                               summary=f"[+ {sum(dropped.values())} 条常规 Windows 事件被安全过滤折叠: {ds}]"))
    return events


def parse_syslog(path: str | Path, security_only: bool = True) -> list[SysEvent]:
    """按内容探测路由后端: Linux auditd / Windows(Sysmon·Security) / 通用。"""
    path = Path(path)
    if not path.exists():
        return []
    if path.read_bytes()[:7] == b"ElfFile":              # .evtx 二进制
        return [SysEvent(idx=0, kind="other", summary="[.evtx 二进制: 请先导出 JSON/XML (Get-WinEvent|ConvertTo-Json) 或装 python-evtx]")]
    text = path.read_text(encoding="utf-8", errors="replace")
    head = text[:4000]
    if "msg=audit(" in head:
        return _parse_auditd(text.splitlines(), security_only)
    if re.search(r'"?EventID"?|Microsoft-Windows-Sysmon|"winlog"|<Event[ >]', head):
        return _parse_windows(text, security_only)
    return _parse_generic(text.splitlines())
