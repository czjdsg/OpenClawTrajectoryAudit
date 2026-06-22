"""解析网络层 pcap -> list[NetFlow].

后端自动选择: 有 tshark 用 tshark (解析更全, 含 TLS-SNI/HTTP-Host),
否则用 scapy (纯 python, pip 可装). 两者都没有则返回空并给出提示.

聚合策略: 按 (src,dst,dport,proto) 聚合成流, 统计字节; 单独收集 DNS 查询、
TLS-SNI、HTTP 请求行. external 用 ipaddress 判定是否公网.
"""
from __future__ import annotations

import ipaddress
import json
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Optional

from ..schema import NetFlow


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return False


def parse_pcap(path: str | Path) -> list[NetFlow]:
    path = Path(path)
    if not path.exists():
        return []
    if shutil.which("tshark"):
        try:
            return _parse_with_tshark(path)
        except Exception:
            pass  # 退回 scapy
    try:
        return _parse_with_scapy(path)
    except ImportError:
        return [NetFlow(proto="ERROR", info="未安装 scapy 且无 tshark; 见 scripts/install_deps.sh")]


# ---------------------------------------------------------------- scapy backend
def _parse_sni(payload: bytes) -> Optional[str]:
    """从 TLS ClientHello 原始字节里抠 SNI (server_name)."""
    try:
        if len(payload) < 6 or payload[0] != 0x16:  # handshake
            return None
        # 跳过 record(5) + handshake header(4) + version(2) + random(32)
        p = 5 + 4 + 2 + 32
        sid_len = payload[p]; p += 1 + sid_len
        cs_len = struct.unpack(">H", payload[p:p + 2])[0]; p += 2 + cs_len
        comp_len = payload[p]; p += 1 + comp_len
        ext_total = struct.unpack(">H", payload[p:p + 2])[0]; p += 2
        end = p + ext_total
        while p + 4 <= end:
            etype, elen = struct.unpack(">HH", payload[p:p + 4]); p += 4
            if etype == 0x00:  # server_name
                # server_name_list(2) + type(1) + name_len(2) + name
                name_len = struct.unpack(">H", payload[p + 3:p + 5])[0]
                return payload[p + 5:p + 5 + name_len].decode("ascii", "replace")
            p += elen
    except Exception:
        return None
    return None


def _parse_with_scapy(path: Path) -> list[NetFlow]:
    from scapy.all import DNS, DNSQR, IP, IPv6, PcapReader, Raw, TCP, UDP  # type: ignore

    flows: dict[tuple, NetFlow] = {}
    extras: list[NetFlow] = []  # DNS / SNI / HTTP 单列

    with PcapReader(str(path)) as pcap:
        for pkt in pcap:
            ipl = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ipl is None:
                continue
            src, dst = ipl.src, ipl.dst
            length = len(pkt)
            ts = float(pkt.time) if hasattr(pkt, "time") else None

            proto, dport = "IP", None
            if pkt.haslayer(TCP):
                proto, dport = "TCP", int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                proto, dport = "UDP", int(pkt[UDP].dport)

            key = (src, dst, dport, proto)
            fl = flows.get(key)
            if fl is None:
                fl = NetFlow(ts_start=ts, proto=proto, src=src, dst=dst, dport=dport, external=_is_external(dst))
                flows[key] = fl
            fl.bytes_out += length

            # DNS 查询
            if pkt.haslayer(DNS) and getattr(pkt[DNS], "qd", None):
                try:
                    qname = pkt[DNSQR].qname.decode("ascii", "replace").rstrip(".")
                    extras.append(NetFlow(ts_start=ts, proto="DNS", src=src, dst=dst, dport=dport, host=qname, info="DNS query", external=_is_external(dst)))
                except Exception:
                    pass
            # TLS SNI / HTTP
            if pkt.haslayer(Raw) and dport in (443, 80, 8080, 8443):
                payload = bytes(pkt[Raw].load)
                if dport in (443, 8443):
                    sni = _parse_sni(payload)
                    if sni:
                        extras.append(NetFlow(ts_start=ts, proto="TLS", src=src, dst=dst, dport=dport, host=sni, info="TLS ClientHello SNI", external=_is_external(dst)))
                else:
                    line = payload[:200].split(b"\r\n")[0].decode("ascii", "replace")
                    host = None
                    for hl in payload.split(b"\r\n"):
                        if hl.lower().startswith(b"host:"):
                            host = hl[5:].strip().decode("ascii", "replace")
                            break
                    if any(line.startswith(m) for m in ("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH")):
                        extras.append(NetFlow(ts_start=ts, proto="HTTP", src=src, dst=dst, dport=dport, host=host, info=line, external=_is_external(dst)))

    result = list(flows.values()) + extras
    # 外部流 + 大流量优先
    result.sort(key=lambda f: (not f.external, -(f.bytes_out + f.bytes_in)))
    return result


# --------------------------------------------------------------- tshark backend
def _parse_with_tshark(path: Path) -> list[NetFlow]:
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport", "udp.dstport",
        "_ws.col.Protocol", "dns.qry.name", "tls.handshake.extensions_server_name",
        "http.host", "http.request.method", "http.request.uri", "frame.len",
    ]
    cmd = ["tshark", "-r", str(path), "-T", "fields", "-E", "separator=\t"]
    for fl in fields:
        cmd += ["-e", fl]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=300).stdout

    flows: dict[tuple, NetFlow] = {}
    extras: list[NetFlow] = []
    for line in out.splitlines():
        c = line.split("\t")
        if len(c) < len(fields):
            c += [""] * (len(fields) - len(c))
        ts = float(c[0]) if c[0] else None
        src, dst = c[1], c[2]
        dport = int(c[3] or c[4]) if (c[3] or c[4]) else None
        proto = c[5] or "IP"
        dns_q, sni, http_host, http_m, http_uri = c[6], c[7], c[8], c[9], c[10]
        length = int(c[11]) if c[11].isdigit() else 0
        if not dst:
            continue
        key = (src, dst, dport, proto)
        fl = flows.get(key) or NetFlow(ts_start=ts, proto=proto, src=src, dst=dst, dport=dport, external=_is_external(dst))
        fl.bytes_out += length
        flows[key] = fl
        if dns_q:
            extras.append(NetFlow(ts_start=ts, proto="DNS", src=src, dst=dst, host=dns_q, info="DNS query", external=_is_external(dst)))
        if sni:
            extras.append(NetFlow(ts_start=ts, proto="TLS", src=src, dst=dst, dport=dport, host=sni, info="SNI", external=_is_external(dst)))
        if http_host or http_m:
            extras.append(NetFlow(ts_start=ts, proto="HTTP", src=src, dst=dst, dport=dport, host=http_host or None, info=f"{http_m} {http_uri}".strip(), external=_is_external(dst)))
    result = list(flows.values()) + extras
    result.sort(key=lambda f: (not f.external, -(f.bytes_out + f.bytes_in)))
    return result
