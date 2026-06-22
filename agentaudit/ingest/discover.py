"""在数据集目录里发现轨迹, 把三层文件配对起来.

默认假设: 每个子目录是一条轨迹, 里面有 session.jsonl / 系统日志 / *.pcap.
拿到真实布局后改 config.discovery 的 glob 即可; flat 布局按 id 前缀聚合.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import DiscoveryCfg


@dataclass
class TrajectoryPaths:
    traj_id: str
    root: Path
    app_path: Optional[Path] = None
    system_path: Optional[Path] = None
    network_path: Optional[Path] = None

    def available(self) -> list[str]:
        got = []
        if self.app_path:
            got.append("app")
        if self.system_path:
            got.append("system")
        if self.network_path:
            got.append("network")
        return got


def _first_match(directory: Path, patterns: list[str]) -> Optional[Path]:
    files = [p for p in directory.iterdir() if p.is_file()]
    for pat in patterns:
        for f in files:
            if fnmatch.fnmatch(f.name, pat):
                return f
    return None


def discover(dataset_dir: str | Path, cfg: DiscoveryCfg) -> list[TrajectoryPaths]:
    root = Path(dataset_dir)
    if not root.exists():
        raise FileNotFoundError(f"dataset dir not found: {root}")

    if cfg.layout == "flat":
        return _discover_flat(root, cfg)
    return _discover_dir_per_trajectory(root, cfg)


def _discover_dir_per_trajectory(root: Path, cfg: DiscoveryCfg) -> list[TrajectoryPaths]:
    out: list[TrajectoryPaths] = []
    subdirs = sorted(p for p in root.iterdir() if p.is_dir())
    # 若 root 自身就是单条轨迹 (直接含 session.jsonl), 也支持
    candidates = subdirs or [root]
    for d in candidates:
        app = _first_match(d, cfg.app_glob)
        sysl = _first_match(d, cfg.system_glob)
        net = _first_match(d, cfg.network_glob)
        if not any([app, sysl, net]):
            continue
        out.append(
            TrajectoryPaths(
                traj_id=d.name, root=d, app_path=app, system_path=sysl, network_path=net
            )
        )
    return out


def _discover_flat(root: Path, cfg: DiscoveryCfg) -> list[TrajectoryPaths]:
    """flat: 所有文件平铺, 用文件名去掉层级后缀的前缀作为 traj_id 聚合."""
    groups: dict[str, TrajectoryPaths] = {}

    def _key(p: Path) -> str:
        # 去掉常见层级后缀, 取剩下的 stem 作为 id
        name = p.name
        for suf in (".session.jsonl", ".pcap", ".pcapng", ".syslog", ".log", ".jsonl"):
            if name.endswith(suf):
                return name[: -len(suf)]
        return p.stem

    for p in sorted(root.iterdir()):
        if not p.is_file():
            continue
        tid = _key(p)
        tp = groups.setdefault(tid, TrajectoryPaths(traj_id=tid, root=root))
        if any(fnmatch.fnmatch(p.name, g) for g in cfg.app_glob):
            tp.app_path = p
        elif any(fnmatch.fnmatch(p.name, g) for g in cfg.system_glob):
            tp.system_path = p
        elif any(fnmatch.fnmatch(p.name, g) for g in cfg.network_glob):
            tp.network_path = p
    return [g for g in groups.values() if g.available()]
