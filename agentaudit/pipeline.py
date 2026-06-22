"""端到端单轨迹管线: 三层文件 -> TrajectoryInput -> 裁决."""
from __future__ import annotations

from typing import Optional

from .config import Config
from .ingest.app_session import parse_session
from .ingest.discover import TrajectoryPaths
from .ingest.net_pcap import parse_pcap
from .ingest.sys_logs import parse_syslog
from .llm.classify import classify
from .llm.client import ChatClient
from .schema import AuditVerdict, TrajectoryInput


def load_trajectory(paths: TrajectoryPaths, security_only: bool = True) -> TrajectoryInput:
    return TrajectoryInput(
        traj_id=paths.traj_id,
        app_events=parse_session(paths.app_path) if paths.app_path else [],
        sys_events=parse_syslog(paths.system_path, security_only) if paths.system_path else [],
        net_flows=parse_pcap(paths.network_path) if paths.network_path else [],
        meta={"root": str(paths.root), "layers": paths.available()},
    )


def audit_one(paths: TrajectoryPaths, cfg: Config, client: Optional[ChatClient] = None) -> AuditVerdict:
    traj = load_trajectory(paths, cfg.audit.syscall_filter == "security")
    verdict = classify(traj, cfg, client)
    verdict.usage = {**verdict.usage, "counts": traj.counts(), "layers": paths.available()}
    return verdict
