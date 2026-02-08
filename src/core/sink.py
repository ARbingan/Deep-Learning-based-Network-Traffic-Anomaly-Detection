"""
Sink 模块：负责检测结果的输出与告警。

当前实现：
- 控制台打印
- 简单日志文件写入
后续 Streamlit 界面会通过共享数据结构直接读取结果进行展示。
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional
import json
import pathlib


@dataclass
class Alert:
    timestamp: datetime
    src_ip: Optional[str]
    dst_ip: Optional[str]
    alert_type: str
    score: float
    detail: Dict[str, Any]


def log_alert(alert: Alert, log_path: str = "data/alerts.log") -> None:
    """将告警写入日志文件（JSON 行）。"""
    pathlib.Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    record = {
        "timestamp": alert.timestamp.isoformat(),
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "alert_type": alert.alert_type,
        "score": alert.score,
        "detail": alert.detail,
    }
    line = json.dumps(record, ensure_ascii=False)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def print_alert(alert: Alert) -> None:
    """在控制台打印简要告警信息。"""
    print(
        f"[{alert.timestamp.isoformat()}] "
        f"[{alert.alert_type}] "
        f"{alert.src_ip} -> {alert.dst_ip}, score={alert.score:.3f}"
    )

