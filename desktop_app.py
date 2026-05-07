#!/usr/bin/env python3
"""
基于 PyQt5 的网络异常流量检测器桌面客户端。

这是启动入口。所有 UI 逻辑位于 src/desktop/ 子包中。
"""

import sys
from pathlib import Path

# 让 core.* 模块可被导入
sys.path.insert(0, str(Path(__file__).parent / "src"))

from desktop.main_window import launch


if __name__ == "__main__":
    sys.exit(launch())
