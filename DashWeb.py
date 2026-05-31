"""
Dash Web 前端启动入口。

运行方式：
    python DashWeb.py

浏览器访问 http://localhost:8050
"""

import pathlib
import sys

# 将 src/ 加入模块搜索路径，与 desktop_app.py 保持一致
sys.path.insert(0, str(pathlib.Path(__file__).parent / "src"))

from web.app import app

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8050)
