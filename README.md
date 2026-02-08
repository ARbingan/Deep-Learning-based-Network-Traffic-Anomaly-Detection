# 基于 Scapy 的网络异常流量检测器

本项目为南京邮电大学B22041217辛晗宇的本科毕业设计，实现一个基于 Scapy 的网络异常流量实时检测与可视化系统，使用 **Streamlit** 作为前端界面。

主要采用流水线架构，将流量采集、解析、特征提取、异常检测与可视化等模块串联起来。每个模块只负责一个特定的功能，有利于独立修改且便于单元测试。数据从上到下流动，没有循环依赖。每一层都是独立修改的个体，可以随时添加规则且不影响其他模块。

各个模块通信的核心是数据结构 `PacketEvent`，它在 `Source` 层被采集，在 `Parser` 层被解析，在 `Feature` 层被特征提取，在 `Sink` 层被输出。每个模块只负责一个特定的功能，而数据则在这些模块之间流动。

我将该本科毕业设计的代码开源在 [GitHub](https://github.com/yourusername/network-anomaly-detector) 上。项目结构如下：

```
network-anomaly-detector/
├── src/
│   ├── core/
│   │   ├── source/
│   │   ├── parser/
│   │   ├── features/
│   │   ├── sink/
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── rules.py
│   ├── streamlit_app.py
├── requirements.txt
├── README.md
```

我将会在项目完成后，逐步完善代码注释、文档字符串、日志输出等。

## 主要模块

- `Source`：流量来源与采集（实时抓包 / pcap 文件）
- `Parser`：协议解析与原始字段提取
- `Feature`：多维度特征构建（统计特征 / 协议特征 / 攻击行为特征）
- `Sink`：检测结果输出（日志、告警、可视化）

## 内部数据流（数据结构与模块关系）

- **PacketEvent（Source 层输出）**
  - 由 `core.source.live_source` 或 `core.source.pcap_source` 产生
  - 字段：抓包时间戳 `timestamp`、原始 `scapy.Packet` 对象 `raw_packet`

- **ParsedPacket（Parser 层输出）**
  - 由 `core.parser.parse_packet` 解析单个 `PacketEvent`
  - 字段：源/目的 IP 与端口、协议类型、包长、TCP flags、TTL、payload 长度等

- **FeatureVector（Feature 层输出）**
  - 由 `core.features.aggregate_features` 按「5 元组（src_ip, dst_ip, src_port, dst_port, protocol）+ 时间窗口」聚合
  - 字段：窗口起止时间、5 元组标识，以及窗口内的统计特征（包数、字节数、平均包长、SYN 数量等）

- **Alert（Sink 层输出）**
  - 异常检测模块（规则 / 模型）根据 `FeatureVector` 生成告警
  - 由 `core.sink.log_alert` 和 `core.sink.print_alert` 进行落盘与 CLI 输出
  - 字段：告警时间、源/目的 IP、告警类型、风险分数、命中规则与模型信息等

## 快速开始（后续将逐步完善）

1. 创建并激活 Python 虚拟环境（推荐 Python 3.10+）。
2. 安装依赖：

```bash
pip install -r requirements.txt
```

3. 启动 Streamlit 界面：

```bash
streamlit run src/streamlit_app.py
```

>>>>>>> 285b31d (提交所有修改后再改名)
