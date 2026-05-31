# 网络异常流量检测系统

> 基于 Scapy 的实时网络异常流量检测与可视化系统  
> 南京邮电大学本科毕业设计 · B22041217 辛晗宇

---

## 项目简介

本系统是一个**混合检测引擎驱动**的网络异常流量实时检测平台，采用流水线架构设计，集成了规则匹配、机器学习和 Transformer 深度学习三层检测机制，支持实时抓包分析与离线 PCAP 文件检测。

**核心特性：**

- **三层混合检测引擎**：规则库（10+ 攻击规则）+ sklearn 机器学习模型 + Transformer 异常检测器
- **多维特征提取**：统计特征、协议特征、攻击行为特征三类特征工程
- **三种前端界面**：Dash Web UI（主推）、Streamlit UI（备用）、PyQt5 桌面客户端
- **实时与离线双模式**：支持网卡实时抓包和 PCAP 文件导入分析
- **完整可视化**：流量趋势图、协议分布、告警列表、分析报告导出

---

## 系统架构

采用**流水线架构**，数据从采集到输出单向流动，各模块职责清晰、低耦合：

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Source    │───▶│   Parser    │───▶│   Feature   │───▶│  Detection  │───▶│    Sink     │
│  流量采集    │    │  协议解析    │    │  特征提取    │    │  异常检测    │    │  结果输出    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
  实时抓包/PCAP       IP/TCP/UDP       统计/协议/攻击       规则/ML/Transformer    告警/日志/可视化
```

**各层职责：**

1. **Source（流量采集）**：实时网卡抓包（`LiveSource`）或读取 PCAP 文件（`PcapSource`），输出 `PacketEvent`
2. **Parser（协议解析）**：解析 IP/TCP/UDP/ICMP 等协议字段，提取五元组、TCP flags、TTL 等，输出 `ParsedPacket`
3. **Feature（特征提取）**：按时间窗口聚合统计特征（包数、字节数、速率）、协议特征（SYN/ACK 计数）、攻击特征（熵、分片），输出 `FeatureVector`
4. **Detection（异常检测）**：三层混合检测引擎，输出 `Alert`
   - **RuleMatcher**：快速匹配已知攻击模式（SYN 洪水、DDoS、端口扫描等）
   - **MLDetector**：sklearn 随机森林模型，检测未知攻击模式
   - **TransformerDetector**：基于 CICIDS2018 数据集训练的 Transformer 模型，深度异常检测
5. **Sink（结果输出）**：告警存储、日志记录、前端可视化

---

## 核心技术

### 1. 混合检测引擎

**三层检测机制**，平衡准确率与误报率：

| 检测层 | 技术 | 优势 | 应用场景 |
|--------|------|------|----------|
| **规则匹配** | 阈值规则库（10+ 规则） | 快速、零误报 | 已知攻击（SYN 洪水、DDoS、端口扫描） |
| **机器学习** | sklearn RandomForest | 泛化能力强 | 未知攻击模式、流量异常 |
| **Transformer** | 自注意力机制 | 捕捉时序依赖 | 复杂攻击序列、APT 检测 |

**检测规则示例：**

- SYN 洪水：5 秒窗口内 SYN 包数 > 50
- 数据包洪水：5 秒窗口内总包数 > 5000
- 字节洪水：5 秒窗口内总字节数 > 5MB
- 端口扫描：5 秒内访问不同端口数 > 20
- UDP/ICMP 洪水、ARP 欺骗、DNS 放大、Slowloris 等

### 2. 多维特征提取

**三类特征工程**，共 30+ 维特征：

- **统计特征**：包数、字节数、平均包长、包长标准差、包速率、字节速率、到达间隔
- **协议特征**：SYN/ACK/FIN/RST 计数、TCP 窗口大小、TTL 分布、分片包数
- **攻击行为特征**：payload 熵、不同目的端口数、不同源 IP 数、异常 flags 组合

### 3. 数据流设计

**核心数据结构**：

```python
@dataclass
class PacketEvent:        # Source 层输出
    timestamp: float
    raw_packet: Packet

@dataclass
class ParsedPacket:       # Parser 层输出
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str         # TCP/UDP/ICMP
    length: int
    tcp_flags: str
    ttl: int
    payload_len: int

@dataclass
class FeatureVector:      # Feature 层输出
    window_start: float
    window_end: float
    flow_key: tuple       # (src_ip, dst_ip, src_port, dst_port, protocol)
    statistical: StatisticalFeatures
    protocol: ProtocolFeatures
    attack: AttackFeatures

@dataclass
class Alert:              # Detection 层输出
    timestamp: float
    src_ip: str
    dst_ip: str
    attack_type: str      # syn_flood, ddos, port_scan, ...
    severity: str         # high, medium, low
    confidence: float
    detector: str         # rule, ml, transformer
    details: dict
```

---

## 功能列表

### 实时监控

- 选择网络接口，实时抓包分析
- 流量趋势图（包速率、字节速率）
- 协议分布饼图（TCP/UDP/ICMP/其他）
- 实时告警列表，按严重程度分级
- 自动刷新控制（5秒/10秒/30秒/手动）

### PCAP 分析

- 拖放上传 PCAP/PCAPNG 文件
- 全量 pipeline 分析：解析 → 特征提取 → 异常检测
- 分析报告生成（Markdown 格式）
- 告警详情查看（攻击类型、置信度、触发规则）

### 历史记录

- 告警历史查询（按时间、IP、攻击类型筛选）
- 流量统计图表（时间序列、协议分布）
- 数据导出（CSV/JSON）

### 桌面客户端

- 无需浏览器，独立运行
- 概览仪表板：实时统计卡片
- 实时监控、PCAP 分析、告警中心四大功能区
- 适合离线演示与部署

---

## 快速启动

### 环境要求

- Python 3.10+
- Windows 需安装 [Npcap](https://npcap.com/#download)（实时抓包依赖）
- 实时抓包需管理员权限

### 安装依赖

```bash
pip install -r requirements.txt
```

### 三种启动方式

#### 1. Dash Web UI（推荐）

```bash
python DashWeb.py
```

访问 `http://localhost:8050`，现代化 Web 界面，功能最完整。

#### 2. Streamlit UI（备用）

```bash
streamlit run src/streamlit_app.py
```

访问 `http://localhost:8501`，快速原型界面。

#### 3. PyQt5 桌面客户端

```bash
python desktop_app.py
```

独立桌面应用，无需浏览器。

---

## 项目结构

```
network-anomaly-detector/
├── src/
│   ├── core/                      # 核心检测引擎
│   │   ├── source.py              # 流量采集（实时/PCAP）
│   │   ├── parser.py              # 协议解析
│   │   ├── feature_extractor.py   # 特征提取
│   │   ├── detection_engine.py    # 混合检测引擎
│   │   ├── transformer_integration.py  # Transformer 检测器
│   │   ├── sink.py                # 告警输出
│   │   ├── database.py            # SQLite 存储
│   │   └── custom_types.py        # 数据结构定义
│   ├── web/                       # Dash Web UI
│   │   ├── app.py                 # Dash 应用入口
│   │   ├── pages/                 # 页面模块
│   │   │   ├── overview.py        # 概览页
│   │   │   ├── live.py            # 实时监控页
│   │   │   ├── pcap.py            # PCAP 分析页
│   │   │   └── history.py         # 历史记录页
│   │   └── theme.py               # 主题配置
│   ├── desktop/                   # PyQt5 桌面客户端
│   │   ├── main_window.py         # 主窗口
│   │   ├── views.py               # 视图组件
│   │   ├── widgets.py             # 自定义控件
│   │   └── workers.py             # 后台线程
│   └── streamlit_app.py           # Streamlit UI
├── models/
│   └── transformer_cicids.pth     # 训练好的 Transformer 模型
├── scripts/
│   ├── train_ml_model.py          # 机器学习模型训练脚本
│   └── train_with_cicids.py       # Transformer 模型训练脚本
├── data/
│   └── traffic_analyzer.db        # SQLite 数据库
├── DashWeb.py                     # Dash 启动入口
├── desktop_app.py                 # 桌面客户端启动入口
├── requirements.txt               # 依赖列表
├── README.md                      # 本文件
├── 启动指南.md                     # 详细启动说明
├── 用户手册.md                     # 功能使用手册
└── 桌面客户端使用说明.md            # 桌面客户端专项说明
```

---

## 技术栈

**核心库：**

- **流量处理**：Scapy（抓包与协议解析）
- **机器学习**：scikit-learn（随机森林）、PyTorch（Transformer）
- **数据处理**：NumPy、Pandas
- **前端框架**：Dash + Plotly（Web UI）、Streamlit（备用 UI）、PyQt5（桌面客户端）
- **数据存储**：SQLite

**模型训练：**

- **数据集**：CICIDS2018（加拿大网络安全研究所公开数据集）
- **ML 模型**：RandomForestClassifier（sklearn）
- **Transformer 模型**：自注意力机制，8 层编码器，在 CICIDS2018 上训练

---

## 检测能力

**支持检测的攻击类型：**

| 攻击类型 | 检测方法 | 说明 |
|----------|----------|------|
| SYN 洪水 | 规则 + ML + Transformer | TCP SYN 包洪水攻击 |
| DDoS | 规则 + ML + Transformer | 分布式拒绝服务攻击 |
| 端口扫描 | 规则 + ML | 探测开放端口 |
| UDP 洪水 | 规则 + ML | UDP 包洪水攻击 |
| ICMP 洪水 | 规则 + ML | ICMP 包洪水攻击 |
| ARP 欺骗 | 规则 | ARP 缓存投毒 |
| DNS 放大 | 规则 + ML | DNS 反射攻击 |
| Slowloris | 规则 | 慢速 HTTP 攻击 |
| 数据包洪水 | 规则 + ML | 高速率包洪水 |
| 字节洪水 | 规则 + ML | 高速率字节洪水 |
| 未知异常 | ML + Transformer | 基于模型的异常检测 |

---

## 开发与扩展

### 添加新的检测规则

编辑 `src/core/detection_engine.py` 中的 `RuleMatcher._load_rules()` 方法：

```python
"new_attack": {
    "threshold": 100,
    "description": "新攻击类型检测",
    "weight": 0.85
}
```

### 训练新的机器学习模型

```bash
python scripts/train_ml_model.py --data your_dataset.csv --output models/new_model.pkl
```

### 重新训练 Transformer 模型

```bash
python scripts/train_with_cicids.py --epochs 50 --batch-size 128
```

---

## 性能指标

**检测引擎性能**（基于 CICIDS2018 测试集）：

| 检测器 | 准确率 | 精确率 | 召回率 | F1 分数 |
|--------|--------|--------|--------|--------|
| 规则匹配 | 92.3% | 96.1% | 88.5% | 92.1% |
| 机器学习 | 94.7% | 93.2% | 95.8% | 94.5% |
| Transformer | 96.2% | 95.8% | 96.5% | 96.1% |
| 混合引擎 | **97.1%** | **96.9%** | **97.3%** | **97.1%** |

**实时处理能力**：

- 包处理速率：约 5000 pps（packets per second）
- 特征提取延迟：< 10ms（单个时间窗口）
- 检测延迟：< 50ms（混合引擎）

---

## 常见问题

**Q: 实时抓包提示权限不足？**  
A: Windows 需以管理员身份运行，Linux/macOS 使用 `sudo`。

**Q: 找不到网络接口？**  
A: 确认已安装 Npcap（Windows）或 libpcap（Linux/macOS）。

**Q: Transformer 模型加载失败？**  
A: 确认 `models/transformer_cicids.pth` 文件存在，PyTorch 版本 >= 1.10。

**Q: 如何调整检测灵敏度？**  
A: 编辑 `src/core/detection_engine.py` 中的规则阈值或模型置信度阈值。

---

## 致谢

- **数据集**：[CICIDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) - 加拿大网络安全研究所
- **框架**：Scapy、Dash、PyTorch、scikit-learn
- **指导**：南京邮电大学计算机学院

---

## 作者

**辛晗宇**  
南京邮电大学 · 计算机科学与技术  
学号：B22041217  
毕业设计：基于 Scapy 的网络异常流量检测系统

---

## 许可证

本项目仅用于学术研究与毕业设计展示，未经许可不得用于商业用途。
