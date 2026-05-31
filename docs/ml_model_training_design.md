# ML 模型训练方案设计

## 1. 背景与问题

本系统采用"规则 + 机器学习 + Transformer"三层混合检测架构。其中机器学习层使用随机森林（RandomForest）分类器，对网络流量特征向量进行异常检测。

在初版训练方案中，特征集包含了由规则检测器派生的攻击标志位（如 `is_syn_flood`、`is_ddos`、`is_port_scan` 等）。实验发现，使用该特征集训练的模型在测试集上 Accuracy、Precision、Recall、F1 均达到 1.0，出现明显的**标签泄露（Label Leakage）**问题：模型实际上是在用"已经判断出是攻击"的规则结果来预测"是否是攻击"，而非从原始流量特征中学习真正的异常模式，导致模型泛化能力极差。

## 2. 特征分析

系统的特征向量（`FeatureVector`）由三部分组成：

### 2.1 统计特征（StatisticalFeatures）

反映流量窗口内的原始统计信息，与攻击标签无直接因果关系：

| 特征名 | 含义 |
|--------|------|
| `packet_count` | 窗口内数据包总数 |
| `byte_count` | 窗口内总字节数 |
| `avg_pkt_len` | 平均包长 |
| `max_pkt_len` | 最大包长 |
| `min_pkt_len` | 最小包长 |
| `std_pkt_len` | 包长标准差 |
| `packet_rate` | 包速率（包/秒） |
| `byte_rate` | 字节速率（字节/秒） |
| `inter_arrival_time` | 平均包间隔时间 |
| `syn_count` | SYN 包数量 |
| `ack_count` | ACK 包数量 |
| `fin_count` | FIN 包数量 |
| `rst_count` | RST 包数量 |

### 2.2 协议特征（ProtocolFeatures）

反映协议层面的行为特征：

| 特征名 | 含义 |
|--------|------|
| `header_size` | 头部大小 |
| `payload_size` | 载荷大小 |
| `ttl_avg` | 平均 TTL 值 |
| `ttl_min` | 最小 TTL 值 |
| `ttl_max` | 最大 TTL 值 |
| `tcp_window_size_avg` | 平均 TCP 窗口大小 |
| `tcp_window_size_max` | 最大 TCP 窗口大小 |
| `payload_entropy` | 载荷熵值 |
| `is_fragmented` | 是否存在分片 |

### 2.3 攻击派生特征（AttackFeatures）——排除

以下特征由规则检测器直接计算得出，与攻击标签存在强因果关系，纳入训练会导致标签泄露，**全部排除**：

| 特征名 | 排除原因 |
|--------|---------|
| `is_ddos` | 规则判断结果，直接等价于标签 |
| `is_syn_flood` | 规则判断结果，直接等价于标签 |
| `is_port_scan` | 规则判断结果，直接等价于标签 |
| `is_udp_flood` | 规则判断结果，直接等价于标签 |
| `is_icmp_flood` | 规则判断结果，直接等价于标签 |
| `unique_src_ips` | 攻击流量中天然极高，与标签强相关 |
| `unique_dst_ports` | 端口扫描的直接特征，与标签强相关 |
| `connection_count` | 与攻击类型强相关 |
| `packet_burst_score` | 由规则逻辑计算的突发评分 |
| `scan_pattern_score` | 由规则逻辑计算的扫描评分 |

## 3. 训练方案

### 3.1 特征集

最终使用 **22 个原始统计与协议特征**，排除全部 10 个规则派生特征。

### 3.2 数据集

使用 CICIDS 2017/2018 数据集预处理后的 `FeatureVector` 文件（`data/cicids_all_features_v2.pkl`），共约 283 万条样本：

- 正常流量（BENIGN）：约 80.3%
- 异常流量（攻击）：约 19.7%

### 3.3 数据预处理

1. **清洗异常值**：将 `inf`、`-inf`、`NaN` 替换为 0，避免标准化失败
2. **标准化**：使用 `StandardScaler` 对训练集 `fit_transform`，对测试集 `transform`
3. **数据集划分**：训练集 80%，测试集 20%，按标签分层采样（`stratify=y`）保持类别比例

### 3.4 模型选择

使用**随机森林（RandomForestClassifier）**，主要参数：

| 参数 | 值 | 说明 |
|------|----|------|
| `n_estimators` | 100 | 决策树数量 |
| `max_depth` | 15 | 最大深度，防止过拟合 |
| `class_weight` | `balanced` | 自动平衡正负样本权重 |
| `n_jobs` | -1 | 使用全部 CPU 核心并行训练 |
| `random_state` | 42 | 固定随机种子，保证可复现 |

选择随机森林的原因：
- 对特征尺度不敏感，鲁棒性强
- 可输出特征重要性，便于分析
- 支持 `predict_proba`，输出异常概率而非硬分类
- 训练速度快，适合大规模数据

### 3.5 模型保存格式

训练完成后将模型、标准化器、特征列名一并保存为 pickle 文件：

```python
{
    'model': RandomForestClassifier,  # 训练好的模型
    'scaler': StandardScaler,         # 已 fit 的标准化器
    'feature_columns': List[str]      # 特征列名（22个）
}
```

## 4. 三层检测架构中的定位

| 检测层 | 方法 | 输入 | 优势 |
|--------|------|------|------|
| 规则层 | 硬规则匹配 | 单条 FeatureVector | 速度快，已知攻击精准 |
| ML 层 | RandomForest | 单条 FeatureVector（22个原始特征） | 从统计模式中发现异常，泛化能力强 |
| Transformer 层 | TinyTransformer | 连续 10 条序列 | 捕捉时序行为模式，检测慢速攻击 |

三层结果并行运行后融合输出，ML 层与规则层形成真正的互补：规则层负责已知攻击的快速判断，ML 层从原始流量统计特征中独立学习异常模式，两者不存在特征依赖关系。
