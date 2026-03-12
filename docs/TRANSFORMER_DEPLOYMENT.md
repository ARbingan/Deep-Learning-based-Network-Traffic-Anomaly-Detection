# 轻量级Transformer异常检测器部署指南

## 📋 目录

1. [概述](#概述)
2. [环境准备](#环境准备)
3. [数据准备](#数据准备)
4. [训练模型](#训练模型)
5. [评估模型](#评估模型)
6. [集成到系统](#集成到系统)
7. [推理使用](#推理使用)
8. [云算力申请](#云算力申请)
9. [故障排除](#故障排除)

---

## 概述

本指南详细说明如何训练、部署和使用轻量级Transformer异常检测器（参数量<100K，适合RTX 3050等入门级GPU）。

### 为什么选择轻量级Transformer？

| 特性 | 传统ML（随机森林） | 轻量Transformer | 大模型（BERT 1.5B） |
|------|-------------------|-----------------|---------------------|
| 参数量 | ~50K | **~85K** | 1,500,000K |
| 显存需求 | CPU | **<200MB** | 8GB+ |
| 推理速度 | 0.1ms | **0.2ms** | 50ms+ |
| 时序建模 | ❌ | **✅** | ✅ |
| 适合硬件 | 任何 | **RTX 3050** | A100+ |

### 模型架构

```
输入序列 [seq_len=10, feature_dim=32]
    ↓
输入投影层 [32 → 64]
    ↓
位置编码（可学习）
    ↓
Transformer编码器 × 2层
    - Multi-Head Attention (4 heads)
    - Feed-Forward (64 → 128 → 64)
    ↓
全局平均池化
    ↓
分类头 [64 → 32 → 1]
    ↓
Sigmoid → 异常概率
```

**总参数量**：约85,000（85K）

---

## 环境准备

### 1. 安装依赖

```bash
# 激活虚拟环境（如果还没激活）
venv\Scripts\activate  # Windows
# 或
source venv/bin/activate  # Linux/Mac

# 安装PyTorch（根据CUDA版本选择）
# RTX 3050需要CUDA 11.8或12.x
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

# 安装其他依赖
pip install -r requirements.txt

# 额外依赖
pip install scikit-learn pyyaml
```

### 2. 验证安装

```python
# test_pytorch.py
import torch
print(f"PyTorch版本：{torch.__version__}")
print(f"CUDA可用：{torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"GPU：{torch.cuda.get_device_name(0)}")
    print(f"显存：{torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")
```

运行：
```bash
python test_pytorch.py
```

---

## 数据准备

### 选项1：使用历史数据（推荐）

系统运行后，数据库 `data/traffic_analyzer.db` 中会积累历史流量特征。

```python
# 检查数据量
from core.database import get_historical_traffic
data = get_historical_traffic(limit=10000)
print(f"历史数据条数：{len(data)}")
```

**建议**：至少收集 **1000-5000** 条数据（对应约200-1000个序列）。

### 选项2：生成合成数据（测试用）

如果没有足够数据，可以用合成数据测试：

```bash
python -c "
from core.train_transformer import generate_synthetic_data
data = generate_synthetic_data(n_samples=5000, anomaly_ratio=0.1)
print(f'生成数据：{len(data)}条')
"
```

---

## 训练模型

### 基本用法

```bash
# 使用默认配置训练（从数据库加载数据）
python -m src.core.train_transformer

# 或使用合成数据
python -m src.core.train_transformer --use-synthetic --synthetic-samples 5000
```

### 常用参数

```bash
# 调整序列长度和批次大小（根据显存）
python -m src.core.train_transformer \
  --seq-len 10 \
  --batch-size 16 \
  --epochs 100 \
  --d-model 64 \
  --num-layers 2

# 指定模型保存路径
python -m src.core.train_transformer \
  --model-save-path models/my_transformer.pth
```

### 完整示例

```bash
# 针对RTX 3050 6GB的优化配置
python -m src.core.train_transformer ^
  --seq-len 10 ^
  --batch-size 32 ^
  --epochs 50 ^
  --d-model 64 ^
  --nhead 4 ^
  --num-layers 2 ^
  --dim-feedforward 128 ^
  --lr 0.001 ^
  --model-save-path models/transformer_detector.pth
```

### 训练输出示例

```
============================================================
轻量级Transformer异常检测器训练
============================================================
配置：
  seq_len: 10
  batch_size: 32
  epochs: 50
  ...
============================================================
📊 从数据库加载历史流量数据...
✅ 加载了 3421 条历史流量记录
📦 准备数据集...
构建数据集：序列数=3412，序列长度=10，特征维度=32
正样本比例：12.34%
🏗️  构建模型...
模型参数量：85,472
使用设备：cuda
🎯 开始训练...
Epoch   1/50: Train Loss=0.4567, Val Loss=0.4123, Val Acc=0.8123, F1=0.5678
  ✓ 保存最佳模型 (F1=0.5678)
...
✅ 训练完成！最佳验证F1：0.7234
📊 评估模型性能...
测试集性能：
  准确率：85.23%
  精确率：78.45%
  召回率：72.34%
  F1分数：75.32%
  AUC：0.8945
📁 评估结果保存到：models/transformer_detector.results.json
```

---

## 评估模型

训练完成后，会自动在测试集上评估。也可以单独评估：

```python
import torch
from core.train_transformer import evaluate_model
from core.transformer_dataset import TransformerDataModule
from core.transformer_detector import TinyTransformer

# 加载数据
data_module = TransformerDataModule(
    feature_vectors=...,
    seq_len=10,
    batch_size=32
)

# 加载模型
checkpoint = torch.load('models/transformer_detector.pth', map_location='cuda')
model = TinyTransformer(**checkpoint['config'])
model.load_state_dict(checkpoint['model_state_dict'])
model.to('cuda')
model.eval()

# 评估
metrics = evaluate_model(model, data_module.test_dataloader(), torch.device('cuda'))
print(metrics)
```

---

## 集成到系统

### 1. 修改检测引擎

编辑 `src/core/detection_engine.py`，在 `HybridDetector` 中添加Transformer检测器：

```python
# 在文件开头添加导入
from .transformer_integration import TransformerDetector

# 修改 HybridDetector.__init__
class HybridDetector:
    def __init__(self, transformer_model_path=None):
        self.rule_detector = RuleMatcher()
        self.ml_detector = MLDetector()
        
        # 新增：Transformer检测器
        if transformer_model_path:
            self.transformer_detector = TransformerDetector(
                model_path=transformer_model_path,
                seq_len=10,
                threshold=0.5
            )
        else:
            self.transformer_detector = None
        
        self.threshold_controller = ThresholdController()
    
    def detect(self, feature_vector: FeatureVector):
        # 原有逻辑...
        rule_alerts = self.rule_detector.match(feature_vector)
        ml_alert, ml_prob = self.ml_detector.predict(feature_vector)
        
        # 新增：Transformer检测（需要维护一个滑动窗口）
        # 需要在DetectionEngine中维护一个特征向量缓冲区
        ...
```

### 2. 维护序列缓冲区

在 `DetectionEngine` 中添加：

```python
class DetectionEngine:
    def __init__(self, transformer_model_path=None):
        ...
        self.transformer_detector = TransformerDetector(transformer_model_path) if transformer_model_path else None
        self.feature_buffer = []  # 滑动窗口缓冲区
        self.buffer_max_len = 20  # 缓冲区大小（>seq_len）
    
    def detect(self, feature_vector: FeatureVector):
        # 更新缓冲区
        self.feature_buffer.append(feature_vector)
        if len(self.feature_buffer) > self.buffer_max_len:
            self.feature_buffer.pop(0)
        
        # 原有检测...
        
        # Transformer检测（如果缓冲区足够）
        if self.transformer_detector and len(self.feature_buffer) >= self.transformer_detector.seq_len:
            # 注意：这里需要异步或批量处理，避免实时性受影响
            pass
```

### 3. 更新 `detection_engine.py` 导出

```python
# 在 detection_engine.py 末尾添加
from .transformer_integration import TransformerDetector, create_transformer_detector

__all__ = [
    'detect_anomalies',
    'train_model',
    'save_model',
    'get_detection_performance',
    'TransformerDetector',  # 新增
    'create_transformer_detector'
]
```

---

## 推理使用

### 独立使用Transformer检测器

```python
from core.transformer_integration import TransformerDetector

# 1. 加载模型
detector = TransformerDetector(
    model_path="models/transformer_detector.pth",
    seq_len=10,
    threshold=0.5
)

# 2. 准备FeatureVector列表（按时间排序）
feature_vectors = [...]  # 从数据库或实时流获取

# 3. 批量预测
results = detector.batch_predict(feature_vectors, batch_size=32)

# 4. 处理结果
for i, (alert, score) in enumerate(results):
    if alert:
        print(f"[{i}] 告警：{alert.alert_type} 风险={score:.1f}")
        print(f"  源IP：{alert.src_ip} → 目的IP：{alert.dst_ip}")
```

### 在Streamlit中集成

修改 `src/streamlit_app.py`：

```python
# 在侧边栏添加选项
with st.sidebar:
    st.header("检测引擎")
    use_transformer = st.checkbox("启用Transformer检测", value=False)
    transformer_threshold = st.slider("Transformer阈值", 0.0, 1.0, 0.5)

# 在主循环中
if use_transformer and 'transformer_detector' in st.session_state:
    # 维护缓冲区
    if 'feature_buffer' not in st.session_state:
        st.session_state.feature_buffer = []
    
    # 添加新特征
    for fv in latest_feature_vectors:
        st.session_state.feature_buffer.append(fv)
        if len(st.session_state.feature_buffer) > 20:
            st.session_state.feature_buffer.pop(0)
    
    # 当缓冲区足够时进行检测
    if len(st.session_state.feature_buffer) >= 10:
        results = st.session_state.transformer_detector.batch_predict(
            st.session_state.feature_buffer[-10:]
        )
        # 显示结果...
```

---

## 云算力申请

如果本地GPU显存不足，可以使用免费云算力训练。

### Google Colab（推荐）

1. **打开Colab**：https://colab.research.google.com
2. **新建Notebook**
3. **设置GPU**：运行时 → 更改运行时类型 → GPU（T4免费）
4. **克隆项目**：

```python
!git clone https://github.com/yourusername/network-anomaly-detector.git
%cd network-anomaly-detector
!pip install -r requirements.txt
!pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

5. **上传数据**（如果需要）：

```python
from google.colab import files
uploaded = files.upload()  # 上传pcap文件或数据库
```

6. **训练模型**：

```python
!python -m src.core.train_transformer --use-synthetic --synthetic-samples 10000 --epochs 100
```

7. **下载模型**：

```python
from google.colab import files
files.download('models/transformer_detector.pth')
```

### Kaggle Notebooks

1. 注册Kaggle：https://www.kaggle.com
2. New Notebook → Add Data（上传数据）→ Accelerator → GPU
3. 类似Colab的操作

### 本地训练显存不足怎么办？

1. **减小batch_size**：`--batch-size 8`
2. **减小模型尺寸**：
   ```bash
   --d-model 32 --num-layers 1 --dim-feedforward 64
   ```
3. **使用CPU**：`--device cpu`（会慢很多）
4. **梯度累积**（修改代码）：每N个batch才更新一次

---

## 故障排除

### 问题1：CUDA out of memory

**症状**：`RuntimeError: CUDA out of memory`

**解决**：
- 减小 `--batch-size`（如从32降到16或8）
- 减小 `--d-model`（如从64降到32）
- 减少 `--num-layers`（如从2降到1）
- 使用 `torch.cuda.empty_cache()` 清理缓存

### 问题2：数据加载错误

**症状**：`IndexError` 或 `ValueError` 在数据集中

**原因**：FeatureVector字段缺失或类型错误

**解决**：
- 检查数据库中的 `extra` 字段是否包含完整的统计/协议/攻击特征
- 或使用合成数据：`--use-synthetic`

### 问题3：模型参数量超过100K

**症状**：断言失败 `assert total_params < 100_000`

**解决**：
- 减小 `d_model`（64→32）
- 减少 `num_layers`（2→1）
- 减小 `dim_feedforward`（128→64）

### 问题4：F1分数低（<50%）

**可能原因**：
1. 数据质量差（标签噪声）
2. 异常样本太少（<5%）
3. 模型欠拟合（增加epochs或模型容量）
4. 序列长度不合适（尝试5-20）

**解决**：
- 增加训练数据量
- 调整类别权重（修改 `criterion = nn.BCELoss(weight=...)`）
- 使用更长的序列（`--seq-len 15`）
- 检查标签质量（规则检测是否准确）

### 问题5：训练速度慢

**优化**：
- 增加 `--batch-size`（如果显存允许）
- 使用 `torch.cuda.amp` 自动混合精度（修改训练代码）
- 减少数据预处理开销（缓存标准化参数）

---

## 性能对比

在RTX 3050上的预期性能：

| 模型 | 参数量 | 训练时间（5K样本） | 推理延迟（单样本） | 显存占用 |
|------|--------|-------------------|-------------------|---------|
| 随机森林 | 50K | - (CPU) | 0.1ms | 0 MB |
| **轻量Transformer** | **85K** | **5-10分钟** | **0.2ms** | **~150MB** |
| BERT-Base | 110M | 数小时 | 5ms | 500MB+ |

---

## 下一步

1. ✅ 训练模型：`python -m src.core.train_transformer`
2. ✅ 评估性能：查看生成的 `.results.json` 文件
3. ✅ 集成到系统：修改 `detection_engine.py`
4. ✅ 更新Streamlit界面：添加Transformer检测选项
5. ✅ 收集反馈：对比规则检测、ML、Transformer的效果

---

## 参考资源

- PyTorch官方教程：https://pytorch.org/tutorials/
- Transformer论文：https://arxiv.org/abs/1706.03762
- 本项目的GitHub仓库：https://github.com/yourusername/network-anomaly-detector

---

**最后更新**：2026-02-14
**适用版本**：v1.0.0