"""调试训练数据问题"""
import pickle
import sys
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.custom_types import FeatureVector
from src.core.transformer_dataset import TransformerTrafficDataset, extract_feature_vector

# 加载数据
with open('data/cicids_all_features_v2.pkl', 'rb') as f:
    all_fvs = pickle.load(f)

print(f"总样本数: {len(all_fvs)}")

# 创建标签
labels = []
for fv in all_fvs:
    label = fv.extra.get('original_label', 'UNKNOWN')
    is_anomaly = 0 if label.upper() == 'BENIGN' else 1
    labels.append(is_anomaly)

print(f"标签分布: 正常={labels.count(0)}, 异常={labels.count(1)}")

# 测试创建数据集（小样本）
print("\n创建测试数据集（100个样本）...")
test_fvs = all_fvs[:100]
test_labels = labels[:100]

try:
    dataset = TransformerTrafficDataset(
        feature_vectors=test_fvs,
        seq_len=10,
        stride=1,
        labels=test_labels,
        use_rule_labels=False
    )
    print(f"数据集创建成功，序列数: {len(dataset)}")

    # 检查一个样本
    x, y = dataset[0]
    print(f"\n第一个样本:")
    print(f"  x shape: {x.shape}")
    print(f"  x min/max: {x.min():.4f} / {x.max():.4f}")
    print(f"  y: {y.item()}")
    print(f"  y是否在[0,1]: {0 <= y.item() <= 1}")

    # 检查是否有NaN或Inf
    if np.any(np.isnan(x.numpy())):
        print("  [ERROR] x包含NaN!")
    if np.any(np.isinf(x.numpy())):
        print("  [ERROR] x包含Inf!")
    if np.isnan(y.item()):
        print("  [ERROR] y是NaN!")
    if np.isinf(y.item()):
        print("  [ERROR] y是Inf!")

    # 检查所有样本
    print("\n检查所有序列的标签范围:")
    all_ys = []
    for i in range(min(100, len(dataset))):
        _, y_i = dataset[i]
        all_ys.append(y_i.item())
    print(f"  y min: {min(all_ys)}, max: {max(all_ys)}")
    print(f"  唯一值: {set(all_ys)}")

except Exception as e:
    print(f"[ERROR] 创建数据集失败: {e}")
    import traceback
    traceback.print_exc()
