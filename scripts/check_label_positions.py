"""检查标签分布和位置"""
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# 加载数据
with open('data/cicids_all_features_v2.pkl', 'rb') as f:
    all_fvs = pickle.load(f)

# 创建标签
labels = []
for fv in all_fvs:
    label = fv.extra.get('original_label', 'UNKNOWN')
    is_anomaly = 0 if label.upper() == 'BENIGN' else 1
    labels.append(is_anomaly)

print(f"总样本数: {len(labels)}")
print(f"正常样本数: {labels.count(0)}")
print(f"异常样本数: {labels.count(1)}")

# 查找第一个异常样本的位置
first_anomaly_idx = None
for i, label in enumerate(labels):
    if label == 1:
        first_anomaly_idx = i
        break

print(f"\n第一个异常样本的索引: {first_anomaly_idx}")

if first_anomaly_idx:
    print(f"前{first_anomaly_idx}个样本都是正常的")
    print(f"从索引{first_anomaly_idx}开始出现异常")
    print(f"前110个样本的标签: {labels[:110]}")

    # 统计前1000个样本中的异常数量
    first_1000_anomalies = sum(labels[:1000])
    print(f"\n前1000个样本中异常数量: {first_1000_anomalies}")
