"""验证转换后的数据"""
import pickle
from collections import Counter
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

# 加载数据
with open('data/cicids_all_features.pkl', 'rb') as f:
    feature_vectors = pickle.load(f)

print(f"总样本数: {len(feature_vectors)}")

# 检查标签分布
labels = [fv.extra.get('original_label', 'UNKNOWN') for fv in feature_vectors]
label_counts = Counter(labels)

print("\n标签分布:")
for label, count in label_counts.most_common():
    print(f"  {label}: {count} ({count/len(feature_vectors)*100:.2f}%)")

# 检查二分类标签（正常 vs 异常）
normal_count = sum(1 for label in labels if label.upper() == 'BENIGN')
anomaly_count = len(feature_vectors) - normal_count
print(f"\n二分类:")
print(f"  正常 (BENIGN): {normal_count} ({normal_count/len(feature_vectors)*100:.2f}%)")
print(f"  异常 (非BENIGN): {anomaly_count} ({anomaly_count/len(feature_vectors)*100:.2f}%)")

# 检查特征向量维度
sample_fv = feature_vectors[0]
print(f"\n单个FeatureVector结构检查:")
print(f"  src_ip: {sample_fv.src_ip}")
print(f"  dst_ip: {sample_fv.dst_ip}")
print(f"  protocol: {sample_fv.protocol}")
print(f"  statistical: {sample_fv.statistical}")
print(f"  attack: {sample_fv.attack}")

# 提取特征向量
from src.core.transformer_dataset import extract_feature_vector
import numpy as np

features = extract_feature_vector(sample_fv)
print(f"\n提取的特征向量维度: {features.shape}")
print(f"特征值范围: [{features.min():.4f}, {features.max():.4f}]")
