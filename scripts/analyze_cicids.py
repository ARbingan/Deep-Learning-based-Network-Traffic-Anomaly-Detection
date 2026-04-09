"""
分析CICIDS2017数据集结构
"""
import pandas as pd
from pathlib import Path

data_dir = Path('MachineLearningCSV/MachineLearningCVE')

files = [
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
]

for f in files:
    filepath = data_dir / f
    if filepath.exists():
        df = pd.read_csv(filepath)
        print(f"\n{'='*60}")
        print(f"文件: {f}")
        print(f"形状: {df.shape}")
        print(f"标签分布:")
        try:
            print(df[' Label'].value_counts())
        except Exception as e:
            print(f"错误: {e}")
            print(f"实际列名: {[c for c in df.columns if 'abel' in c.lower()]}")
    else:
        print(f"文件不存在: {filepath}")
