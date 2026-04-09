"""检查CICIDS标签的实际值"""
import pandas as pd

csv_path = 'MachineLearningCSV/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv'
df = pd.read_csv(csv_path)

print("Tuesday文件的标签值:")
unique_labels = df[' Label'].unique()
for label in unique_labels:
    print(f"  '{label}'")

print("\n检查攻击类型匹配:")
for label in unique_labels:
    label_upper = label.upper()
    print(f"\n{label} -> upper: {label_upper}")
    print(f"  'DDOS' in: {'DDOS' in label_upper}")
    print(f"  'PortScan' in: {'PORTSCAN' in label_upper or 'PortScan' in label_upper}")
    print(f"  'FTP-PATATOR' in: {'FTP-PATATOR' in label_upper}")
    print(f"  'SSH-PATATOR' in: {'SSH-PATATOR' in label_upper}")
    print(f"  'SYN' in: {'SYN' in label_upper}")
    print(f"  'DoS' in: {'DOS' in label_upper or 'DoS' in label_upper}")
