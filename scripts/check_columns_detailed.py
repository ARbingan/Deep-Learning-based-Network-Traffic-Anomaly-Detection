import pandas as pd

csv_path = 'MachineLearningCSV/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv'
df = pd.read_csv(csv_path)

print("所有列名（带空格）:")
for i, col in enumerate(df.columns):
    print(f"{i:2d}: {repr(col)}")

print("\n\n查找包含'IP'的列:")
for col in df.columns:
    if 'ip' in col.lower():
        print(f"  {repr(col)}")

print("\n\n查找包含'Port'的列:")
for col in df.columns:
    if 'port' in col.lower():
        print(f"  {repr(col)}")

print("\n\n查找包含'Address'的列:")
for col in df.columns:
    if 'address' in col.lower():
        print(f"  {repr(col)}")

print("\n\n前5行数据:")
print(df.head())
