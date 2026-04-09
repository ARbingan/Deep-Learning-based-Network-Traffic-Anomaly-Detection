import pandas as pd

csv_path = 'MachineLearningCSV/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv'
df = pd.read_csv(csv_path)

print("查看前3行数据，了解实际内容:")
print(df.head(3).to_string())

print("\n\n列名列表（按索引）:")
for i, col in enumerate(df.columns):
    print(f"{i:2d}: {col}")

print("\n\n是否有Timestamp列?")
print([col for col in df.columns if 'timestamp' in col.lower() or 'time' in col.lower()])

print("\n\n数据形状:", df.shape)
print("数据类型统计:")
print(df.dtypes.value_counts())
