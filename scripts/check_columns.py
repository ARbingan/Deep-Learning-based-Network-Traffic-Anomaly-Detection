import pandas as pd

df = pd.read_csv('MachineLearningCSV/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv')
print("列名（前30个）:")
for i, col in enumerate(df.columns[:30]):
    print(f'{i}: {repr(col)}')

print("\n所有列名:")
for i, col in enumerate(df.columns):
    print(f'{i}: {repr(col)}')
