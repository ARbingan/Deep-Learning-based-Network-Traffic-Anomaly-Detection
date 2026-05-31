import sys
sys.path.insert(0, 'src')
from core.detection_engine import detection_engine
print('检测引擎初始化成功')
print(f'Transformer 已加载: {detection_engine.transformer_detector is not None}')
if detection_engine.transformer_detector:
    print(f'Transformer seq_len: {detection_engine.transformer_detector.seq_len}')
