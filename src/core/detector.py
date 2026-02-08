"""
检测模块：规则匹配与机器学习模型。

- 输入：FeatureVector 序列
- 输出：Alert 序列
"""

from datetime import datetime
from typing import List, Optional, Dict, Any

from .types import FeatureVector
from .sink import Alert


class RuleDetector:
    """
    规则检测器：基于阈值和规则的异常检测。
    """

    def __init__(self):
        # 规则配置
        self.rules = {
            "syn_flood": {
                "threshold": 50,  # 5秒窗口内SYN包数量阈值
                "description": "SYN 洪水攻击检测"
            },
            "packet_flood": {
                "threshold": 1000,  # 5秒窗口内总包数阈值
                "description": "数据包洪水攻击检测"
            },
            "byte_flood": {
                "threshold": 100000,  # 5秒窗口内总字节数阈值
                "description": "字节洪水攻击检测"
            }
        }

    def detect(self, feature_vector: FeatureVector) -> Optional[Alert]:
        """
        基于规则检测异常。
        """
        alerts = []

        # 检测 SYN 洪水
        if feature_vector.syn_count > self.rules["syn_flood"]["threshold"]:
            score = min(100.0, feature_vector.syn_count / self.rules["syn_flood"]["threshold"] * 100)
            alerts.append(Alert(
                timestamp=datetime.now(),
                src_ip=feature_vector.src_ip,
                dst_ip=feature_vector.dst_ip,
                alert_type="SYN Flood",
                score=score,
                detail={
                    "rule": "syn_flood",
                    "syn_count": feature_vector.syn_count,
                    "threshold": self.rules["syn_flood"]["threshold"]
                }
            ))

        # 检测数据包洪水
        if feature_vector.packet_count > self.rules["packet_flood"]["threshold"]:
            score = min(100.0, feature_vector.packet_count / self.rules["packet_flood"]["threshold"] * 100)
            alerts.append(Alert(
                timestamp=datetime.now(),
                src_ip=feature_vector.src_ip,
                dst_ip=feature_vector.dst_ip,
                alert_type="Packet Flood",
                score=score,
                detail={
                    "rule": "packet_flood",
                    "packet_count": feature_vector.packet_count,
                    "threshold": self.rules["packet_flood"]["threshold"]
                }
            ))

        # 检测字节洪水
        if feature_vector.byte_count > self.rules["byte_flood"]["threshold"]:
            score = min(100.0, feature_vector.byte_count / self.rules["byte_flood"]["threshold"] * 100)
            alerts.append(Alert(
                timestamp=datetime.now(),
                src_ip=feature_vector.src_ip,
                dst_ip=feature_vector.dst_ip,
                alert_type="Byte Flood",
                score=score,
                detail={
                    "rule": "byte_flood",
                    "byte_count": feature_vector.byte_count,
                    "threshold": self.rules["byte_flood"]["threshold"]
                }
            ))

        # 返回风险分数最高的告警
        if alerts:
            return max(alerts, key=lambda x: x.score)
        return None


class MLDetector:
    """
    机器学习检测器：基于决策树/随机森林的异常检测。
    
    注意：当前为简化实现，实际应用中需要训练模型。
    """

    def __init__(self):
        # 模拟模型，实际应用中需要加载训练好的模型
        self.threshold = 0.7  # 异常概率阈值

    def detect(self, feature_vector: FeatureVector) -> Optional[Alert]:
        """
        基于机器学习模型检测异常。
        
        简化实现：基于特征向量计算异常概率
        """
        # 计算异常概率（简化实现）
        features = [
            feature_vector.packet_count,
            feature_vector.byte_count,
            feature_vector.avg_pkt_len,
            feature_vector.max_pkt_len,
            feature_vector.syn_count
        ]

        # 简化的异常概率计算
        # 实际应用中应该使用训练好的模型
        anomaly_prob = min(1.0, (
            feature_vector.packet_count / 1000 +
            feature_vector.byte_count / 100000 +
            feature_vector.syn_count / 50
        ))

        if anomaly_prob > self.threshold:
            score = anomaly_prob * 100
            return Alert(
                timestamp=datetime.now(),
                src_ip=feature_vector.src_ip,
                dst_ip=feature_vector.dst_ip,
                alert_type="ML Anomaly",
                score=score,
                detail={
                    "anomaly_prob": anomaly_prob,
                    "threshold": self.threshold,
                    "features": features
                }
            )
        return None


class HybridDetector:
    """
    混合检测器：结合规则检测和机器学习检测。
    """

    def __init__(self):
        self.rule_detector = RuleDetector()
        self.ml_detector = MLDetector()

    def detect(self, feature_vector: FeatureVector) -> Optional[Alert]:
        """
        混合检测：先规则，后机器学习，取最高风险分数。
        """
        rule_alert = self.rule_detector.detect(feature_vector)
        ml_alert = self.ml_detector.detect(feature_vector)

        # 收集所有告警
        alerts = []
        if rule_alert:
            alerts.append(rule_alert)
        if ml_alert:
            alerts.append(ml_alert)

        # 返回风险分数最高的告警
        if alerts:
            return max(alerts, key=lambda x: x.score)
        return None


def detect_anomalies(feature_vectors: List[FeatureVector]) -> List[Alert]:
    """
    批量检测异常。
    """
    detector = HybridDetector()
    alerts = []

    for fv in feature_vectors:
        alert = detector.detect(fv)
        if alert:
            alerts.append(alert)

    return alerts
