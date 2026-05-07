"""
混合检测引擎：结合规则匹配与机器学习的网络异常检测系统。

模块结构：
1. RuleDetector：规则匹配库（快速检测已知攻击）
2. MLDetector：机器学习模型（检测未知攻击模式）
3. ThresholdController：阈值决策控制（平衡准确率与误报率）
4. HybridDetector：混合检测器（融合两种检测结果）
5. DetectionEngine：检测引擎（统一接口）
"""

from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
import json
import pickle
import os

import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from .custom_types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures
from .sink import Alert
from .transformer_integration import TransformerDetector


class RuleMatcher:
    """
    规则匹配库：快速检测已知攻击模式。
    
    特性：
    - 可配置的规则库
    - 支持规则优先级和权重
    - 快速匹配已知攻击模式
    - 可扩展性强
    """

    def __init__(self, rules_file: Optional[str] = None):
        """
        初始化规则匹配器。
        
        参数：
            rules_file: 规则配置文件路径（可选）
        """
        self.rules = self._load_rules(rules_file)
        self.rule_priority = {
            "syn_flood": 5,
            "ddos": 5,
            "packet_flood": 4,
            "byte_flood": 4,
            "port_scan": 3,
            "udp_flood": 4,
            "icmp_flood": 4,
            "arp_spoof": 5,
            "dns_amplification": 4,
            "slowloris": 3
        }

    def _load_rules(self, rules_file: Optional[str]) -> Dict[str, Dict[str, Any]]:
        """
        加载规则配置。
        """
        default_rules = {
            "syn_flood": {
                "threshold": 50,  # 5秒窗口内SYN包数量阈值
                "description": "SYN 洪水攻击检测",
                "weight": 0.9
            },
            "packet_flood": {
                "threshold": 1000,  # 5秒窗口内总包数阈值
                "description": "数据包洪水攻击检测",
                "weight": 0.8
            },
            "byte_flood": {
                "threshold": 100000,  # 5秒窗口内总字节数阈值
                "description": "字节洪水攻击检测",
                "weight": 0.8
            },
            "port_scan": {
                "threshold": 10,  # 访问的端口数量阈值
                "description": "端口扫描攻击检测",
                "weight": 0.7
            },
            "ddos": {
                "threshold": 0.7,  # DDoS 检测阈值
                "description": "DDoS 攻击检测",
                "weight": 0.95
            },
            "udp_flood": {
                "threshold": 500,  # UDP 包数量阈值
                "description": "UDP 洪水攻击检测",
                "weight": 0.85
            },
            "icmp_flood": {
                "threshold": 200,  # ICMP 包数量阈值
                "description": "ICMP 洪水攻击检测",
                "weight": 0.85
            },
            "arp_spoof": {
                "threshold": 50,  # ARP 包数量阈值
                "description": "ARP 欺骗攻击检测",
                "weight": 0.9
            },
            "dns_amplification": {
                "threshold": 100,  # DNS 包数量阈值
                "description": "DNS 放大攻击检测",
                "weight": 0.8
            },
            "slowloris": {
                "threshold": 50,  # 半开连接数量阈值
                "description": "Slowloris 攻击检测",
                "weight": 0.7
            }
        }

        if rules_file and os.path.exists(rules_file):
            try:
                with open(rules_file, 'r', encoding='utf-8') as f:
                    custom_rules = json.load(f)
                default_rules.update(custom_rules)
            except Exception as e:
                print(f"Error loading rules file: {e}")

        return default_rules

    def match(self, feature_vector: FeatureVector) -> List[Tuple[Alert, float, int]]:
        """
        匹配规则并生成告警。
        
        返回：
            List[Tuple[Alert, float, int]]: [(告警, 权重, 优先级)]
        """
        alerts = []
        stat = feature_vector.statistical
        proto = feature_vector.protocol_features
        attack = feature_vector.attack
        
        # 检测 SYN 洪水
        if stat.syn_count > self.rules["syn_flood"]["threshold"]:
            score = min(100.0, stat.syn_count / self.rules["syn_flood"]["threshold"] * 100)
            weight = self.rules["syn_flood"]["weight"]
            priority = self.rule_priority["syn_flood"]
            alerts.append((Alert(
                timestamp=datetime.now(),
                src_ip=feature_vector.src_ip,
                dst_ip=feature_vector.dst_ip,
                alert_type="SYN Flood",
                score=score,
                detail={
                    "rule": "syn_flood",
                    "syn_count": stat.syn_count,
                    "threshold": self.rules["syn_flood"]["threshold"]
                }
            ), weight, priority))

        # 检测数据包洪水
        if stat.packet_count > self.rules["packet_flood"]["threshold"]:
            score = min(100.0, stat.packet_count / self.rules["packet_flood"]["threshold"] * 100)
            weight = self.rules["packet_flood"]["weight"]
            priority = self.rule_priority["packet_flood"]
            alerts.append((Alert(
                timestamp=datetime.now(),
                src_ip=feature_vector.src_ip,
                dst_ip=feature_vector.dst_ip,
                alert_type="Packet Flood",
                score=score,
                detail={
                    "rule": "packet_flood",
                    "packet_count": stat.packet_count,
                    "threshold": self.rules["packet_flood"]["threshold"]
                }
            ), weight, priority))

        # 检测字节洪水
        if stat.byte_count > self.rules["byte_flood"]["threshold"]:
            score = min(100.0, stat.byte_count / self.rules["byte_flood"]["threshold"] * 100)
            weight = self.rules["byte_flood"]["weight"]
            priority = self.rule_priority["byte_flood"]
            alerts.append((Alert(
                timestamp=datetime.now(),
                src_ip=feature_vector.src_ip,
                dst_ip=feature_vector.dst_ip,
                alert_type="Byte Flood",
                score=score,
                detail={
                    "rule": "byte_flood",
                    "byte_count": stat.byte_count,
                    "threshold": self.rules["byte_flood"]["threshold"]
                }
            ), weight, priority))

        # 检测端口扫描
        if attack.unique_dst_ports > self.rules["port_scan"]["threshold"]:
            score = min(100.0, attack.unique_dst_ports / self.rules["port_scan"]["threshold"] * 100)
            weight = self.rules["port_scan"]["weight"]
            priority = self.rule_priority["port_scan"]
            alerts.append((Alert(
                timestamp=datetime.now(),
                src_ip=feature_vector.src_ip,
                dst_ip=feature_vector.dst_ip,
                alert_type="Port Scan",
                score=score,
                detail={
                    "rule": "port_scan",
                    "unique_dst_ports": attack.unique_dst_ports,
                    "threshold": self.rules["port_scan"]["threshold"]
                }
            ), weight, priority))

        # 检测 DDoS
        if attack.is_ddos or attack.packet_burst_score > self.rules["ddos"]["threshold"]:
            score = max(attack.packet_burst_score * 100, attack.scan_pattern_score * 100)
            weight = self.rules["ddos"]["weight"]
            priority = self.rule_priority["ddos"]
            alerts.append((Alert(
                timestamp=datetime.now(),
                src_ip=feature_vector.src_ip,
                dst_ip=feature_vector.dst_ip,
                alert_type="DDoS Attack",
                score=score,
                detail={
                    "rule": "ddos",
                    "is_ddos": attack.is_ddos,
                    "packet_burst_score": attack.packet_burst_score,
                    "scan_pattern_score": attack.scan_pattern_score
                }
            ), weight, priority))

        return alerts


class MLModel:
    """
    机器学习模型：使用决策树/随机森林检测未知攻击模式。
    
    特性：
    - 支持决策树和随机森林算法
    - 支持模型训练、保存和加载
    - 特征选择和重要性分析
    - 异常概率计算
    """

    def __init__(self, model_type: str = "random_forest", model_path: Optional[str] = None):
        """
        初始化机器学习模型。
        
        参数：
            model_type: 模型类型，"decision_tree" 或 "random_forest"
            model_path: 预训练模型路径
        """
        self.model_type = model_type
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = [
            "packet_count", "byte_count", "avg_pkt_len", "max_pkt_len", "min_pkt_len",
            "std_pkt_len", "packet_rate", "byte_rate", "inter_arrival_time", "syn_count",
            "ack_count", "fin_count", "rst_count", "header_size", "payload_size",
            "ttl_avg", "ttl_min", "ttl_max", "tcp_window_size_avg", "tcp_window_size_max",
            "payload_entropy", "is_fragmented", "is_ddos", "is_port_scan", "is_syn_flood",
            "is_udp_flood", "is_icmp_flood", "connection_count", "unique_dst_ports",
            "unique_src_ips", "packet_burst_score", "scan_pattern_score"
        ]
        
        # 加载预训练模型
        if model_path and os.path.exists(model_path):
            self._load_model(model_path)
        else:
            self._initialize_model()

    def _initialize_model(self):
        """
        初始化模型。
        """
        if self.model_type == "decision_tree":
            self.model = DecisionTreeClassifier(
                max_depth=10,
                random_state=42,
                class_weight="balanced"
            )
        else:  # random_forest
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                random_state=42,
                class_weight="balanced"
            )

    def _load_model(self, model_path: str):
        """
        加载预训练模型。
        """
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.feature_columns = model_data['feature_columns']
                print(f"Model loaded from {model_path}")
        except Exception as e:
            print(f"Error loading model: {e}")
            self._initialize_model()

    def save_model(self, model_path: str):
        """
        保存模型。
        """
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_columns': self.feature_columns
            }
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
            print(f"Model saved to {model_path}")
        except Exception as e:
            print(f"Error saving model: {e}")

    def _feature_row(self, fv: FeatureVector) -> list:
        """提取单条特征行（list），供 extract_features / predict_batch 复用。"""
        stat = fv.statistical
        proto = fv.protocol_features
        attack = fv.attack
        return [
            stat.packet_count, stat.byte_count, stat.avg_pkt_len,
            stat.max_pkt_len, stat.min_pkt_len, stat.std_pkt_len,
            stat.packet_rate, stat.byte_rate, stat.inter_arrival_time,
            stat.syn_count, stat.ack_count, stat.fin_count, stat.rst_count,
            proto.header_size, proto.payload_size,
            proto.ttl_avg, proto.ttl_min, proto.ttl_max,
            proto.tcp_window_size_avg, proto.tcp_window_size_max,
            proto.payload_entropy, int(proto.is_fragmented),
            int(attack.is_ddos), int(attack.is_port_scan),
            int(attack.is_syn_flood), int(attack.is_udp_flood),
            int(attack.is_icmp_flood), attack.connection_count,
            attack.unique_dst_ports, attack.unique_src_ips,
            attack.packet_burst_score, attack.scan_pattern_score,
        ]

    def extract_features(self, feature_vector: FeatureVector) -> np.ndarray:
        """从特征向量中提取机器学习特征（单条，shape=(1, n_features)）。"""
        return np.array(self._feature_row(feature_vector)).reshape(1, -1)

    def predict_batch(
        self, feature_vectors: List[FeatureVector]
    ) -> List[Tuple[Optional[Alert], float]]:
        """
        D1 优化：批量推理，一次 predict_proba 替代 N 次单条推理。
        返回与 feature_vectors 等长的 [(Alert|None, prob)] 列表。
        """
        if not feature_vectors or self.model is None:
            return [(None, 0.0)] * len(feature_vectors)
        try:
            X = np.array([self._feature_row(fv) for fv in feature_vectors], dtype=float)
            X_scaled = self.scaler.transform(X)
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X_scaled)[:, 1]
            else:
                probs = self.model.predict(X_scaled).astype(float)

            results: List[Tuple[Optional[Alert], float]] = []
            for fv, prob in zip(feature_vectors, probs):
                prob = float(prob)
                if prob > 0.5:
                    alert = Alert(
                        timestamp=datetime.now(),
                        src_ip=fv.src_ip,
                        dst_ip=fv.dst_ip,
                        alert_type="ML Anomaly",
                        score=prob * 100,
                        detail={"anomaly_prob": prob, "model_type": self.model_type},
                    )
                    results.append((alert, prob))
                else:
                    results.append((None, prob))
            return results
        except Exception as e:
            print(f"[MLModel.predict_batch] {e}")
            return [(None, 0.0)] * len(feature_vectors)

    def train(self, X: np.ndarray, y: np.ndarray):
        """
        训练模型。
        
        参数：
            X: 特征矩阵
            y: 标签向量
        """
        try:
            # 数据标准化
            X_scaled = self.scaler.fit_transform(X)
            
            # 分割训练集和测试集
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.2, random_state=42
            )
            
            # 训练模型
            self.model.fit(X_train, y_train)
            
            # 评估模型
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            print(f"Model training completed:")
            print(f"Accuracy: {accuracy:.4f}")
            print(f"Precision: {precision:.4f}")
            print(f"Recall: {recall:.4f}")
            print(f"F1 Score: {f1:.4f}")
            
            # 输出特征重要性
            if hasattr(self.model, 'feature_importances_'):
                importances = self.model.feature_importances_
                feature_importance = sorted(
                    zip(self.feature_columns, importances),
                    key=lambda x: x[1],
                    reverse=True
                )
                print("Top 10 important features:")
                for feature, importance in feature_importance[:10]:
                    print(f"{feature}: {importance:.4f}")
                    
        except Exception as e:
            print(f"Error training model: {e}")

    def predict(self, feature_vector: FeatureVector) -> Optional[Tuple[Alert, float]]:
        """
        预测异常。
        
        返回：
            Tuple[Alert, float]: (告警, 置信度)
        """
        try:
            # 提取特征
            features = self.extract_features(feature_vector)
            
            # 数据标准化
            features_scaled = self.scaler.transform(features)
            
            # 预测
            if hasattr(self.model, 'predict_proba'):
                prob = self.model.predict_proba(features_scaled)[0][1]  # 异常概率
            else:
                prob = float(self.model.predict(features_scaled)[0])
            
            # 生成告警
            if prob > 0.5:
                score = prob * 100
                alert = Alert(
                    timestamp=datetime.now(),
                    src_ip=feature_vector.src_ip,
                    dst_ip=feature_vector.dst_ip,
                    alert_type="ML Anomaly",
                    score=score,
                    detail={
                        "anomaly_prob": prob,
                        "model_type": self.model_type,
                        "features": features.tolist()[0]
                    }
                )
                return alert, prob
            
            return None, prob
            
        except Exception as e:
            print(f"Error predicting: {e}")
            return None, 0.0


class ThresholdController:
    """
    阈值决策控制：平衡准确率与误报率。
    
    特性：
    - 动态阈值调整
    - 准确率与误报率平衡
    - 置信度计算
    """

    def __init__(self, initial_threshold: float = 0.7, target_fpr: float = 0.05):
        """
        初始化阈值控制器。
        
        参数：
            initial_threshold: 初始阈值
            target_fpr: 目标误报率
        """
        self.initial_threshold = initial_threshold
        self.current_threshold = initial_threshold
        self.target_fpr = target_fpr
        self.history: List[Dict[str, Any]] = []
        self.min_threshold = 0.5
        self.max_threshold = 0.95

    def adjust_threshold(self, performance: Dict[str, float]):
        """
        根据检测性能调整阈值。
        
        参数：
            performance: 性能指标，包含 fpr, tpr, precision, recall
        """
        fpr = performance.get('fpr', 0.0)
        tpr = performance.get('tpr', 0.0)
        
        # 记录历史
        self.history.append({
            'threshold': self.current_threshold,
            'fpr': fpr,
            'tpr': tpr,
            'timestamp': datetime.now()
        })
        
        # 调整阈值
        if fpr > self.target_fpr:
            # 误报率过高，提高阈值
            self.current_threshold = min(
                self.max_threshold,
                self.current_threshold + 0.05
            )
        elif fpr < self.target_fpr * 0.5 and tpr < 0.9:
            # 误报率过低但召回率也低，降低阈值
            self.current_threshold = max(
                self.min_threshold,
                self.current_threshold - 0.05
            )
        
        # 限制阈值范围
        self.current_threshold = max(self.min_threshold, min(self.max_threshold, self.current_threshold))
        
        return self.current_threshold

    def calculate_confidence(self, alert: Alert, detector_type: str) -> float:
        """
        计算告警的置信度。
        
        参数：
            alert: 告警对象
            detector_type: 检测器类型（"rule" 或 "ml"）
        """
        base_confidence = alert.score / 100.0
        
        # 根据检测器类型调整置信度
        if detector_type == "rule":
            # 规则检测的置信度
            confidence = base_confidence * 0.9
        else:
            # 机器学习检测的置信度
            confidence = base_confidence * 0.85
        
        # 根据告警类型调整置信度
        high_confidence_types = ["SYN Flood", "DDoS Attack", "ARP Spoof"]
        if alert.alert_type in high_confidence_types:
            confidence = min(1.0, confidence * 1.1)
        
        return confidence

    def get_threshold(self) -> float:
        """
        获取当前阈值。
        """
        return self.current_threshold

    def reset_threshold(self):
        """
        重置阈值。
        """
        self.current_threshold = self.initial_threshold


class DetectionEngine:
    """
    检测引擎：统一的检测接口。
   
    特性：
     - 集成规则匹配、机器学习和Transformer检测
     - 融合检测结果
     - 提供统一的检测接口
    """
    def __init__(self, rules_file: Optional[str] = None, model_path: Optional[str] = None, transformer_model_path: Optional[str] = None):
       """
       初始化检测引擎。
       
       参数：
           rules_file: 规则配置文件路径
           model_path: 预训练ML模型路径
           transformer_model_path: 预训练Transformer模型路径
       """
       self.rule_matcher = RuleMatcher(rules_file)
       self.ml_model = MLModel(model_path=model_path)
       self.transformer_detector = TransformerDetector(model_path=transformer_model_path) if transformer_model_path else None
       self.threshold_controller = ThresholdController()
       self.detection_history: List[Dict[str, Any]] = []
       
       # 用于Transformer序列缓冲
       self.feature_buffer: List[FeatureVector] = []
       self.buffer_max_len = 20  # 缓冲区大小，应大于seq_len

    def detect(self, feature_vector: FeatureVector) -> Optional[Alert]:
        """
        检测异常。
       
        参数：
            feature_vector: 特征向量
       
        返回：
            Alert: 检测到的告警
        """
        # 规则检测
        rule_alerts = self.rule_matcher.match(feature_vector)

        
        # 机器学习检测
        ml_alert, ml_prob = self.ml_model.predict(feature_vector)
        
        # Transformer检测（如果启用）
        transformer_alert = None
        if self.transformer_detector:
            # 更新缓冲区
            self.feature_buffer.append(feature_vector)
            if len(self.feature_buffer) > self.buffer_max_len:
                self.feature_buffer.pop(0)
            
            # 如果缓冲区足够，进行Transformer检测
            if len(self.feature_buffer) >= self.transformer_detector.seq_len:
                # 注意：这里应该异步或批量处理，避免实时性受影响
                # 简单实现：只对最新序列检测
                recent_buffer = self.feature_buffer[-self.transformer_detector.seq_len:]
                # 使用batch_predict获取结果
                results = self.transformer_detector.batch_predict([recent_buffer])
                if results:
                    alert, score = results[0]
                    if alert:
                        transformer_alert = (alert, score, 0.85, 4, "transformer")
        
        # 收集所有告警
        all_alerts = []
        
        # 处理规则告警
        for alert, weight, priority in rule_alerts:
            confidence = self.threshold_controller.calculate_confidence(alert, "rule")
            all_alerts.append((alert, confidence, weight, priority, "rule"))
        
        # 处理机器学习告警
        if ml_alert:
            confidence = self.threshold_controller.calculate_confidence(ml_alert, "ml")
            all_alerts.append((ml_alert, confidence, 0.8, 3, "ml"))
        
        # 处理Transformer告警
        if transformer_alert:
            alert, score, weight, priority, det_type = transformer_alert
            confidence = self.threshold_controller.calculate_confidence(alert, "transformer")
            all_alerts.append((alert, confidence, weight, priority, "transformer"))
        
        # 融合告警
        if all_alerts:
            # 按优先级和置信度排序
            all_alerts.sort(key=lambda x: (x[3], x[1]), reverse=True)
            
            # 选择最佳告警
            best_alert, best_confidence, best_weight, _, detector_type = all_alerts[0]
            
            # 应用阈值
            if best_confidence >= self.threshold_controller.get_threshold():
                # 增强告警信息
                best_alert.detail.update({
                    "confidence": best_confidence,
                    "detector_type": detector_type,
                    "threshold": self.threshold_controller.get_threshold()
                })
                
                # 记录检测历史
                self.detection_history.append({
                    'alert': best_alert,
                    'confidence': best_confidence,
                    'detector_type': detector_type,
                    'timestamp': datetime.now()
                })
                
                return best_alert
        
        return None

    def batch_detect(self, feature_vectors: List[FeatureVector]) -> List[Alert]:
        """
        批量检测（D1 优化版）。

        流程：
        1. 规则匹配：逐条（快速，无法向量化）
        2. ML 推理：一次 predict_proba 批量完成，替代 N 次单条调用
        3. 融合：规则优先，ML 补充
        """
        if not feature_vectors:
            return []

        threshold = self.threshold_controller.get_threshold()
        alerts: List[Alert] = []

        # --- 步骤 1：批量 ML 推理 ---
        ml_results = self.ml_model.predict_batch(feature_vectors)

        # --- 步骤 2：逐条规则匹配 + 融合 ---
        for fv, (ml_alert, ml_prob) in zip(feature_vectors, ml_results):
            rule_alerts = self.rule_matcher.match(fv)

            all_candidates: List[Tuple[Alert, float, float, int, str]] = []

            for alert, weight, priority in rule_alerts:
                confidence = self.threshold_controller.calculate_confidence(alert, "rule")
                all_candidates.append((alert, confidence, weight, priority, "rule"))

            if ml_alert:
                confidence = self.threshold_controller.calculate_confidence(ml_alert, "ml")
                all_candidates.append((ml_alert, confidence, 0.8, 3, "ml"))

            if not all_candidates:
                continue

            all_candidates.sort(key=lambda x: (x[3], x[1]), reverse=True)
            best_alert, best_confidence, _, _, detector_type = all_candidates[0]

            if best_confidence >= threshold:
                best_alert.detail.update({
                    "confidence": best_confidence,
                    "detector_type": detector_type,
                    "threshold": threshold,
                })
                self.detection_history.append({
                    "alert": best_alert,
                    "confidence": best_confidence,
                    "detector_type": detector_type,
                    "timestamp": datetime.now(),
                })
                alerts.append(best_alert)

        # 调整阈值
        if alerts:
            self.threshold_controller.adjust_threshold(
                {"fpr": 0.05, "tpr": 0.9, "precision": 0.85, "recall": 0.9}
            )

        return alerts

    def train_model(self, X: np.ndarray, y: np.ndarray):
        """
        训练机器学习模型。
        
        参数：
            X: 特征矩阵
            y: 标签向量
        """
        self.ml_model.train(X, y)

    def save_model(self, model_path: str):
        """
        保存机器学习模型。
        
        参数：
            model_path: 模型保存路径
        """
        self.ml_model.save_model(model_path)

    def get_performance(self) -> Dict[str, Any]:
        """
        获取检测性能。
        
        返回：
            Dict[str, Any]: 性能指标
        """
        if not self.detection_history:
            return {
                'total_detections': 0,
                'total_alerts': 0,
                'rule_alerts': 0,
                'ml_alerts': 0,
                'transformer_alerts': 0,
                'current_threshold': self.threshold_controller.get_threshold()
            }
        
        # 计算性能指标
        total_detections = len(self.detection_history)
        total_alerts = sum(1 for h in self.detection_history if h['alert'])
        rule_alerts = sum(1 for h in self.detection_history if h['detector_type'] == 'rule')
        ml_alerts = sum(1 for h in self.detection_history if h['detector_type'] == 'ml')
        transformer_alerts = sum(1 for h in self.detection_history if h['detector_type'] == 'transformer')
        
        return {
            'total_detections': total_detections,
            'total_alerts': total_alerts,
            'rule_alerts': rule_alerts,
            'ml_alerts': ml_alerts,
            'transformer_alerts': transformer_alerts,
            'current_threshold': self.threshold_controller.get_threshold(),
            'detection_rate': total_alerts / total_detections if total_detections > 0 else 0.0
        }


# 全局检测引擎实例（默认不加载Transformer）
detection_engine = DetectionEngine()


def detect_anomalies(feature_vectors: List[FeatureVector]) -> List[Alert]:
    """
    批量检测异常。
    
    参数：
        feature_vectors: 特征向量列表
    
    返回：
        List[Alert]: 检测到的告警列表
    """
    return detection_engine.batch_detect(feature_vectors)


def init_detection_engine(
    rules_file: Optional[str] = None,
    model_path: Optional[str] = None,
    transformer_model_path: Optional[str] = None
) -> DetectionEngine:
    """
    初始化带Transformer的检测引擎。
    
    参数：
        rules_file: 规则配置文件路径
        model_path: ML模型路径
        transformer_model_path: Transformer模型路径
    
    返回：
        DetectionEngine实例
    """
    global detection_engine
    detection_engine = DetectionEngine(
        rules_file=rules_file,
        model_path=model_path,
        transformer_model_path=transformer_model_path
    )
    return detection_engine


def train_model(X: np.ndarray, y: np.ndarray):
    """
    训练机器学习模型。
    
    参数：
        X: 特征矩阵
        y: 标签向量
    """
    detection_engine.train_model(X, y)


def save_model(model_path: str):
    """
    保存机器学习模型。
    
    参数：
        model_path: 模型保存路径
    """
    detection_engine.save_model(model_path)


def get_detection_performance() -> Dict[str, Any]:
    """
    获取检测性能。
    
    返回：
        Dict[str, Any]: 性能指标
    """
    return detection_engine.get_performance()
