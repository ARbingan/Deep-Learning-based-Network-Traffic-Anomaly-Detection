"""
数据库模块：用于存储和查询历史日志与流量数据。

使用 SQLite 作为本地数据库，方便部署和使用。
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from .sink import Alert
from .types import FeatureVector, ParsedPacket


class DatabaseManager:
    """
    数据库管理器：负责数据库的初始化、连接和操作。
    """

    def __init__(self, db_path: str = "data/traffic_analyzer.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """
        初始化数据库表结构。
        """
        with sqlite3.connect(self.db_path) as conn:
            init = conn.cursor()

            # 创建告警表
            init.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                alert_type TEXT NOT NULL,
                score REAL NOT NULL,
                detail TEXT NOT NULL
            )
            ''')

            # 创建流量特征表
            init.execute('''
            CREATE TABLE IF NOT EXISTS traffic_features (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                window_start REAL NOT NULL,
                window_end REAL NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                packet_count INTEGER NOT NULL,
                byte_count INTEGER NOT NULL,
                avg_pkt_len REAL NOT NULL,
                max_pkt_len INTEGER NOT NULL,
                min_pkt_len INTEGER NOT NULL,
                std_pkt_len REAL NOT NULL,
                packet_rate REAL NOT NULL,
                byte_rate REAL NOT NULL,
                inter_arrival_time REAL NOT NULL,
                syn_count INTEGER NOT NULL,
                ack_count INTEGER NOT NULL,
                fin_count INTEGER NOT NULL,
                rst_count INTEGER NOT NULL,
                header_size INTEGER NOT NULL,
                payload_size INTEGER NOT NULL,
                ttl_avg REAL NOT NULL,
                ttl_min INTEGER NOT NULL,
                ttl_max INTEGER NOT NULL,
                tcp_window_size_avg REAL NOT NULL,
                tcp_window_size_max INTEGER NOT NULL,
                payload_entropy REAL NOT NULL,
                is_fragmented INTEGER NOT NULL,
                is_ddos INTEGER NOT NULL,
                is_port_scan INTEGER NOT NULL,
                is_syn_flood INTEGER NOT NULL,
                is_udp_flood INTEGER NOT NULL,
                is_icmp_flood INTEGER NOT NULL,
                connection_count INTEGER NOT NULL,
                unique_dst_ports INTEGER NOT NULL,
                unique_src_ips INTEGER NOT NULL,
                packet_burst_score REAL NOT NULL,
                scan_pattern_score REAL NOT NULL,
                extra TEXT
            )
            ''')

            # 创建原始数据包表（可选，用于存储关键数据包）
            init.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                length INTEGER NOT NULL,
                tcp_flags TEXT,
                ttl INTEGER,
                payload_len INTEGER
            )
            ''')

            conn.commit()

    def insert_alert(self, alert: Alert):
        """
        插入告警记录。
        """
        with sqlite3.connect(self.db_path) as conn:
            insert = conn.cursor()
            insert.execute(
                '''
                INSERT INTO alerts (timestamp, src_ip, dst_ip, alert_type, score, detail)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (
                    alert.timestamp.isoformat(),
                    alert.src_ip,
                    alert.dst_ip,
                    alert.alert_type,
                    alert.score,
                    json.dumps(alert.detail, ensure_ascii=False)
                )
            )
            conn.commit()

    def insert_feature_vector(self, feature_vector: FeatureVector):
        """
        插入流量特征记录。
        """
        stat = feature_vector.statistical
        proto = feature_vector.protocol_features
        attack = feature_vector.attack
        
        with sqlite3.connect(self.db_path) as conn:
            insert = conn.cursor()
            insert.execute(
                '''
                INSERT INTO traffic_features (
                    window_start, window_end, src_ip, dst_ip, src_port, dst_port, protocol,
                    packet_count, byte_count, avg_pkt_len, max_pkt_len, min_pkt_len, std_pkt_len,
                    packet_rate, byte_rate, inter_arrival_time, syn_count, ack_count, fin_count, rst_count,
                    header_size, payload_size, ttl_avg, ttl_min, ttl_max,
                    tcp_window_size_avg, tcp_window_size_max, payload_entropy, is_fragmented,
                    is_ddos, is_port_scan, is_syn_flood, is_udp_flood, is_icmp_flood,
                    connection_count, unique_dst_ports, unique_src_ips, packet_burst_score, scan_pattern_score,
                    extra
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    feature_vector.window_start,
                    feature_vector.window_end,
                    feature_vector.src_ip,
                    feature_vector.dst_ip,
                    feature_vector.src_port,
                    feature_vector.dst_port,
                    feature_vector.protocol,
                    stat.packet_count,
                    stat.byte_count,
                    stat.avg_pkt_len,
                    stat.max_pkt_len,
                    stat.min_pkt_len,
                    stat.std_pkt_len,
                    stat.packet_rate,
                    stat.byte_rate,
                    stat.inter_arrival_time,
                    stat.syn_count,
                    stat.ack_count,
                    stat.fin_count,
                    stat.rst_count,
                    proto.header_size,
                    proto.payload_size,
                    proto.ttl_avg,
                    proto.ttl_min,
                    proto.ttl_max,
                    proto.tcp_window_size_avg,
                    proto.tcp_window_size_max,
                    proto.payload_entropy,
                    int(proto.is_fragmented),
                    int(attack.is_ddos),
                    int(attack.is_port_scan),
                    int(attack.is_syn_flood),
                    int(attack.is_udp_flood),
                    int(attack.is_icmp_flood),
                    attack.connection_count,
                    attack.unique_dst_ports,
                    attack.unique_src_ips,
                    attack.packet_burst_score,
                    attack.scan_pattern_score,
                    json.dumps(feature_vector.extra, ensure_ascii=False)
                )
            )
            conn.commit()

    def insert_packet(self, packet: ParsedPacket):
        """
        插入原始数据包记录。
        """
        with sqlite3.connect(self.db_path) as conn:
            insert = conn.cursor()
            insert.execute(
                '''
                INSERT INTO packets (
                    timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                    length, tcp_flags, ttl, payload_len
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    packet.timestamp,
                    packet.src_ip,
                    packet.dst_ip,
                    packet.src_port,
                    packet.dst_port,
                    packet.protocol,
                    packet.length,
                    packet.tcp_flags,
                    packet.ttl,
                    packet.payload_len
                )
            )
            conn.commit()

    def get_alerts(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        获取告警记录。
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            select = conn.cursor()
            select.execute(
                '''
                SELECT * FROM alerts
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                ''',
                (limit, offset)
            )
            rows = select.fetchall()
            return [dict(row) for row in rows]

    def get_alerts_by_time_range(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """
        根据时间范围获取告警记录。
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            select = conn.cursor()
            select.execute(
                '''
                SELECT * FROM alerts
                WHERE timestamp >= ? AND timestamp <= ?
                ORDER BY timestamp DESC
                ''',
                (start_time.isoformat(), end_time.isoformat())
            )
            rows = select.fetchall()
            return [dict(row) for row in rows]

    def get_alerts_by_type(self, alert_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        根据告警类型获取告警记录。
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            select = conn.cursor()
            select.execute(
                '''
                SELECT * FROM alerts
                WHERE alert_type = ?
                ORDER BY timestamp DESC
                LIMIT ?
                ''',
                (alert_type, limit)
            )
            rows = select.fetchall()
            return [dict(row) for row in rows]

    def get_traffic_features(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        获取流量特征记录。
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            select = conn.cursor()
            select.execute(
                '''
                SELECT * FROM traffic_features
                ORDER BY window_start DESC
                LIMIT ? OFFSET ?
                ''',
                (limit, offset)
            )
            rows = select.fetchall()
            return [dict(row) for row in rows]

    def get_traffic_features_by_ip(self, ip: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        根据 IP 地址获取流量特征记录。
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            select = conn.cursor()
            select.execute(
                '''
                SELECT * FROM traffic_features
                WHERE src_ip = ? OR dst_ip = ?
                ORDER BY window_start DESC
                LIMIT ?
                ''',
                (ip, ip, limit)
            )
            rows = select.fetchall()
            return [dict(row) for row in rows]

    def get_packets(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        获取原始数据包记录。
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            select = conn.cursor()
            select.execute(
                '''
                SELECT * FROM packets
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                ''',
                (limit, offset)
            )
            rows = select.fetchall()
            return [dict(row) for row in rows]

    def get_packets_by_ip(self, ip: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        根据 IP 地址获取原始数据包记录。
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            select = conn.cursor()
            select.execute(
                '''
                SELECT * FROM packets
                WHERE src_ip = ? OR dst_ip = ?
                ORDER BY timestamp DESC
                LIMIT ?
                ''',
                (ip, ip, limit)
            )
            rows = select.fetchall()
            return [dict(row) for row in rows]


# 全局数据库管理器实例
db_manager = DatabaseManager()


def store_alert(alert: Alert):
    """
    存储告警到数据库。
    """
    db_manager.insert_alert(alert)


def store_feature_vector(feature_vector: FeatureVector):
    """
    存储流量特征到数据库。
    """
    db_manager.insert_feature_vector(feature_vector)


def store_packet(packet: ParsedPacket):
    """
    存储原始数据包到数据库。
    """
    db_manager.insert_packet(packet)


def get_historical_alerts(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """
    获取历史告警记录。
    """
    return db_manager.get_alerts(limit, offset)


def get_historical_traffic(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """
    获取历史流量特征记录。
    """
    return db_manager.get_traffic_features(limit, offset)
