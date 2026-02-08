"""
基于 Streamlit 的前端可视化中心。

当前实现了一条完整的数据流（离线 pcap）：
Source → Parser → Feature → （后续 Detection）→ Sink / 可视化。
"""

import pathlib
from typing import List

import pandas as pd
import streamlit as st

import threading
import time
from core.source import pcap_source, live_source, get_available_interfaces, CaptureConfig
from core.parser import parse_packet
from core.feature_extractor import extract_features
from core.detector import detect_anomalies
from core.sink import log_alert, print_alert
from core.database import store_alert, store_feature_vector, store_packet, get_historical_alerts, get_historical_traffic
from core.types import ParsedPacket, FeatureVector, PacketEvent


st.set_page_config(
    page_title="Scapy 网络异常流量检测器",
    layout="wide",
)

# 初始化会话状态
if 'capture_running' not in st.session_state:
    st.session_state.capture_running = False
if 'captured_packets' not in st.session_state:
    st.session_state.captured_packets = []
if 'last_update' not in st.session_state:
    st.session_state.last_update = time.time()

st.title("基于 Scapy 的网络异常流量检测器")

with st.sidebar:
    st.header("流量来源（Source）")
    source_mode = st.radio(
        "选择流量来源：",
        ["实时抓包", "pcap 文件"],
    )

    iface = None
    pcap_file = None
    if source_mode == "实时抓包":
        # 获取可用网络接口
        interfaces = get_available_interfaces()
        if interfaces:
            iface = st.selectbox("选择网络接口：", interfaces)
        else:
            iface = st.text_input("网络接口名称（如 eth0 / Wi-Fi）", value="")
        bpf_filter = st.text_input("BPF 过滤表达式", value="tcp or udp")
        
        if st.session_state.capture_running:
            if st.button("停止抓包"):
                st.session_state.capture_running = False
                st.session_state.captured_packets = []
                st.success("抓包已停止")
        else:
            if st.button("开始抓包"):
                if iface:
                    st.session_state.capture_running = True
                    st.session_state.captured_packets = []
                    st.success(f"开始在接口 {iface} 上抓包")
                else:
                    st.error("请选择网络接口")
    else:
        pcap_file = st.file_uploader("选择 pcap 文件", type=["pcap", "pcapng"])

# 主界面布局
# 定义所有可能需要的列变量
col_dashboard = None
col_charts = None
col_stats = None
col_alerts = None

if source_mode == "实时抓包" and st.session_state.capture_running:
    # 实时模式下使用更紧凑的布局
    col_dashboard = st.columns(1)[0]
    col_charts = st.columns(1)[0]
    col_alerts = st.columns(1)[0]
else:
    # 非实时模式下使用两列布局
    col_stats, col_alerts = st.columns(2)

# 处理实时抓包模式
if source_mode == "实时抓包" and st.session_state.capture_running:
    # 实时仪表盘
    with col_dashboard:
        st.subheader("实时仪表盘")
        
        # 显示抓包状态
        st.info(f"正在接口 {iface} 上抓包...")
        
        # 实时统计卡片
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("已捕获数据包", len(st.session_state.captured_packets))
        with col2:
            st.metric("最近处理数据包", min(100, len(st.session_state.captured_packets)))
        with col3:
            st.metric("抓包状态", "运行中" if st.session_state.capture_running else "已停止")
        with col4:
            st.metric("网络接口", iface)
        
        # 定期更新界面
        if time.time() - st.session_state.last_update > 1:
            st.session_state.last_update = time.time()
            st.experimental_rerun()
        
        # 启动后台线程进行抓包
        def capture_thread():
            def packet_callback(evt: PacketEvent):
                st.session_state.captured_packets.append(evt)
                # 限制缓存的数据包数量，避免内存占用过高
                if len(st.session_state.captured_packets) > 1000:
                    st.session_state.captured_packets = st.session_state.captured_packets[-1000:]
            
            config = CaptureConfig(
                iface=iface,
                bpf_filter=bpf_filter,
                count=0,  # 不限制数量
                timeout=None  # 不设置超时
            )
            live_source(config, packet_callback)
        
        # 只启动一个线程
        if 'capture_thread' not in st.session_state or not st.session_state.capture_thread.is_alive():
            st.session_state.capture_thread = threading.Thread(target=capture_thread, daemon=True)
            st.session_state.capture_thread.start()
    
    # 实时图表
    with col_charts:
        st.subheader("流量分析图表")
        
        # 处理已捕获的数据包
        if st.session_state.captured_packets:
            # 只处理最近的数据包
            recent_packets = st.session_state.captured_packets[-100:]
            
            # Parser：PacketEvent → ParsedPacket
            parsed_packets: List[ParsedPacket] = [parse_packet(evt) for evt in recent_packets]
            
            # Feature：ParsedPacket → FeatureVector（5 元组 + 时间窗口聚合）
            feature_vectors: List[FeatureVector] = extract_features(parsed_packets, window_seconds=5.0)
            
            # Detection：FeatureVector → Alert
            alerts = detect_anomalies(feature_vectors)
            
            # 记录和打印告警
            for alert in alerts:
                log_alert(alert)
                print_alert(alert)
                store_alert(alert)
            
            # 存储流量特征
            for fv in feature_vectors:
                store_feature_vector(fv)
            
            # 存储关键数据包（可选，限制数量）
            for pkt in parsed_packets[:10]:  # 只存储前10个数据包
                store_packet(pkt)
            
            if feature_vectors:
                fv_df = pd.DataFrame([
                    {
                        "window_start": fv.window_start,
                        "window_end": fv.window_end,
                        "src_ip": fv.src_ip,
                        "dst_ip": fv.dst_ip,
                        "src_port": fv.src_port,
                        "dst_port": fv.dst_port,
                        "protocol": fv.protocol,
                        "packet_count": fv.statistical.packet_count,
                        "byte_count": fv.statistical.byte_count,
                        "syn_count": fv.statistical.syn_count,
                    }
                    for fv in feature_vectors
                ])
                
                # 流量趋势图表
                st.markdown("**流量趋势**")
                window_stats = (
                    fv_df.groupby(["window_start", "window_end"], as_index=False)["packet_count"].sum()
                )
                window_stats = window_stats.sort_values("window_start")
                window_stats_display = window_stats.set_index("window_start")["packet_count"]
                st.line_chart(window_stats_display)
                
                # 协议分布饼图
                st.markdown("**协议分布**")
                protocol_dist = fv_df.groupby("protocol")["packet_count"].sum()
                st.pyplot(protocol_dist.plot.pie(autopct='%1.1f%%', figsize=(5, 5)).figure)
                
                # Top-N 流量
                st.markdown("**Top-N 流量**")
                top_flows = (
                    fv_df.sort_values("packet_count", ascending=False)
                    .head(10)[
                        [
                            "src_ip",
                            "dst_ip",
                            "src_port",
                            "dst_port",
                            "protocol",
                            "packet_count",
                            "byte_count",
                        ]
                    ]
                )
                st.dataframe(top_flows, use_container_width=True)
    
    # 实时告警
    with col_alerts:
        st.subheader("实时告警")
        
        # 显示最新告警
        alerts_log = pathlib.Path("data/alerts.log")
        if alerts_log.exists():
            st.write("最近告警：")
            with alerts_log.open("r", encoding="utf-8") as f:
                lines = f.readlines()[-20:]
            
            # 按时间倒序显示
            for line in reversed(lines):
                try:
                    alert_data = eval(line.strip())
                    # 格式化显示告警
                    with st.expander(f"[{alert_data.get('alert_type')}] {alert_data.get('src_ip')} -> {alert_data.get('dst_ip')}"):
                        st.write(f"时间：{alert_data.get('timestamp')}")
                        st.write(f"风险分数：{alert_data.get('score'):.2f}")
                        st.write(f"详情：{alert_data.get('detail')}")
                except:
                    st.code(line.strip(), language="json")
        else:
            st.write("当前尚无告警。")

# 处理非实时模式（pcap 文件）
else:
    with col_stats:
        st.subheader("流量统计与特征视图")

        if source_mode == "pcap 文件":
            if pcap_file is None:
                st.info("请在左侧上传一个 pcap/pcapng 文件。")
            elif pcap_file is not None:
                # 将上传文件保存到本地，便于后续分析和复现
                uploads_dir = pathlib.Path("data/uploads")
                uploads_dir.mkdir(parents=True, exist_ok=True)
                local_path = uploads_dir / pcap_file.name
                with local_path.open("wb") as f:
                    f.write(pcap_file.read())

                st.write(f"已保存到 `{local_path}`，开始解析与特征聚合……")

                # Source：pcap → PacketEvent
                events = list(pcap_source(str(local_path)))

                # Parser：PacketEvent → ParsedPacket
                parsed_packets: List[ParsedPacket] = [parse_packet(evt) for evt in events]

                # Feature：ParsedPacket → FeatureVector（5 元组 + 时间窗口聚合）
                feature_vectors: List[FeatureVector] = extract_features(parsed_packets, window_seconds=5.0)

                # Detection：FeatureVector → Alert
                alerts = detect_anomalies(feature_vectors)
                
                # 记录和打印告警
                for alert in alerts:
                    log_alert(alert)
                    print_alert(alert)

                st.markdown("**基础统计**")
                st.write(
                    {
                        "原始包数量": len(parsed_packets),
                        "特征窗口数量": len(feature_vectors),
                        "检测到的告警数量": len(alerts),
                    }
                )

                if feature_vectors:
                    fv_df = pd.DataFrame([
                        {
                            "window_start": fv.window_start,
                            "window_end": fv.window_end,
                            "src_ip": fv.src_ip,
                            "dst_ip": fv.dst_ip,
                            "src_port": fv.src_port,
                            "dst_port": fv.dst_port,
                            "protocol": fv.protocol,
                            "packet_count": fv.statistical.packet_count,
                            "byte_count": fv.statistical.byte_count,
                            "syn_count": fv.statistical.syn_count,
                        }
                        for fv in feature_vectors
                    ])

                    st.markdown("**Top-N 5 元组（按包数）**")
                    top_flows = (
                        fv_df.sort_values("packet_count", ascending=False)
                        .head(10)[
                            [
                                "src_ip",
                                "dst_ip",
                                "src_port",
                                "dst_port",
                                "protocol",
                                "packet_count",
                                "byte_count",
                                "syn_count",
                            ]
                        ]
                    )
                    st.dataframe(top_flows, use_container_width=True)

                    st.markdown("**时间窗口内总包数曲线**")
                    window_stats = (
                        fv_df.groupby(["window_start", "window_end"], as_index=False)["packet_count"].sum()
                    )
                    window_stats = window_stats.sort_values("window_start")
                    window_stats_display = window_stats.set_index("window_start")["packet_count"]
                    st.line_chart(window_stats_display)

                    # 协议分布饼图
                    st.markdown("**协议分布**")
                    protocol_dist = fv_df.groupby("protocol")["packet_count"].sum()
                    st.pyplot(protocol_dist.plot.pie(autopct='%1.1f%%', figsize=(5, 5)).figure)

                else:
                    st.warning("未从该 pcap 中提取到有效特征（可能是文件为空或未包含 IP/TCP/UDP 流量）。")
        else:
            st.info("请选择流量来源并开始分析。")

    with col_alerts:
        st.subheader("异常告警（Sink 日志视图）")
        alerts_log = pathlib.Path("data/alerts.log")
        if alerts_log.exists():
            st.write("最近日志内容：")
            with alerts_log.open("r", encoding="utf-8") as f:
                lines = f.readlines()[-50:]
            for line in lines:
                st.code(line.strip(), language="json")
        else:
            st.write("当前尚无告警日志。")

# 历史数据查询与分析
st.header("历史数据查询与分析")

# 选择查询类型
query_type = st.selectbox(
    "选择查询类型：",
    ["历史告警", "历史流量特征", "数据库统计"]
)

if query_type == "历史告警":
    # 历史告警查询
    st.subheader("历史告警查询")
    
    # 查询参数
    limit = st.slider("显示数量", min_value=10, max_value=1000, value=100)
    
    # 获取历史告警
    historical_alerts = get_historical_alerts(limit=limit)
    
    if historical_alerts:
        # 转换为 DataFrame 进行展示
        alerts_df = pd.DataFrame(historical_alerts)
        # 格式化显示
        alerts_df['detail'] = alerts_df['detail'].apply(lambda x: x[:100] + '...' if len(x) > 100 else x)
        st.dataframe(alerts_df, use_container_width=True)
        
        # 告警类型分布
        if not alerts_df.empty:
            st.markdown("**告警类型分布**")
            alert_type_dist = alerts_df.groupby('alert_type').size()
            st.pyplot(alert_type_dist.plot.bar(figsize=(10, 5)).figure)
    else:
        st.info("暂无历史告警记录。")

elif query_type == "历史流量特征":
    # 历史流量特征查询
    st.subheader("历史流量特征查询")
    
    # 查询参数
    limit = st.slider("显示数量", min_value=10, max_value=1000, value=100)
    
    # 获取历史流量特征
    historical_traffic = get_historical_traffic(limit=limit)
    
    if historical_traffic:
        # 转换为 DataFrame 进行展示
        traffic_df = pd.DataFrame(historical_traffic)
        # 格式化显示
        traffic_df['extra'] = traffic_df['extra'].apply(lambda x: x[:50] + '...' if x and len(x) > 50 else x)
        st.dataframe(traffic_df, use_container_width=True)
        
        # 流量趋势
        if not traffic_df.empty:
            st.markdown("**历史流量趋势**")
            traffic_df['window_start'] = pd.to_datetime(traffic_df['window_start'], unit='s')
            traffic_trend = traffic_df.groupby('window_start')['packet_count'].sum()
            st.line_chart(traffic_trend)
    else:
        st.info("暂无历史流量特征记录。")

elif query_type == "数据库统计":
    # 数据库统计信息
    st.subheader("数据库统计信息")
    
    # 获取历史告警数量
    total_alerts = len(get_historical_alerts(limit=10000))
    # 获取历史流量特征数量
    total_traffic = len(get_historical_traffic(limit=10000))
    
    # 显示统计卡片
    col1, col2 = st.columns(2)
    with col1:
        st.metric("总告警数", total_alerts)
    with col2:
        st.metric("总流量特征记录数", total_traffic)
    
    st.info("数据库统计信息每小时更新一次。")

