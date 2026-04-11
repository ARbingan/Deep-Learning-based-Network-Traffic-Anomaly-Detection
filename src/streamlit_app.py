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
from core.detection_engine import detect_anomalies, get_detection_performance
from core.sink import log_alert, print_alert
from core.database import store_alert, store_feature_vector, store_packet, get_historical_alerts, get_historical_traffic
from core.custom_types import ParsedPacket, FeatureVector, PacketEvent


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
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = True  # 默认开启自动刷新
if 'refresh_interval' not in st.session_state:
    st.session_state.refresh_interval = 0.1  # 默认100ms

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
            # 提取友好名称用于显示
            interface_options = [name for _, name in interfaces]
            # 存储原始名称和友好名称的映射
            interface_map = {name: raw for raw, name in interfaces}
            # 创建选择框
            selected_name = st.selectbox("选择网络接口：", interface_options)
            # 获取对应的原始名称
            iface = interface_map[selected_name]
        else:
            iface = st.text_input("网络接口名称（如 eth0 / Wi-Fi）", value="")
        bpf_filter = st.text_input("BPF 过滤表达式", value="tcp or udp")
        
        if st.session_state.capture_running:
            if st.button("停止抓包"):
                st.session_state.capture_running = False
                st.session_state.capture_manager.stop()
                st.session_state.capture_manager.clear_packets()
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

# 抓包线程管理器 - 采用简单可靠的线程设计，参考测试成功的实现
class CaptureManager:
    """使用线程的抓包管理器，确保抓包持续稳定运行"""
    def __init__(self):
        self.running = False
        self.captured_packets = []
        self.capture_thread = None
        self.new_packets = 0  # 新捕获的数据包计数
        self.iface = None
        self.bpf_filter = None
        print("[CAPTURE] 初始化抓包管理器")
    
    def packet_callback(self, evt):
        """数据包回调函数"""
        try:
            self.captured_packets.append(evt)
            self.new_packets += 1
            # 限制数据包数量
            if len(self.captured_packets) > 2000:
                self.captured_packets = self.captured_packets[-1500:]
        except Exception as e:
            print(f"[CAPTURE] 回调函数异常: {e}")
    
    def _capture_thread_func(self):
        """抓包线程函数 - 使用简单可靠的短时间循环"""
        print(f"[CAPTURE] 启动抓包线程，接口: {self.iface}")
        
        from core.source import CaptureConfig, live_source
        
        config = CaptureConfig(
            iface=self.iface,
            bpf_filter=self.bpf_filter,
            count=0,
            timeout=None
        )
        
        try:
            # 直接调用live_source，它内部有自己的循环逻辑
            live_source(config, self.packet_callback)
        except Exception as e:
            print(f"[CAPTURE] 抓包线程异常: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.running:
                print(f"[CAPTURE] 抓包线程意外退出")
            else:
                print(f"[CAPTURE] 抓包线程正常退出")
    
    def start(self, iface, bpf_filter):
        """启动抓包"""
        if self.running:
            return
        
        print(f"[CAPTURE] 开始抓包，接口: {iface}")
        
        self.running = True
        self.captured_packets = []
        self.new_packets = 0
        self.iface = iface
        self.bpf_filter = bpf_filter
        
        # 启动抓包线程
        self.capture_thread = threading.Thread(
            target=self._capture_thread_func,
            daemon=True
        )
        self.capture_thread.start()
    
    def stop(self):
        """停止抓包"""
        print("[CAPTURE] 停止抓包")
        self.running = False
        # 这里不需要强制终止线程，live_source会在内部循环中自然退出
    
    def get_packets(self):
        """获取捕获的数据包"""
        return self.captured_packets.copy()
    
    def get_new_packets_count(self):
        """获取新捕获的数据包数量"""
        count = self.new_packets
        self.new_packets = 0
        return count
    
    def reset_new_packets_count(self):
        """重置新捕获的数据包计数器"""
        self.new_packets = 0
    
    def clear_packets(self):
        """清除所有捕获的数据包"""
        self.captured_packets = []
        self.new_packets = 0
    
    def check_health(self):
        """检查抓包线程健康状态"""
        if not self.running:
            return
        
        # 检查线程是否还在运行
        if self.capture_thread and not self.capture_thread.is_alive():
            print(f"[CAPTURE] 抓包线程已死，重启中...")
            self.restart()
    
    def restart(self):
        """重启抓包"""
        if not self.running or not self.iface:
            return
        
        print(f"[CAPTURE] 重启抓包...")
        self.stop()
        time.sleep(0.5)
        self.start(self.iface, self.bpf_filter)


# 初始化抓包管理器
if 'capture_manager' not in st.session_state:
    st.session_state.capture_manager = CaptureManager()


# 处理实时抓包模式
if source_mode == "实时抓包" and st.session_state.capture_running:
    # 启动抓包线程
    if not st.session_state.capture_manager.running:
        st.session_state.capture_manager.start(iface, bpf_filter)
    
    # 实时仪表盘
    with col_dashboard:
        st.subheader("实时仪表盘")
        
        # 刷新控制区域
        refresh_col1, refresh_col2 = st.columns([1, 2])
        with refresh_col1:
            # 手动刷新按钮
            if st.button("🔄 手动刷新", key="manual_refresh", type="primary", help="点击刷新获取最新捕获的数据包"):
                st.rerun()
        
        # 自动刷新设置
        auto_refresh_container = st.container()
        with auto_refresh_container:
            col_auto, col_interval = st.columns([1, 2])
            with col_auto:
                # 自动刷新开关
                st.session_state.auto_refresh = st.checkbox("自动刷新", value=st.session_state.auto_refresh, help="启用或禁用自动刷新")
            with col_interval:
                # 时间间隔选择下拉列表
                if st.session_state.auto_refresh:
                    interval_options = {
                        "100ms": 0.1,
                        "500ms": 0.5,
                        "1s": 1.0,
                        "2s": 2.0,
                        "5s": 5.0
                    }
                    selected_option = st.selectbox(
                        "刷新间隔",
                        options=list(interval_options.keys()),
                        index=list(interval_options.values()).index(st.session_state.refresh_interval),
                        help="选择自动刷新的时间间隔"
                    )
                    
                    # 当选择新的时间间隔时，立即更新并重置last_update
                    new_interval = interval_options[selected_option]
                    if new_interval != st.session_state.refresh_interval:
                        st.session_state.refresh_interval = new_interval
                        st.session_state.last_update = time.time()  # 立即重置上次更新时间
        
        # 显示抓包状态
        st.info(f"正在接口 {iface} 上抓包...")
        
        # 从抓包管理器获取数据包
        captured_packets = st.session_state.capture_manager.get_packets()
        new_packets_count = st.session_state.capture_manager.get_new_packets_count()
        
        # 实时统计卡片
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("已捕获数据包", len(captured_packets))
        with col2:
            st.metric("新捕获数据包", new_packets_count)
        with col3:
            st.metric("抓包状态", "运行中" if st.session_state.capture_running else "已停止")
        with col4:
            st.metric("网络接口", iface.split('_')[-1][:8] if '_' in iface else iface)
        
        # 添加调试信息
        with st.expander("调试信息"):
            st.write(f"当前使用接口: {iface}")
            st.write(f"BPF过滤表达式: {bpf_filter}")
            st.write(f"抓包状态: {'运行中' if st.session_state.capture_running else '已停止'}")
            st.write(f"已捕获数据包数: {len(captured_packets)}")
            st.write(f"抓包线程状态: {'运行中' if st.session_state.capture_manager.running else '已停止'}")
            
            # 测试Scapy接口连接
            import scapy.all as scapy
            st.write(f"Scapy识别的接口数: {len(scapy.get_if_list())}")
            st.write(f"当前接口在Scapy列表中: {iface in scapy.get_if_list()}")
        
        # 检查抓包线程健康状态，确保持续运行
        st.session_state.capture_manager.check_health()
        
        # 使用更可靠的自动刷新机制 - 基于请求计数
        if 'refresh_count' not in st.session_state:
            st.session_state.refresh_count = 0
        
        # 立即显示当前刷新计数和间隔（用于调试）
        st.write(f"当前刷新计数: {st.session_state.refresh_count}")
        st.write(f"当前刷新间隔: {st.session_state.refresh_interval}秒")
        
        # 自动刷新逻辑
        if st.session_state.auto_refresh:
            # 获取当前时间
            current_time = time.time()
            
            # 检查是否需要刷新
            if current_time - st.session_state.last_update > st.session_state.refresh_interval:
                # 增加刷新计数
                st.session_state.refresh_count += 1
                # 更新上次刷新时间
                st.session_state.last_update = current_time
                # 使用强制刷新
                st.experimental_rerun() if hasattr(st, 'experimental_rerun') else st.rerun()
    
    # 实时图表
    with col_charts:
        st.subheader("流量分析图表")
        
        # 处理已捕获的数据包
        captured_packets = st.session_state.capture_manager.get_packets()
        if captured_packets:
            try:
                st.write(f"[调试] 处理 {len(captured_packets)} 个数据包")
                
                # 只处理最近的数据包
                recent_packets = captured_packets[-100:]
                
                # Parser：PacketEvent → ParsedPacket
                parsed_packets: List[ParsedPacket] = []
                for i, evt in enumerate(recent_packets):
                    try:
                        pkt = parse_packet(evt)
                        if pkt is not None:
                            parsed_packets.append(pkt)
                    except Exception as e:
                        print(f"[DEBUG] 解析数据包 {i} 失败: {e}")
                
                st.write(f"[调试] 成功解析 {len(parsed_packets)} 个数据包")
                
                if not parsed_packets:
                    st.info("没有解析到有效的数据包")
                    continue_processing = False
                else:
                    continue_processing = True
                
                if continue_processing:
                    # Feature：ParsedPacket → FeatureVector（5 元组 + 时间窗口聚合）
                    feature_vectors: List[FeatureVector] = extract_features(parsed_packets, window_seconds=5.0)
                    
                    st.write(f"[调试] 生成 {len(feature_vectors)} 个特征向量")
                    
                    if not feature_vectors:
                        st.info("没有生成有效的特征向量")
                        continue_processing = False
                
                if continue_processing:
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
                    
                    # 创建特征向量DataFrame，处理可能的空值
                    fv_data = []
                    for fv in feature_vectors:
                        if fv.statistical is not None:
                            fv_data.append({
                                "window_start": fv.window_start,
                                "window_end": fv.window_end,
                                "src_ip": fv.src_ip or "unknown",
                                "dst_ip": fv.dst_ip or "unknown",
                                "src_port": fv.src_port or 0,
                                "dst_port": fv.dst_port or 0,
                                "protocol": fv.protocol or "unknown",
                                "packet_count": fv.statistical.packet_count or 0,
                                "byte_count": fv.statistical.byte_count or 0,
                                "syn_count": fv.statistical.syn_count or 0,
                            })
                    
                    if fv_data:
                        fv_df = pd.DataFrame(fv_data)
                        st.write(f"[调试] 创建了 {len(fv_df)} 行的DataFrame")
                        
                        # 流量趋势图表 - 使用Streamlit内置图表，更可靠
                        st.markdown("**流量趋势**")
                        try:
                            window_stats = fv_df.groupby(["window_start", "window_end"], as_index=False)["packet_count"].sum()
                            window_stats = window_stats.sort_values("window_start")
                            
                            if not window_stats.empty:
                                st.line_chart(window_stats, x="window_start", y="packet_count", use_container_width=True)
                            else:
                                st.info("没有足够的数据生成流量趋势图表")
                        except Exception as e:
                            st.error(f"流量趋势图表错误: {e}")
                        
                        # 协议分布 - 使用Streamlit内置的bar_chart代替pyplot
                        st.markdown("**协议分布**")
                        try:
                            protocol_dist = fv_df["protocol"].value_counts()
                            if not protocol_dist.empty:
                                st.bar_chart(protocol_dist, use_container_width=True)
                            else:
                                st.info("没有足够的数据生成协议分布图表")
                        except Exception as e:
                            st.error(f"协议分布图表错误: {e}")
                        
                        # Top-N 流量
                        st.markdown("**Top-N 流量**")
                        try:
                            top_flows = fv_df.sort_values("packet_count", ascending=False).head(10)[[
                                "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_count", "byte_count"
                            ]]
                            st.dataframe(top_flows, use_container_width=True)
                        except Exception as e:
                            st.error(f"Top-N 流量图表错误: {e}")
                    else:
                        st.info("没有有效的统计数据")
                    
            except Exception as e:
                st.error(f"数据处理错误: {str(e)}")
                import traceback
                st.write("错误详情:")
                st.code(traceback.format_exc(), language="text")
    
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
                
                # 显示检测性能
                st.markdown("**检测性能**")
                performance = get_detection_performance()
                st.write(performance)

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
        
        # 1. 添加恶意流量仪表
        st.markdown("### 恶意流量检测概览")
        
        # 计算恶意流量包数量和攻击模式
        attack_types = {}
        if 'alerts' in locals() or 'alerts' in globals():
            total_malicious_packets = len(alerts)
            if alerts:
                # 使用更安全的方式统计攻击类型
                for alert in alerts:
                    if hasattr(alert, 'alert_type'):
                        alert_type = alert.alert_type
                        attack_types[alert_type] = attack_types.get(alert_type, 0) + 1
            total_attack_types = len(attack_types)
        else:
            total_malicious_packets = 0
            total_attack_types = 0
        
        # 创建两列布局展示仪表
        meter_col1, meter_col2 = st.columns(2)
        
        with meter_col1:
            st.metric("检测到的恶意流量包", total_malicious_packets)
            st.markdown("**恶意流量包**：系统检测到的可疑网络数据包数量")
        
        with meter_col2:
            st.metric("检测到的攻击模式", total_attack_types)
            st.markdown("**攻击模式**：系统识别出的不同类型网络攻击数量")
        
        # 2. 显示攻击模式详情
        if attack_types:
            st.markdown("### 攻击模式分布")
            attack_df = pd.DataFrame(list(attack_types.items()), columns=['攻击类型', '检测次数'])
            st.bar_chart(attack_df, x='攻击类型', y='检测次数', use_container_width=True)
        else:
            st.info("当前未检测到攻击模式")
        
        # 3. 缩小后的告警日志列表
        st.markdown("### 告警日志（最近20条）")
        alerts_log = pathlib.Path("data/alerts.log")
        if alerts_log.exists():
            with alerts_log.open("r", encoding="utf-8") as f:
                lines = f.readlines()[-20:]  # 只显示最近20条
            if lines:
                for line in lines:
                    st.code(line.strip(), language="json")
            else:
                st.write("告警日志为空")
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

