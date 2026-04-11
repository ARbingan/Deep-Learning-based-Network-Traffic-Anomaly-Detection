# PCAP测试数据集推荐

## 1. CTU-13 Dataset
- **来源**：捷克技术大学 (CTU)
- **特点**：包含13个不同的恶意软件捕获，每个捕获都有明确的标签
- **攻击类型**：恶意软件通信、C&C流量、僵尸网络活动等
- **数据集规模**：每个捕获约2-100MB
- **下载链接**：[CTU-13 Dataset](https://www.stratosphereips.org/datasets-ctu13)
- **使用建议**：适合测试恶意软件检测和C&C流量识别

## 2. ISCX-IDS 2012 Dataset
- **来源**：加拿大网络安全研究所 (ISCX)
- **特点**：包含真实的网络流量和多种攻击类型的组合
- **攻击类型**：DDoS、端口扫描、SQL注入、暴力破解、Web攻击等
- **数据集规模**：约1.5GB（压缩后）
- **下载链接**：[ISCX-IDS 2012](https://www.unb.ca/cic/datasets/ids-2012.html)
- **使用建议**：适合全面测试入侵检测系统的各种攻击检测能力

## 3. CICIDS2017 Dataset
- **来源**：加拿大网络安全研究所 (CIC)
- **特点**：包含现代网络攻击，基于真实网络环境构建
- **攻击类型**：DDoS、DoS、暴力破解、渗透测试、Web攻击、僵尸网络等
- **数据集规模**：约100GB（包含原始PCAP和CSV格式）
- **下载链接**：[CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- **使用建议**：适合测试针对现代攻击的检测能力

## 4. UNSW-NB15 Dataset
- **来源**：澳大利亚网络安全中心 (UNSW)
- **特点**：包含多种攻击类型，覆盖了传统和现代攻击
- **攻击类型**：DoS、Probe、R2L、U2R、Exploit等
- **数据集规模**：约10GB（包含PCAP和CSV格式）
- **下载链接**：[UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- **使用建议**：适合测试对各种攻击类型的检测能力

## 5. MTA-CTS DDoS Dataset
- **来源**：以色列理工学院 (Technion)
- **特点**：专注于DDoS攻击的数据集，包含多种DDoS攻击类型
- **攻击类型**：UDP洪水、TCP洪水、HTTP洪水、SYN洪水等
- **数据集规模**：约5GB
- **下载链接**：[MTA-CTS DDoS](https://mta-cts.net/projects/ddos-attack-dataset/)
- **使用建议**：适合专门测试DDoS攻击检测能力

## 6. MAWI Dataset
- **来源**：日本国立信息学研究所 (NII)
- **特点**：真实的互联网流量数据集，包含各种应用流量
- **攻击类型**：可能包含真实的网络攻击（无明确标签）
- **数据集规模**：每月约1TB（可选择特定日期和时间窗口）
- **下载链接**：[MAWI Working Group Traffic Archive](https://mawi.wide.ad.jp/mawi/)
- **使用建议**：适合测试系统在真实互联网流量下的性能

## 7. DARPA Intrusion Detection Dataset
- **来源**：美国国防高级研究计划局 (DARPA)
- **特点**：最早的入侵检测数据集之一，包含多种经典攻击
- **攻击类型**：端口扫描、缓冲区溢出、Teardrop攻击、Land攻击等
- **数据集规模**：约4GB
- **下载链接**：[DARPA IDS Dataset](https://www.kdd.org/kdd-cup/view/kdd-cup-1999/Data)
- **使用建议**：适合研究经典攻击检测方法

## 数据集使用建议

1. **CTU-13** 和 **ISCX-IDS 2012** 是入门级测试的首选，体积适中且标签清晰
2. **CICIDS2017** 和 **UNSW-NB15** 适合高级测试，包含现代攻击类型
3. **MTA-CTS DDoS** 适合专门测试DDoS检测能力
4. **MAWI** 适合测试系统在真实互联网流量下的性能和稳定性

## 如何获取PCAP文件

大多数数据集都提供直接的PCAP文件下载。如果只有CSV文件，可以使用工具如 **tcpreplay** 或 **scapy** 将其转换为PCAP格式。

## 测试方法

1. 下载选定的PCAP数据集
2. 在应用中选择"PCAP文件分析"模式
3. 上传下载的PCAP文件
4. 观察系统的检测结果
5. 验证检测到的恶意流量是否与数据集标签一致