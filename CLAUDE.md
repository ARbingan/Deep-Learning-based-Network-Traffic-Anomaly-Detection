# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a network anomaly traffic detection system (基于 Scapy 的网络异常流量检测器), a graduation design project. It captures and analyzes network traffic in real time, extracts features, and detects anomalies using rule-based and ML-based methods.

## Running the Application

```bash
# Web UI（Dash，推荐）
cd src && python web/app.py
# 浏览器访问 http://localhost:8050

# Web UI（旧版 Streamlit，保留备用）
streamlit run src/streamlit_app.py

# Desktop UI (PyQt5)
python desktop_app.py

# PCAP analysis report
python scripts/analyze_pcap_report.py
```

## Development Setup

```bash
# Install dependencies (use the virtual environment at .venv/)
pip install -r requirements.txt

# Scapy on Windows requires Npcap (not WinPcap) for live capture
# Run as Administrator for live packet capture
```

## Architecture

The system is a linear pipeline where each stage produces a typed data structure consumed by the next:

```
Source → PacketEvent → Parser → ParsedPacket → FeatureExtractor → FeatureVector → DetectionEngine → Alert → Sink
```

All core types are defined in `src/core/custom_types.py`. The key types are:
- `PacketEvent` — raw packet with timestamp from Source
- `ParsedPacket` — extracted IP/TCP/UDP fields from Parser
- `FeatureVector` — combined statistical + protocol + attack features for detection

**Core modules** (`src/core/`):
- `source.py` — two modes: live Scapy sniff on a network interface, or reading a PCAP file
- `parser.py` — extracts IP, IPv6, TCP, UDP fields into `ParsedPacket`
- `feature_extractor.py` — computes `StatisticalFeatures`, `ProtocolFeatures`, and `AttackFeatures` from packet windows
- `detection_engine.py` — hybrid detection: rule-based (SYN flood, DDoS, port scan) + scikit-learn ML models + optional Transformer
- `sink.py` — outputs alerts to log file, console, or Streamlit session state
- `database.py` — SQLite persistence (`data/traffic_analyzer.db`)

**UI layers:**
- `src/streamlit_app.py` — web UI; manages capture lifecycle via `st.session_state`; supports live capture and PCAP upload
- `desktop_app.py` — PyQt5 desktop app; uses `PacketCaptureThread` for non-blocking capture

**ML / Transformer subsystem** (all in `src/core/`):
- `transformer_detector.py` + `transformer_integration.py` — lightweight Transformer anomaly detector
- `train_transformer.py` / `transformer_dataset.py` — training pipeline using CICIDS dataset
- Trained models and feature data stored as pickle files under `data/`

## Training Models

```bash
# Convert CICIDS CSV dataset to feature vectors
python scripts/convert_cicids_to_featurevectors.py

# Train with CICIDS data
python scripts/train_with_cicids.py

# Test model integration
python scripts/test_model_integration.py
```

## Testing / Debugging

There is no formal test suite. Validation scripts live in `scripts/`:

```bash
python scripts/test_scapy_sniff.py        # verify live capture works
python scripts/simple_capture_test.py     # basic capture sanity check
python scripts/test_streamlit_scapy.py    # Streamlit + Scapy integration
python scripts/debug_training.py          # debug ML training issues
```

## Data

- `data/traffic_analyzer.db` — SQLite database for persisted traffic records
- `data/alerts.log` — alert log output
- `data/cicids_all_features_v2.pkl` — preprocessed CICIDS feature vectors for training
- `MachineLearningCSV/` — raw CICIDS 2018 CSV files
- `IDS2018_change_PCAP/` — PCAP test files
