# 🛡️ Endpoint Detection Tool

Lightweight Python-based endpoint monitoring system.  
It detects suspicious processes, ports, and outbound connections in real time.

## 🚀 Features
- Detects **suspicious processes** (e.g., running from `/tmp` or `/dev/shm`)
- Detects **new listening ports**
- Detects **uncommon outbound connections**
- Colored, structured runtime alerts
- Logs all alerts into `alerts.jsonl`

## 💻 Requirements
```bash
sudo apt update
sudo apt install -y python3-pip
pip3 install --user psutil
```

## 📦 Installation
```bash
git clone https://github.com/YOUR-USERNAME/endpoint-monitor-tool.git
cd endpoint-monitor-tool
```

## ▶️ Usage
```bash
sudo ./End-PointCyspy.py --monitor --interval 3
```

## 📂 Alerts

Alerts are saved in: 
alerts.jsonl

## 🔥 Example Alert
```bash
🔴 2025-08-26 [NETWORK] CRITICAL
  New outbound connection
  PID=1234 → 45.67.89.10:4444 (uncommon port)
```
