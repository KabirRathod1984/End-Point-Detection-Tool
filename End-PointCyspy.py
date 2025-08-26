#!/usr/bin/env python3
import argparse
import psutil
import time
import os
import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)  # auto reset color after each print

# -----------------------------
# Logo
# -----------------------------
LOGO = r"""
███████╗███╗   ██╗██████╗       ██████╗  ██████╗ ██╗███╗   ██╗████████╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
██╔════╝████╗  ██║██╔══██╗      ██╔══██╗██╔═══██╗██║████╗  ██║╚══██╔══╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
█████╗  ██╔██╗ ██║██║  ██║█████╗██████╔╝██║   ██║██║██╔██╗ ██║   ██║       ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
██╔══╝  ██║╚██╗██║██║  ██║╚════╝██╔═══╝ ██║   ██║██║██║╚██╗██║   ██║       ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
███████╗██║ ╚████║██████╔╝      ██║     ╚██████╔╝██║██║ ╚████║   ██║       ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═══╝╚═════╝       ╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                                                                                                                    
                                                                                                                                                                                                            
                                                   Endpoint Detection Tool | By CyspyMaiden

"""

# -----------------------------
# Alert Printer
# -----------------------------
def print_alert(level, category, message, details=""):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    icons = {
        "CRITICAL": "🔴",
        "WARNING": "🟡",
        "INFO": "🔵"
    }
    colors = {
        "CRITICAL": Fore.RED,
        "WARNING": Fore.YELLOW,
        "INFO": Fore.CYAN
    }
    icon = icons.get(level.upper(), "⚪")
    color = colors.get(level.upper(), Fore.WHITE)

    print(f"{color}{icon} {ts} [{category}] {level}{Style.RESET_ALL}")
    print(f"  {message}")
    if details:
        print(f"  {details}")

# -----------------------------
# Detection Functions
# -----------------------------
def detect_process_anomalies(known_pids):
    alerts = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
        try:
            if proc.info['pid'] not in known_pids:
                exe = proc.info['exe'] or ""
                if exe.startswith("/tmp") or exe.startswith("/dev/shm"):
                    alerts.append({
                        "type": "PROCESS",
                        "level": "CRITICAL",
                        "msg": f"Suspicious process execution detected",
                        "details": f"PID={proc.info['pid']} Name={proc.info['name']} Path={exe}"
                    })
                known_pids.add(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return alerts

def detect_listening_ports(known_ports):
    alerts = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN:
            lport = conn.laddr.port
            if lport not in known_ports:
                alerts.append({
                    "type": "NETWORK",
                    "level": "WARNING",
                    "msg": f"New listening port detected",
                    "details": f"Port={lport} PID={conn.pid}"
                })
                known_ports.add(lport)
    return alerts

def detect_outbound_connections(known_conns):
    alerts = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.status == psutil.CONN_ESTABLISHED:
            key = (conn.laddr.port, conn.raddr.ip, conn.raddr.port)
            if key not in known_conns:
                known_conns.add(key)
                if conn.raddr.port not in [80, 443, 22, 53]:
                    alerts.append({
                        "type": "NETWORK",
                        "level": "CRITICAL",
                        "msg": f"New outbound connection",
                        "details": f"PID={conn.pid} → {conn.raddr.ip}:{conn.raddr.port} (uncommon port)"
                    })
                else:
                    alerts.append({
                        "type": "NETWORK",
                        "level": "INFO",
                        "msg": f"New outbound connection",
                        "details": f"PID={conn.pid} → {conn.raddr.ip}:{conn.raddr.port}"
                    })
    return alerts

# -----------------------------
# Main Monitor
# -----------------------------
def monitor(interval=5):
    print(Fore.MAGENTA + LOGO + Style.RESET_ALL)  # print logo once at startup
    known_pids = set(p.pid for p in psutil.process_iter())
    known_ports = set()
    known_conns = set()
    print(Fore.GREEN + f"[i] Monitoring started. Interval={interval}s" + Style.RESET_ALL)
    while True:
        alerts = []
        alerts += detect_process_anomalies(known_pids)
        alerts += detect_listening_ports(known_ports)
        alerts += detect_outbound_connections(known_conns)

        for a in alerts:
            print_alert(a["level"], a["type"], a["msg"], a["details"])
            with open("alerts.jsonl", "a") as f:
                f.write(json.dumps({"time": datetime.utcnow().isoformat(), **a}) + "\n")
        time.sleep(interval)

# -----------------------------
# Entry Point
# -----------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight Endpoint Detection Tool with colored alerts")
    parser.add_argument("--monitor", action="store_true", help="Run monitoring mode")
    parser.add_argument("--interval", type=int, default=5, help="Check interval in seconds")
    args = parser.parse_args()

    if args.monitor:
        monitor(interval=args.interval)
    else:
        print("Use --monitor to start monitoring")
