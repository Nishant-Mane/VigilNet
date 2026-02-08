import sys
import os
import subprocess
import time
import threading
import queue
import json

# ================= PATH FIX =================
# Ensure backend is importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from storage.db_writer import insert_alert
from flow_manager import FlowManager
from feature_extractor import extract_model_features
from ML.inference import IDSModel

# ================= CONFIG =================

# ---- CAPTURE CONFIG (DOCKER SAFE) ----
TSHARK_BIN = os.getenv("TSHARK_BIN", "tshark")
CAPTURE_IFACE = os.getenv("CAPTURE_IFACE", "eth0")

FLOW_TIMEOUT_SECONDS = 30
FINALIZE_INTERVAL = 2  # seconds

MIN_PACKETS_FOR_ML = 10
MIN_DURATION_FOR_ML = 1.0  # seconds

ACTIVE_FLOWS_DUMP_INTERVAL = 2
LIVE_TRAFFIC_INTERVAL = 2

# ---- STORAGE PATHS ----
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

STORAGE_DIR = os.path.join(BASE_DIR, "storage", "runtime")
os.makedirs(STORAGE_DIR, exist_ok=True)

ACTIVE_FLOWS_PATH = os.path.join(STORAGE_DIR, "active_flows.json")
LIVE_TRAFFIC_PATH = os.path.join(STORAGE_DIR, "live_traffic.json")
CAPTURE_STATUS_PATH = os.path.join(STORAGE_DIR, "capture_status.json")

# ---- MODEL PATH (DOCKER SAFE) ----
MODEL_DIR = os.getenv("MODEL_DIR", "/app/models")

# =========================================


def write_capture_status(running: bool):
    with open(CAPTURE_STATUS_PATH, "w") as f:
        json.dump(
            {
                "running": running,
                "timestamp": time.time()
            },
            f
        )


def tshark_reader(proc, q):
    for line in proc.stdout:
        q.put(line)


def eligible_for_ml(flow):
    total_packets = flow.fwd_packets + flow.bwd_packets
    return (
        total_packets >= MIN_PACKETS_FOR_ML and
        flow.duration() >= MIN_DURATION_FOR_ML
    )


def dump_active_flows(manager):
    now = time.time()
    flows_snapshot = []

    for flow in manager.active_flows.values():
        flows_snapshot.append({
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "duration": round(flow.duration(), 2),
            "packet_count": flow.fwd_packets + flow.bwd_packets,
            "last_seen_seconds": round(now - flow.last_seen, 2)
        })

    with open(ACTIVE_FLOWS_PATH, "w") as f:
        json.dump(flows_snapshot, f)


def start_live_capture():
    write_capture_status(True)

    manager = FlowManager(flow_timeout=FLOW_TIMEOUT_SECONDS)
    ids_model = IDSModel(model_dir=MODEL_DIR)

    cmd = [
        TSHARK_BIN,
        "-i", CAPTURE_IFACE,
        "-l",
        "-T", "fields",
        "-e", "frame.len",
        "-e", "tcp.flags",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "ip.proto",
    ]

    print(f"[INFO] Starting TShark on interface: {CAPTURE_IFACE}")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    q = queue.Queue()
    threading.Thread(target=tshark_reader, args=(process, q), daemon=True).start()

    last_finalize = time.time()
    last_active_dump = time.time()
    last_traffic_dump = time.time()

    total_packets = tcp_packets = udp_packets = 0

    try:
        while True:
            try:
                line = q.get(timeout=0.5)
            except queue.Empty:
                line = None

            if line:
                fields = line.strip().split("\t")
                if len(fields) >= 9:
                    (
                        frame_len,
                        tcp_flags,
                        src_ip,
                        dst_ip,
                        tcp_src,
                        tcp_dst,
                        udp_src,
                        udp_dst,
                        proto
                    ) = fields

                    packet_length = int(frame_len) if frame_len.isdigit() else 0
                    flags = tcp_flags if tcp_flags else None

                    protocol = None
                    if tcp_src and tcp_dst:
                        protocol = "TCP"
                        src_port = int(tcp_src)
                        dst_port = int(tcp_dst)
                        tcp_packets += 1
                    elif udp_src and udp_dst:
                        protocol = "UDP"
                        src_port = int(udp_src)
                        dst_port = int(udp_dst)
                        udp_packets += 1

                    if protocol:
                        manager.process_packet(
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                            protocol,
                            packet_length,
                            flags
                        )
                        total_packets += 1

            now = time.time()

            if now - last_finalize >= FINALIZE_INTERVAL:
                last_finalize = now
                finalized_flows = manager.finalize_expired_flows()

                for flow in finalized_flows:
                    if not eligible_for_ml(flow):
                        continue

                    features = extract_model_features(flow)
                    result = ids_model.predict(features)
                    insert_alert(flow, result)

                    print(
                        f"[ALERT] {flow.src_ip}:{flow.src_port} -> "
                        f"{flow.dst_ip}:{flow.dst_port} | "
                        f"{result['severity']} | "
                        f"P={result['attack_probability']}"
                    )

            if now - last_active_dump >= ACTIVE_FLOWS_DUMP_INTERVAL:
                dump_active_flows(manager)
                last_active_dump = now

            if now - last_traffic_dump >= LIVE_TRAFFIC_INTERVAL:
                with open(LIVE_TRAFFIC_PATH, "w") as f:
                    json.dump({
                        "timestamp": now,
                        "total_packets": total_packets,
                        "tcp_packets": tcp_packets,
                        "udp_packets": udp_packets
                    }, f)

                total_packets = tcp_packets = udp_packets = 0
                last_traffic_dump = now

    except KeyboardInterrupt:
        print("\n[INFO] Stopping capture...")
    finally:
        write_capture_status(False)
        process.terminate()


if __name__ == "__main__":
    start_live_capture()
