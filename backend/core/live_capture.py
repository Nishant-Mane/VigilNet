import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import subprocess
import time
import threading
import queue
from storage.db_writer import insert_alert


from flow_manager import FlowManager
from feature_extractor import extract_model_features
from ML.inference import IDSModel

# ================= CONFIG =================
TSHARK_INTERFACE_INDEX = "2"
FLOW_TIMEOUT_SECONDS = 30
FINALIZE_INTERVAL = 2  # seconds
MODEL_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "ML", "model")
)

# =========================================


def tshark_reader(proc, q):
    """
    Reads tshark stdout in a separate thread (Windows-safe)
    and pushes each line into a queue.
    """
    for line in proc.stdout:
        q.put(line)


def start_live_capture():
    # ---- Core components ----
    manager = FlowManager(flow_timeout=FLOW_TIMEOUT_SECONDS)
    ids_model = IDSModel(model_dir=MODEL_DIR)

    # ---- tshark command ----
    cmd = [
        r"C:\Program Files\Wireshark\tshark.exe",
        "-i", TSHARK_INTERFACE_INDEX,
        "-l",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "ip.proto"
    ]

    print("Starting live packet capture via tshark...")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    line_queue = queue.Queue()

    reader_thread = threading.Thread(
        target=tshark_reader,
        args=(process, line_queue),
        daemon=True
    )
    reader_thread.start()

    last_finalize = time.time()

    try:
        while True:
            # ------------- PACKET INGEST (NON-BLOCKING) -------------
            try:
                line = line_queue.get(timeout=0.5)
            except queue.Empty:
                line = None

            if line:
                fields = line.strip().split("\t")
                if len(fields) >= 7:
                    src_ip, dst_ip, tcp_src, tcp_dst, udp_src, udp_dst, proto = fields

                    protocol = None
                    if tcp_src and tcp_dst:
                        src_port = int(tcp_src)
                        dst_port = int(tcp_dst)
                        protocol = "TCP"
                    elif udp_src and udp_dst:
                        src_port = int(udp_src)
                        dst_port = int(udp_dst)
                        protocol = "UDP"

                    if protocol:
                        manager.process_packet(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=protocol,
                            packet_length=0,   # length not wired yet
                            flags=[]
                        )

            # ------------- FLOW FINALIZATION + ML -------------
            now = time.time()
            if now - last_finalize >= FINALIZE_INTERVAL:
                last_finalize = now

                finalized_flows = manager.finalize_expired_flows()

                for flow in finalized_flows:
                    print(
                        f"[FLOW FINALIZED] "
                        f"{flow.src_ip}:{flow.src_port} -> "
                        f"{flow.dst_ip}:{flow.dst_port} | "
                        f"Proto={flow.protocol} | "
                        f"Duration={flow.duration():.2f}s | "
                        f"Packets={flow.fwd_packets + flow.bwd_packets}"
                    )

                    # ---- Feature extraction ----
                    features = extract_model_features(flow)

                    # ---- ML inference ----
                    result = ids_model.predict(features)
                    insert_alert(flow, result)


                    print("[ML RESULT]")
                    print(f"  Attack Probability: {result['attack_probability']}")
                    print(f"  Prediction: {result['prediction']}")
                    print(f"  Severity: {result['severity']}")

                print(f"Active flows: {manager.total_flows()}")

    except KeyboardInterrupt:
        print("\nStopping capture...")

    finally:
        process.terminate()


if __name__ == "__main__":
    start_live_capture()
