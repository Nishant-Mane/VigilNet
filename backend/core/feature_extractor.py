import math
import statistics


def _safe_mean(values):
    return statistics.mean(values) if values else 0.0


def _safe_std(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def _safe_var(values):
    return statistics.variance(values) if len(values) > 1 else 0.0


def extract_features_part1(flow):
    """
    Extract Part-1 features (packet-length stats + basics)
    from a finalized Flow object.
    """

    # Collect packet lengths
    fwd_lengths = []
    bwd_lengths = []

    # We don't store per-packet lists in Flow,
    # so we approximate using totals and counts
    # (This will be refined later if needed)

    # Backward packet stats
    if flow.bwd_packets > 0:
        bwd_mean = flow.bwd_bytes / flow.bwd_packets
        bwd_lengths = [bwd_mean] * flow.bwd_packets
    else:
        bwd_mean = 0.0
        bwd_lengths = []

    # Overall packet stats
    total_packets = flow.fwd_packets + flow.bwd_packets
    total_bytes = flow.fwd_bytes + flow.bwd_bytes

    if total_packets > 0:
        pkt_mean = total_bytes / total_packets
        pkt_lengths = [pkt_mean] * total_packets
    else:
        pkt_mean = 0.0
        pkt_lengths = []

    features = {
        # --- Backward packet length stats ---
        "Bwd Packet Length Std": _safe_std(bwd_lengths),
        "Bwd Packet Length Mean": bwd_mean,
        "Avg Bwd Segment Size": bwd_mean,
        "Bwd Packet Length Max": max(bwd_lengths) if bwd_lengths else 0.0,

        # --- Overall packet length stats ---
        "Packet Length Std": _safe_std(pkt_lengths),
        "Packet Length Max": max(pkt_lengths) if pkt_lengths else 0.0,
        "Avg Packet Size": pkt_mean,
        "Packet Length Mean": pkt_mean,
        "Packet Length Variance": _safe_var(pkt_lengths),

        # --- Flow basics ---
        "Flow Duration": flow.duration(),
        "Protocol": _protocol_to_int(flow.protocol),
        "FIN Flag Count": flow.fin_count,
    }

    return features


def _protocol_to_int(proto):
    """
    CICIDS-style protocol encoding.
    TCP=6, UDP=17, ICMP=1, else=0
    """
    proto = proto.upper()
    if proto == "TCP":
        return 6
    if proto == "UDP":
        return 17
    if proto == "ICMP":
        return 1
    return 0

import statistics


def _compute_iats(timestamps):
    if len(timestamps) < 2:
        return []
    return [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]


def _compute_idle_times(timestamps, idle_threshold=1.0):
    """
    Idle time = gap between packets > idle_threshold (seconds)
    """
    iats = _compute_iats(timestamps)
    return [iat for iat in iats if iat > idle_threshold]


def extract_features_part2(flow):
    """
    Extract Part-2 features: IAT + Idle metrics
    """

    # ---- IATs ----
    flow_iats = _compute_iats(flow.all_packet_times)
    fwd_iats = _compute_iats(flow.fwd_packet_times)

    # ---- Idle times ----
    idle_times = _compute_idle_times(flow.all_packet_times)

    features = {
        # Fwd IAT
        "Fwd IAT Std": statistics.stdev(fwd_iats) if len(fwd_iats) > 1 else 0.0,
        "Fwd IAT Max": max(fwd_iats) if fwd_iats else 0.0,
        "Fwd IAT Total": sum(fwd_iats) if fwd_iats else 0.0,

        # Flow IAT
        "Flow IAT Std": statistics.stdev(flow_iats) if len(flow_iats) > 1 else 0.0,
        "Flow IAT Max": max(flow_iats) if flow_iats else 0.0,

        # Idle
        "Idle Max": max(idle_times) if idle_times else 0.0,
        "Idle Mean": statistics.mean(idle_times) if idle_times else 0.0,
        "Idle Min": min(idle_times) if idle_times else 0.0,
    }

    return features

    # -------------------------------
# FINAL MODEL-READY EXTRACTOR
# -------------------------------

def extract_model_features(flow):
    """
    Returns a model-ready feature dictionary
    with EXACT schema and order.
    """

    part1 = extract_features_part1(flow)
    part2 = extract_features_part2(flow)

    features = {
        # --- Packet length stats ---
        "Bwd Packet Length Std": part1["Bwd Packet Length Std"],
        "Bwd Packet Length Mean": part1["Bwd Packet Length Mean"],
        "Avg Bwd Segment Size": part1["Avg Bwd Segment Size"],
        "Bwd Packet Length Max": part1["Bwd Packet Length Max"],

        "Packet Length Std": part1["Packet Length Std"],
        "Packet Length Max": part1["Packet Length Max"],
        "Avg Packet Size": part1["Avg Packet Size"],
        "Packet Length Mean": part1["Packet Length Mean"],
        "Packet Length Variance": part1["Packet Length Variance"],

        # --- IAT + Idle ---
        "Fwd IAT Std": part2["Fwd IAT Std"],
        "Idle Max": part2["Idle Max"],
        "Flow IAT Max": part2["Flow IAT Max"],
        "Fwd IAT Max": part2["Fwd IAT Max"],
        "Idle Mean": part2["Idle Mean"],
        "Idle Min": part2["Idle Min"],
        "Flow IAT Std": part2["Flow IAT Std"],
        "Fwd IAT Total": part2["Fwd IAT Total"],

        # --- Flow basics ---
        "Flow Duration": part1["Flow Duration"],
        "Protocol": part1["Protocol"],
        "FIN Flag Count": part1["FIN Flag Count"],
    }

    return features

