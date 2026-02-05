import statistics


# ---------------- SAFE STATS ----------------

def _safe_mean(values):
    return statistics.mean(values) if values else 0.0


def _safe_std(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def _safe_var(values):
    return statistics.variance(values) if len(values) > 1 else 0.0


# ---------------- PART 1: PACKET STATS + BASICS ----------------

def extract_features_part1(flow):
    """
    Extract packet-length and basic flow features
    using REAL per-packet distributions.
    """

    all_lengths = flow.all_packet_lengths
    bwd_lengths = flow.bwd_packet_lengths

    features = {
        # --- Backward packet length stats ---
        "Bwd Packet Length Std": _safe_std(bwd_lengths),
        "Bwd Packet Length Mean": _safe_mean(bwd_lengths),
        "Avg Bwd Segment Size": _safe_mean(bwd_lengths),
        "Bwd Packet Length Max": max(bwd_lengths) if bwd_lengths else 0.0,

        # --- Overall packet length stats ---
        "Packet Length Std": _safe_std(all_lengths),
        "Packet Length Max": max(all_lengths) if all_lengths else 0.0,
        "Avg Packet Size": _safe_mean(all_lengths),
        "Packet Length Mean": _safe_mean(all_lengths),
        "Packet Length Variance": _safe_var(all_lengths),

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


# ---------------- PART 2: IAT + IDLE ----------------

def _compute_iats(timestamps):
    if len(timestamps) < 2:
        return []
    return [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]


def _compute_idle_times(timestamps, idle_threshold=1.0):
    iats = _compute_iats(timestamps)
    return [iat for iat in iats if iat > idle_threshold]


def extract_features_part2(flow):
    """
    Extract timing-based features (IAT + Idle).
    """

    flow_iats = _compute_iats(flow.all_packet_times)
    fwd_iats = _compute_iats(flow.fwd_packet_times)
    idle_times = _compute_idle_times(flow.all_packet_times)

    features = {
        # --- Forward IAT ---
        "Fwd IAT Std": _safe_std(fwd_iats),
        "Fwd IAT Max": max(fwd_iats) if fwd_iats else 0.0,
        "Fwd IAT Total": sum(fwd_iats) if fwd_iats else 0.0,

        # --- Flow IAT ---
        "Flow IAT Std": _safe_std(flow_iats),
        "Flow IAT Max": max(flow_iats) if flow_iats else 0.0,

        # --- Idle ---
        "Idle Max": max(idle_times) if idle_times else 0.0,
        "Idle Mean": _safe_mean(idle_times),
        "Idle Min": min(idle_times) if idle_times else 0.0,
    }

    return features


# ---------------- FINAL MODEL-READY EXTRACTOR ----------------

def extract_model_features(flow):
    """
    Returns a model-ready feature dictionary
    with EXACT schema expected by the model.
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
