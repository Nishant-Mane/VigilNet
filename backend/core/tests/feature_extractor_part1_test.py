import time
from flow import Flow
from feature_extractor import extract_features_part1


def main():
    flow = Flow(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=80,
        protocol="TCP"
    )

    # simulate packets
    flow.update_forward(packet_length=100, flags=["SYN"])
    time.sleep(0.1)
    flow.update_forward(packet_length=150, flags=["ACK"])
    time.sleep(0.1)
    flow.update_backward(packet_length=120, flags=["ACK"])

    features = extract_features_part1(flow)

    for k, v in features.items():
        print(f"{k}: {round(v, 3) if isinstance(v, float) else v}")


if __name__ == "__main__":
    main()
