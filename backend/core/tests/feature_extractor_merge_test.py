import time
from flow import Flow
from feature_extractor import extract_model_features


def main():
    flow = Flow(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=80,
        protocol="TCP"
    )

    flow.update_forward(100, flags=["SYN"])
    time.sleep(0.2)
    flow.update_forward(150, flags=["ACK"])
    time.sleep(1.1)   # idle
    flow.update_backward(120, flags=["ACK"])

    features = extract_model_features(flow)

    print("Feature count:", len(features))
    print("---- Features (in order) ----")
    for k, v in features.items():
        print(f"{k}: {round(v, 3) if isinstance(v, float) else v}")


if __name__ == "__main__":
    main()
