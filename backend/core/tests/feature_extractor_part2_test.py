import time
from flow import Flow
from feature_extractor import extract_features_part2


def main():
    flow = Flow(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP"
    )

    flow.update_forward(100)
    time.sleep(0.2)
    flow.update_forward(120)
    time.sleep(1.2)   # idle
    flow.update_backward(80)

    features = extract_features_part2(flow)

    for k, v in features.items():
        print(f"{k}: {round(v, 3)}")


if __name__ == "__main__":
    main()
