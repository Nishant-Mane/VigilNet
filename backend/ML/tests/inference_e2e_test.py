import sys
import os
import time

# Add backend/ to Python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
sys.path.append(BACKEND_DIR)

from inference import IDSModel
from core.flow import Flow
from core.feature_extractor import extract_model_features


def main():
    model = IDSModel(model_dir="model")

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
    time.sleep(1.1)
    flow.update_backward(120, flags=["ACK"])

    features = extract_model_features(flow)
    result = model.predict(features)

    print("Prediction result:")
    for k, v in result.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
