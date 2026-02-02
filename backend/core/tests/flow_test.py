import time
from flow import Flow


def main():
    flow = Flow(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=53,
        protocol="UDP"
    )

    # simulate packets
    flow.update_forward(packet_length=120)
    time.sleep(0.1)
    flow.update_forward(packet_length=80)
    time.sleep(0.1)
    flow.update_backward(packet_length=60)

    print("Duration:", round(flow.duration(), 3))
    print("Forward packets:", flow.fwd_packets)
    print("Backward packets:", flow.bwd_packets)
    print("Forward bytes:", flow.fwd_bytes)
    print("Backward bytes:", flow.bwd_bytes)


if __name__ == "__main__":
    main()
