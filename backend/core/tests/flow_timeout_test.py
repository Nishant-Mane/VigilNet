import time
from flow_manager import FlowManager


def main():
    manager = FlowManager(flow_timeout=1)  # 1 second timeout for test

    # create a flow
    manager.process_packet(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        packet_length=100,
        flags=["SYN"]
    )

    print("Active flows (initial):", manager.total_flows())

    # wait for timeout
    time.sleep(1.5)

    finalized = manager.finalize_expired_flows()

    print("Finalized flows:", len(finalized))
    print("Active flows (after):", manager.total_flows())


if __name__ == "__main__":
    main()
