from flow_manager import FlowManager


def main():
    manager = FlowManager()

    # forward packet
    manager.process_packet(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        packet_length=100,
        flags=["SYN"]
    )

    # forward packet
    manager.process_packet(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        packet_length=150,
        flags=["ACK"]
    )

    # backward packet
    flow, direction = manager.process_packet(
        src_ip="8.8.8.8",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=50000,
        protocol="TCP",
        packet_length=120,
        flags=["ACK"]
    )

    print("Direction:", direction)
    print("Forward packets:", flow.fwd_packets)
    print("Backward packets:", flow.bwd_packets)
    print("Forward bytes:", flow.fwd_bytes)
    print("Backward bytes:", flow.bwd_bytes)
    print("SYN count:", flow.syn_count)
    print("ACK count:", flow.ack_count)
    print("Total flows:", manager.total_flows())


if __name__ == "__main__":
    main()
