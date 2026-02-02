from flow_manager import FlowManager


def main():
    manager = FlowManager()

    # First packet (forward)
    flow1, dir1 = manager.get_flow_and_direction(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=53,
        protocol="UDP"
    )

    # Reverse packet (should map to same flow, backward)
    flow2, dir2 = manager.get_flow_and_direction(
        src_ip="8.8.8.8",
        dst_ip="192.168.1.10",
        src_port=53,
        dst_port=50000,
        protocol="UDP"
    )

    print("Same flow object:", flow1 is flow2)
    print("First direction:", dir1)
    print("Second direction:", dir2)
    print("Total flows:", manager.total_flows())


if __name__ == "__main__":
    main()
