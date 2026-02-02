from flow_manager import FlowManager


def main():
    manager = FlowManager()

    # create first flow
    f1 = manager.get_or_create_flow(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=53,
        protocol="UDP"
    )

    # same flow again (should NOT create new)
    f2 = manager.get_or_create_flow(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=53,
        protocol="UDP"
    )

    # different flow
    f3 = manager.get_or_create_flow(
        src_ip="192.168.1.11",
        dst_ip="8.8.4.4",
        src_port=40000,
        dst_port=53,
        protocol="UDP"
    )

    print("Total flows:", manager.total_flows())
    print("f1 is f2:", f1 is f2)
    print("f1 is f3:", f1 is f3)


if __name__ == "__main__":
    main()
