import time
from flow import Flow


class FlowManager:
    """
    Manages all active network flows.
    Responsibilities:
    - Create/retrieve flows
    - Determine packet direction
    - Update flow counters
    - Finalize inactive flows
    """

    def __init__(self, flow_timeout=30):
        self.active_flows = {}
        self.flow_timeout = flow_timeout  # seconds

    def _make_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        return (src_ip, dst_ip, src_port, dst_port, protocol)

    def get_flow_and_direction(self, src_ip, dst_ip, src_port, dst_port, protocol):
        forward_key = self._make_flow_key(
            src_ip, dst_ip, src_port, dst_port, protocol
        )

        backward_key = self._make_flow_key(
            dst_ip, src_ip, dst_port, src_port, protocol
        )

        if forward_key in self.active_flows:
            return self.active_flows[forward_key], "forward", forward_key

        if backward_key in self.active_flows:
            return self.active_flows[backward_key], "backward", backward_key

        flow = Flow(src_ip, dst_ip, src_port, dst_port, protocol)
        self.active_flows[forward_key] = flow
        return flow, "forward", forward_key

    def process_packet(
        self,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        packet_length,
        flags=None
    ):
        flow, direction, key = self.get_flow_and_direction(
            src_ip, dst_ip, src_port, dst_port, protocol
        )

        if direction == "forward":
            flow.update_forward(packet_length, flags)
        else:
            flow.update_backward(packet_length, flags)

        return flow, direction

    def finalize_expired_flows(self):
        """
        Returns:
            list of finalized Flow objects
        """
        now = time.time()
        expired_keys = []

        for key, flow in self.active_flows.items():
            if now - flow.last_seen > self.flow_timeout:
                expired_keys.append(key)

        finalized_flows = []
        for key in expired_keys:
            finalized_flows.append(self.active_flows.pop(key))

        return finalized_flows

    def total_flows(self):
        return len(self.active_flows)
