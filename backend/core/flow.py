import time


class Flow:
    """
    Core domain object representing ONE network flow.
    Used by:
    - Flow Manager
    - Feature Extractor
    - Storage layer
    - API responses
    """

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        # ---- Identity (5-tuple) ----
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        # ---- Timestamp tracking ----
        self.all_packet_times = []
        self.fwd_packet_times = []
        self.bwd_packet_times = []

        # ---- Packet length tracking (CRITICAL FIX) ----
        self.all_packet_lengths = []
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []

        # ---- Timing ----
        self.start_time = time.time()
        self.last_seen = self.start_time

        # ---- Packet counters ----
        self.fwd_packets = 0
        self.bwd_packets = 0

        # ---- Byte counters ----
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        # ---- TCP flag counters ----
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0

    def update_forward(self, packet_length, flags=None):
        now = time.time()

        self.all_packet_times.append(now)
        self.fwd_packet_times.append(now)

        self.all_packet_lengths.append(packet_length)
        self.fwd_packet_lengths.append(packet_length)

        self.fwd_packets += 1
        self.fwd_bytes += packet_length
        self.last_seen = now

        self._update_flags(flags)

    def update_backward(self, packet_length, flags=None):
        now = time.time()

        self.all_packet_times.append(now)
        self.bwd_packet_times.append(now)

        self.all_packet_lengths.append(packet_length)
        self.bwd_packet_lengths.append(packet_length)

        self.bwd_packets += 1
        self.bwd_bytes += packet_length
        self.last_seen = now

        self._update_flags(flags)

    def _update_flags(self, flags):
        if not flags:
            return

        # Normalize flags safely (handles numeric / hex / string)
        flags = str(flags).upper()

        if "FIN" in flags:
            self.fin_count += 1
        if "SYN" in flags:
            self.syn_count += 1
        if "RST" in flags:
            self.rst_count += 1
        if "PSH" in flags:
            self.psh_count += 1
        if "ACK" in flags:
            self.ack_count += 1
        if "URG" in flags:
            self.urg_count += 1

    def duration(self):
        return self.last_seen - self.start_time
