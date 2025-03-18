import time
import sqlite3

from scapy.sendrecv import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet, Padding, Raw


class TrafficLogger:
    def __init__(self):
        self.conn = None
        self.cursor = None
        self.start_time = time.time()
        self.capture_count = 0
        self.sniffer = AsyncSniffer(prn=self.analyze_packet)

    def analyze_packet(self, packet: Packet):
        try:
            self.capture_count += 1
            protocol = "Unknown"
            for i in packet.layers()[::-1]:
                if i not in (Raw, Padding):
                    protocol = i.__name__
                    break

            src_ip = None
            dst_ip = None
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            src_port = None
            dst_port = None
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            if packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            packet_length = len(packet)

            if self.cursor:
                self.cursor.execute(
                    "INSERT INTO traffic (protocol, src_ip, dst_ip, src_port, dst_port, packet_length, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
                    (protocol, src_ip, dst_ip, src_port, dst_port, packet_length),
                )
            if self.conn:
                self.conn.commit()

            if __name__ == "__main__":
                # debugging
                return packet
        except Exception as e:
            print(f"Error: {e}")

    def start_sniffer(self):
        try:
            # Create SQLite connection and cursor in the same thread
            self.conn = sqlite3.connect("network_traffic.db", check_same_thread=False)
            self.cursor = self.conn.cursor()
            self.cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    protocol TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
                    packet_length INTEGER, timestamp TEXT
                )
            """
            )
            self.conn.commit()

            self.sniffer.start()
        except Exception as e:
            print(f"Error: {e}")

    def stop_sniffer(self):
        self.sniffer.stop()

    def get_capture_duration(self):
        return time.time() - self.start_time

    def get_capture_count(self):
        return self.capture_count


if __name__ == "__main__":
    tf = TrafficLogger()
    tf.start_sniffer()
    input()  # Press anything to stop
    tf.stop_sniffer()
