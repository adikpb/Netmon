import logging
import queue
import sqlite3
import threading
import time

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet, Padding, Raw
from scapy.sendrecv import AsyncSniffer

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class TrafficLogger:
    def __init__(self):
        self.db_queue = queue.Queue()  # Queue for async DB writes
        self.conn = None
        self.cursor = None
        self.start_time = time.time()
        self.capture_count = 0
        self.running = True

        # Start database worker thread
        self.db_thread = threading.Thread(target=self.process_db_queue, daemon=True)
        self.db_thread.start()

        # Start packet sniffer
        self.sniffer = AsyncSniffer(prn=self.analyze_packet)

    def analyze_packet(self, packet: Packet):
        try:
            self.capture_count += 1
            protocol = "Unknown"
            for layer in packet.layers()[::-1]:
                if layer not in (Raw, Padding):
                    protocol = layer.__name__
                    break

            src_ip, dst_ip = None, None
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            src_port, dst_port = None, None
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            packet_length = len(packet)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            # Queue packet data for database insertion
            self.db_queue.put(
                (protocol, src_ip, dst_ip, src_port, dst_port, packet_length, timestamp)
            )

        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def process_db_queue(self):
        self.conn = sqlite3.connect("network_traffic.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT, 
                src_ip TEXT, 
                dst_ip TEXT, 
                src_port INTEGER, 
                dst_port INTEGER,
                packet_length INTEGER, 
                timestamp TEXT
            )
            """
        )
        self.conn.commit()

        while self.running or not self.db_queue.empty():
            try:
                data = self.db_queue.get(timeout=1)
                if data:
                    self.cursor.execute(
                        """
                        INSERT INTO traffic (protocol, src_ip, dst_ip, src_port, dst_port, packet_length, timestamp) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        data,
                    )
                    self.conn.commit()
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Database error: {e}")

    def start_sniffer(self):
        try:
            self.sniffer.start()
            logging.info("Sniffer started.")
        except Exception as e:
            logging.error(f"Error starting sniffer: {e}")

    def stop_sniffer(self):
        self.sniffer.stop()
        logging.info("Sniffer stopped. Waiting for pending DB operations...")
        self.running = False
        self.db_thread.join()  # Ensure all pending database writes are completed
        if self.conn:
            self.conn.close()
        logging.info("Database connection closed.")

    def get_capture_duration(self):
        return time.time() - self.start_time

    def get_capture_count(self):
        return self.capture_count


if __name__ == "__main__":
    tf = TrafficLogger()
    try:
        tf.start_sniffer()
        logging.info("Press Ctrl+C to stop the sniffer.")

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping sniffer...")
        tf.stop_sniffer()
        logging.info(f"Total packets captured: {tf.get_capture_count()}")
