import atexit
import logging
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional

from scapy.all import ICMP, IP, TCP, UDP, Padding, Raw, sniff

from database import DatabaseManager


class TrafficLogger:
    def __init__(self):
        self.start_time: Optional[float] = None
        self.packet_count = 0
        self.db = DatabaseManager()
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self._setup_logging()
        # Register cleanup on program exit
        atexit.register(self.stop_sniffer)

    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("network_monitor.log"),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)

    def _extract_packet_info(self, packet) -> Dict[str, Any]:
        """Extract relevant information from a packet."""
        try:
            protocol = "Unknown"
            for layer in packet.layers()[::-1]:
                if layer not in (Raw, Padding):
                    protocol = layer.__name__
                    break
            if IP in packet:
                info = {
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "protocol": protocol,
                    "packet_length": len(packet),
                    "timestamp": datetime.now().isoformat(),
                    "ttl": packet[IP].ttl,
                    "flags": None,
                    "window_size": None,
                    "src_port": None,
                    "dst_port": None,
                }

                if TCP in packet:
                    info.update(
                        {
                            "src_port": packet[TCP].sport,
                            "dst_port": packet[TCP].dport,
                            "flags": str(packet[TCP].flags),
                            "window_size": packet[TCP].window,
                        }
                    )
                elif UDP in packet:
                    info.update(
                        {"src_port": packet[UDP].sport, "dst_port": packet[UDP].dport}
                    )
                elif ICMP in packet:
                    info.update({"type": packet[ICMP].type, "code": packet[ICMP].code})

                return info
            return None
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None

    def _packet_callback(self, packet):
        """Callback function for packet processing."""
        try:
            if not self.is_running:
                return

            packet_info = self._extract_packet_info(packet)
            if packet_info:
                self.packet_count += 1
                if self.db.insert_traffic(packet_info):
                    self.logger.debug(f"Packet captured: {packet_info}")
                else:
                    self.logger.error("Failed to insert packet data into database")
        except Exception as e:
            self.logger.error(f"Error in packet callback: {e}")

    def _sniff_thread(self):
        """Thread function for packet capture."""
        try:
            self.start_time = time.time()
            self.packet_count = 0
            self.is_running = True
            self.logger.info("Starting packet capture...")

            sniff(
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda x: not self.is_running,
            )
        except Exception as e:
            self.logger.error(f"Error in sniffer thread: {e}")
            self.stop_sniffer()

    def start_sniffer(self):
        """Start the packet sniffer in a separate thread."""
        if not self.is_running and (
            not self.sniffer_thread or not self.sniffer_thread.is_alive()
        ):
            self.sniffer_thread = threading.Thread(target=self._sniff_thread)
            self.sniffer_thread.daemon = (
                True  # Thread will exit when main program exits
            )
            self.sniffer_thread.start()
            self.logger.info("Packet capture thread started")

    def stop_sniffer(self):
        """Stop the packet sniffer."""
        if self.is_running:
            self.is_running = False
            if self.sniffer_thread and self.sniffer_thread.is_alive():
                self.sniffer_thread.join(
                    timeout=1.0
                )  # Wait up to 1 second for thread to finish
            self.logger.info("Stopping packet capture")

    def get_capture_duration(self) -> float:
        """Get the duration of the capture in seconds."""
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time

    def get_capture_count(self) -> int:
        """Get the total number of packets captured."""
        return self.packet_count

    def get_capture_stats(self) -> Dict[str, Any]:
        """Get capture statistics."""
        return {
            "duration": self.get_capture_duration(),
            "packet_count": self.get_capture_count(),
            "packets_per_second": self.packet_count / self.get_capture_duration()
            if self.get_capture_duration() > 0
            else 0,
        }


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
