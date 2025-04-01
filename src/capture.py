import atexit
import logging
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional

from scapy.all import ICMP, IP, TCP, UDP, Padding, Raw, sniff  # pyright: ignore

from database import DatabaseManager

logger = logging.getLogger(__name__)


class TrafficLogger:
    def __init__(self):
        self.start_time: Optional[float] = None
        self.packet_count = 0
        self.db = DatabaseManager()
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        logger.info("Initializing TrafficLogger")
        atexit.register(self.stop_sniffer)

    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        try:
            protocol = "Unknown"
            for layer in packet.layers()[::-1]:
                if layer not in (Raw, Padding):
                    protocol = layer.__name__
                    break

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                logger.debug(f"Processing packet: {protocol} {src_ip} -> {dst_ip}")

                info = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
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
                    logger.debug(
                        f"TCP flags: {packet[TCP].flags}, window: {packet[TCP].window}"
                    )
                elif UDP in packet:
                    info.update(
                        {"src_port": packet[UDP].sport, "dst_port": packet[UDP].dport}
                    )
                    logger.debug(
                        f"UDP ports: {packet[UDP].sport} -> {packet[UDP].dport}"
                    )
                elif ICMP in packet:
                    info.update({"type": packet[ICMP].type, "code": packet[ICMP].code})
                    logger.debug(
                        f"ICMP type: {packet[ICMP].type}, code: {packet[ICMP].code}"
                    )

                return info
            return None
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}", exc_info=True)
            return None

    def _packet_callback(self, packet):
        try:
            if not self.is_running:
                return

            packet_info = self._extract_packet_info(packet)
            if packet_info:
                self.packet_count += 1
                if not self.db.insert_traffic(packet_info):
                    logger.error("Failed to insert packet data into database")
        except Exception as e:
            logger.error(f"Error in packet callback: {e}", exc_info=True)

    def _sniff_thread(self):
        try:
            self.start_time = time.time()
            self.packet_count = 0
            self.is_running = True
            logger.info("Starting packet capture thread")

            sniff(
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda x: not self.is_running,
            )
        except Exception as e:
            logger.error(f"Error in sniffer thread: {e}", exc_info=True)
            self.stop_sniffer()

    def start_sniffer(self):
        if not self.is_running and (
            not self.sniffer_thread or not self.sniffer_thread.is_alive()
        ):
            logger.info("Starting packet sniffer")
            self.sniffer_thread = threading.Thread(target=self._sniff_thread)
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()
            logger.info("Packet capture thread started successfully")

    def stop_sniffer(self):
        if self.is_running:
            logger.info("Stopping packet sniffer")
            self.is_running = False
            if self.sniffer_thread and self.sniffer_thread.is_alive():
                self.sniffer_thread.join(timeout=1.0)
                logger.info(
                    f"Packet capture stopped. Total packets captured: {self.packet_count}"
                )

    def get_capture_duration(self) -> float:
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time

    def get_capture_count(self) -> int:
        return self.packet_count

    def get_capture_stats(self) -> Dict[str, Any]:
        duration = self.get_capture_duration()
        count = self.get_capture_count()
        pps = count / duration if duration > 0 else 0

        logger.debug(
            f"Capture stats - Duration: {duration:.1f}s, "
            f"Packets: {count}, PPS: {pps:.2f}"
        )

        return {
            "duration": duration,
            "packet_count": count,
            "packets_per_second": pps,
        }


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("network_monitor.log"),
            logging.StreamHandler(),
        ],
    )

    logger.info("Starting standalone packet capture")
    tf = TrafficLogger()
    try:
        tf.start_sniffer()
        logger.info("Press Ctrl+C to stop the sniffer")

        while True:
            time.sleep(1)
            stats = tf.get_capture_stats()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
        tf.stop_sniffer()
        final_stats = tf.get_capture_stats()
        logger.info(
            f"Final capture stats - Duration: {final_stats['duration']:.1f}s, "
            f"Total packets: {final_stats['packet_count']}, "
            f"Avg PPS: {final_stats['packets_per_second']:.2f}"
        )
