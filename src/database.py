import logging
import sqlite3
from contextlib import contextmanager
from typing import List, Optional

import pandas as pd


class DatabaseManager:
    def __init__(self, db_path: str = "network_traffic.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the database with required tables and indexes."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Create traffic table with improved schema
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    packet_length INTEGER,
                    timestamp TEXT,
                    flags TEXT,
                    ttl INTEGER,
                    window_size INTEGER
                )
            """)

            # Create indexes for better query performance
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_protocol ON traffic(protocol)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_timestamp ON traffic(timestamp)"
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON traffic(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON traffic(dst_ip)")
            conn.commit()

    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def insert_traffic(self, data: dict) -> bool:
        """Insert a new traffic record."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO traffic 
                    (protocol, src_ip, dst_ip, src_port, dst_port, packet_length, timestamp, flags, ttl, window_size)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        data.get("protocol"),
                        data.get("src_ip"),
                        data.get("dst_ip"),
                        data.get("src_port"),
                        data.get("dst_port"),
                        data.get("packet_length"),
                        data.get("timestamp"),
                        data.get("flags"),
                        data.get("ttl"),
                        data.get("window_size"),
                    ),
                )
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Error inserting traffic data: {e}")
            return False

    def fetch_traffic(
        self, protocol_filter: Optional[str] = None, limit: int = 100
    ) -> pd.DataFrame:
        """Fetch traffic data with optional protocol filter."""
        try:
            with self.get_connection() as conn:
                if protocol_filter and protocol_filter != "All":
                    query = """
                        SELECT * FROM traffic 
                        WHERE protocol = ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """
                    df = pd.read_sql(query, conn, params=(protocol_filter, limit))
                else:
                    query = "SELECT * FROM traffic ORDER BY timestamp DESC LIMIT ?"
                    df = pd.read_sql(query, conn, params=(limit,))
                return df
        except Exception as e:
            logging.error(f"Error fetching traffic data: {e}")
            return pd.DataFrame()

    def get_protocol_types(self) -> List[str]:
        """Get list of unique protocols."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT DISTINCT protocol FROM traffic")
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Error fetching protocol types: {e}")
            return []

    def get_traffic_statistics(self) -> dict:
        """Get traffic statistics."""
        try:
            with self.get_connection() as conn:
                stats = {
                    "total_packets": pd.read_sql(
                        "SELECT COUNT(*) as count FROM traffic", conn
                    ).iloc[0, 0],
                    "total_bytes": pd.read_sql(
                        "SELECT SUM(packet_length) as total FROM traffic", conn
                    ).iloc[0, 0],
                    "unique_ips": pd.read_sql(
                        """
                        SELECT COUNT(DISTINCT src_ip) + COUNT(DISTINCT dst_ip) as count 
                        FROM traffic
                    """,
                        conn,
                    ).iloc[0, 0],
                    "top_talkers": pd.read_sql(
                        """
                        SELECT src_ip, COUNT(*) as count 
                        FROM traffic 
                        GROUP BY src_ip 
                        ORDER BY count DESC 
                        LIMIT 5
                    """,
                        conn,
                    ).to_dict("records"),
                }
                return stats
        except Exception as e:
            logging.error(f"Error fetching traffic statistics: {e}")
            return {}
