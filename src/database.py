import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd
import requests

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(
        self, db_path: str = "network_traffic.db", abuseipdb_key: Optional[str] = None
    ):
        self.db_path = db_path
        self.abuseipdb_key = abuseipdb_key
        logger.info(f"Initializing DatabaseManager with database at {db_path}")
        if not abuseipdb_key:
            logger.warning(
                "No AbuseIPDB API key provided - abuse checking will be disabled"
            )
        self._init_db()

    def _init_db(self):
        logger.info("Initializing database tables and indexes")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
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
                logger.debug("Traffic table created or verified")

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS flagged_ips (
                        ip TEXT PRIMARY KEY,
                        timestamp TEXT,
                        confidence_score INTEGER,
                        abuse_report TEXT
                    )
                """)
                logger.debug("Flagged IPs table created or verified")

                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_protocol ON traffic(protocol)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_timestamp ON traffic(timestamp)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_src_ip ON traffic(src_ip)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_dst_ip ON traffic(dst_ip)"
                )
                conn.commit()
                logger.debug("Database indexes created or verified")
                logger.info("Database initialization completed successfully")
            except Exception as e:
                logger.error(f"Error during database initialization: {e}")
                raise

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def insert_traffic(self, data: dict) -> bool:
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
                logger.debug(
                    f"Inserted traffic record for {data.get('src_ip')} -> {data.get('dst_ip')}"
                )
                return True
        except Exception as e:
            logger.error(f"Error inserting traffic data: {e}")
            return False

    def fetch_traffic(
        self,
        protocol_filter: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 100,
    ) -> pd.DataFrame:
        try:
            with self.get_connection() as conn:
                query = "SELECT * FROM traffic WHERE 1=1"
                params = []

                if protocol_filter and protocol_filter != "All":
                    query += " AND protocol = ?"
                    params.append(protocol_filter)
                    logger.debug(f"Applying protocol filter: {protocol_filter}")

                if start_date:
                    query += " AND timestamp >= ?"
                    params.append(start_date)
                    logger.debug(f"Applying start date filter: {start_date}")

                if end_date:
                    query += " AND timestamp <= ?"
                    params.append(end_date)
                    logger.debug(f"Applying end date filter: {end_date}")

                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                logger.debug(f"Executing query: {query} with params: {params}")
                df = pd.read_sql(query, conn, params=params)
                logger.debug(f"Retrieved {len(df)} traffic records")
                return df
        except Exception as e:
            logger.error(f"Error fetching traffic data: {e}")
            return pd.DataFrame()

    def get_protocol_types(self) -> List[str]:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT DISTINCT protocol FROM traffic")
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Error fetching protocol types: {e}")
            return []

    def get_traffic_statistics(self) -> dict:
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

    def check_ip_abuse(self, ip: str) -> Dict:
        logger.info(f"Checking abuse information for IP: {ip}")
        if not self.abuseipdb_key:
            logger.warning("AbuseIPDB API key not configured")
            return {"score": 0, "reports": "API key not configured"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": self.abuseipdb_key}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

        try:
            logger.debug(f"Making API request to AbuseIPDB for IP: {ip}")
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()["data"]
                score = data["abuseConfidenceScore"]
                reports = data.get("reports", [])
                logger.info(f"Received abuse score {score} for IP: {ip}")
                logger.debug(f"Found {len(reports)} abuse reports for IP: {ip}")
                return {"score": score, "reports": reports}
            else:
                logger.error(f"AbuseIPDB API error {response.status_code} for IP: {ip}")
                return {"score": 0, "reports": f"API Error: {response.status_code}"}
        except Exception as e:
            logger.error(f"Error checking IP abuse: {e}")
            return {"score": 0, "reports": str(e)}

    def flag_ip(self, ip: str) -> bool:
        logger.info(f"Flagging IP address: {ip}")
        try:
            abuse_info = self.check_ip_abuse(ip)
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO flagged_ips (ip, timestamp, confidence_score, abuse_report)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        ip,
                        datetime.now().isoformat(),
                        abuse_info["score"],
                        str(abuse_info["reports"]),
                    ),
                )
                conn.commit()
                logger.info(
                    f"Successfully flagged IP {ip} with abuse score {abuse_info['score']}"
                )
                return True
        except Exception as e:
            logger.error(f"Error flagging IP {ip}: {e}")
            return False

    def unflag_ip(self, ip: str) -> bool:
        logger.info(f"Unflagging IP address: {ip}")
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM flagged_ips WHERE ip = ?", (ip,))
                conn.commit()
                logger.info(f"Successfully unflagged IP: {ip}")
                return True
        except Exception as e:
            logger.error(f"Error unflagging IP {ip}: {e}")
            return False

    def get_flagged_ips(self) -> List[Dict[str, str]]:
        logger.debug("Fetching list of flagged IPs")
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ip, timestamp, confidence_score, abuse_report 
                    FROM flagged_ips
                """)
                results = [
                    {
                        "ip": row[0],
                        "timestamp": row[1],
                        "action": "Unflag",
                        "confidence_score": row[2],
                        "abuse_report": row[3],
                    }
                    for row in cursor.fetchall()
                ]
                logger.debug(f"Retrieved {len(results)} flagged IPs")
                return results
        except Exception as e:
            logger.error(f"Error fetching flagged IPs: {e}")
            return []

    def is_ip_flagged(self, ip: str) -> bool:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM flagged_ips WHERE ip = ?", (ip,))
                result = cursor.fetchone() is not None
                logger.debug(
                    f"Checked flag status for IP {ip}: {'flagged' if result else 'not flagged'}"
                )
                return result
        except Exception as e:
            logger.error(f"Error checking flag status for IP {ip}: {e}")
            return False
