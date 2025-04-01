import logging
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd
import requests
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from models import Traffic, FlaggedIP, init_db, get_session

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
        self.session_factory = init_db(db_path)

    def insert_traffic(self, data: dict) -> bool:
        try:
            with get_session(self.session_factory) as session:
                traffic = Traffic(
                    protocol=data.get("protocol"),
                    src_ip=data.get("src_ip"),
                    dst_ip=data.get("dst_ip"),
                    src_port=data.get("src_port"),
                    dst_port=data.get("dst_port"),
                    packet_length=data.get("packet_length"),
                    timestamp=datetime.fromisoformat(data.get("timestamp")),
                    flags=data.get("flags"),
                    ttl=data.get("ttl"),
                    window_size=data.get("window_size"),
                )
                session.add(traffic)
                session.commit()
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
            with get_session(self.session_factory) as session:
                query = session.query(Traffic)

                if protocol_filter and protocol_filter != "All":
                    query = query.filter(Traffic.protocol == protocol_filter)
                    logger.debug(f"Applying protocol filter: {protocol_filter}")

                if start_date:
                    query = query.filter(Traffic.timestamp >= datetime.fromisoformat(start_date))
                    logger.debug(f"Applying start date filter: {start_date}")

                if end_date:
                    query = query.filter(Traffic.timestamp <= datetime.fromisoformat(end_date))
                    logger.debug(f"Applying end date filter: {end_date}")

                query = query.order_by(desc(Traffic.timestamp)).limit(limit)
                logger.debug(f"Executing query with limit: {limit}")

                df = pd.read_sql(query.statement, session.bind)
                logger.debug(f"Retrieved {len(df)} traffic records")
                return df
        except Exception as e:
            logger.error(f"Error fetching traffic data: {e}")
            return pd.DataFrame()

    def get_protocol_types(self) -> List[str]:
        try:
            with get_session(self.session_factory) as session:
                protocols = session.query(Traffic.protocol).distinct().all()
                return [p[0] for p in protocols]
        except Exception as e:
            logging.error(f"Error fetching protocol types: {e}")
            return []

    def get_traffic_statistics(self) -> dict:
        try:
            with get_session(self.session_factory) as session:
                stats = {
                    "total_packets": session.query(func.count(Traffic.id)).scalar(),
                    "total_bytes": session.query(func.sum(Traffic.packet_length)).scalar() or 0,
                    "unique_ips": session.query(
                        func.count(func.distinct(Traffic.src_ip)) + 
                        func.count(func.distinct(Traffic.dst_ip))
                    ).scalar(),
                    "top_talkers": [
                        {"src_ip": row[0], "count": row[1]}
                        for row in session.query(
                            Traffic.src_ip,
                            func.count(Traffic.id)
                        ).group_by(Traffic.src_ip).order_by(
                            desc(func.count(Traffic.id))
                        ).limit(5).all()
                    ]
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
            with get_session(self.session_factory) as session:
                flagged_ip = FlaggedIP(
                    ip=ip,
                    timestamp=datetime.now(),
                    confidence_score=abuse_info["score"],
                    abuse_report=str(abuse_info["reports"]),
                )
                session.merge(flagged_ip)
                session.commit()
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
            with get_session(self.session_factory) as session:
                session.query(FlaggedIP).filter(FlaggedIP.ip == ip).delete()
                session.commit()
                logger.info(f"Successfully unflagged IP: {ip}")
                return True
        except Exception as e:
            logger.error(f"Error unflagging IP {ip}: {e}")
            return False

    def get_flagged_ips(self) -> List[Dict[str, str]]:
        logger.debug("Fetching list of flagged IPs")
        try:
            with get_session(self.session_factory) as session:
                flagged_ips = session.query(FlaggedIP).all()
                results = [
                    {
                        "ip": ip.ip,
                        "timestamp": ip.timestamp.isoformat(),
                        "action": "Unflag",
                        "confidence_score": ip.confidence_score,
                        "abuse_report": ip.abuse_report,
                    }
                    for ip in flagged_ips
                ]
                logger.debug(f"Retrieved {len(results)} flagged IPs")
                return results
        except Exception as e:
            logger.error(f"Error fetching flagged IPs: {e}")
            return []

    def is_ip_flagged(self, ip: str) -> bool:
        try:
            with get_session(self.session_factory) as session:
                result = session.query(FlaggedIP).filter(FlaggedIP.ip == ip).first() is not None
                logger.debug(
                    f"Checked flag status for IP {ip}: {'flagged' if result else 'not flagged'}"
                )
                return result
        except Exception as e:
            logger.error(f"Error checking flag status for IP {ip}: {e}")
            return False
