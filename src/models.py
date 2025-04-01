from datetime import datetime
from typing import Optional, Generator
from contextlib import contextmanager

from sqlalchemy import Column, Integer, String, DateTime, Float, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

Base = declarative_base()


class Traffic(Base):
    __tablename__ = "traffic"

    id = Column(Integer, primary_key=True)
    protocol = Column(String, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    packet_length = Column(Integer)
    timestamp = Column(DateTime, index=True)
    flags = Column(String)
    ttl = Column(Integer)
    window_size = Column(Integer)


class FlaggedIP(Base):
    __tablename__ = "flagged_ips"

    ip = Column(String, primary_key=True)
    timestamp = Column(DateTime)
    confidence_score = Column(Integer)
    abuse_report = Column(String)


def init_db(db_path: str = "network_traffic.db"):
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@contextmanager
def get_session(session_factory) -> Generator[Session, None, None]:
    session = session_factory()
    try:
        yield session
    finally:
        session.close() 