from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Boolean, Index
from datetime import datetime
from .database import Base


class NodeConfig(Base):
    __tablename__ = "nodes"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    node_type = Column(String, nullable=False)  # 'miner', 'aggregator', 'output'
    config = Column(JSON, default={})
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime, nullable=True)


class NodeEdge(Base):
    __tablename__ = "node_edges"
    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("nodes.id", ondelete="CASCADE"))
    target_id = Column(Integer, ForeignKey("nodes.id", ondelete="CASCADE"))


class IndicatorDB(Base):
    __tablename__ = "indicators"
    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, unique=True, index=True, nullable=False)
    ioc_type = Column(String, index=True, nullable=False)
    confidence = Column(Integer, default=50)
    source_node_id = Column(Integer, ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    expire_at = Column(DateTime, index=True)


class NodeRunLog(Base):
    __tablename__ = "node_run_logs"
    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(Integer, ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    status = Column(String, nullable=False)  # 'success', 'error', 'running'
    message = Column(String)
    iocs_processed = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)


Index("idx_feed_extraction", IndicatorDB.ioc_type, IndicatorDB.confidence, IndicatorDB.expire_at)
