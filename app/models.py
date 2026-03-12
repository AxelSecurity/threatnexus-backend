from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Boolean, Index, UniqueConstraint
from datetime import datetime
from .database import Base


class NodeConfig(Base):
    __tablename__ = "nodes"
    id        = Column(Integer, primary_key=True, index=True)
    name      = Column(String, unique=True, index=True, nullable=False)
    node_type = Column(String, nullable=False)  # 'miner', 'whitelist', 'aggregator', 'output'
    config    = Column(JSON, default={})
    is_active = Column(Boolean, default=True)
    last_run  = Column(DateTime, nullable=True)


class NodeEdge(Base):
    __tablename__ = "node_edges"
    id        = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("nodes.id", ondelete="CASCADE"))
    target_id = Column(Integer, ForeignKey("nodes.id", ondelete="CASCADE"))


class IndicatorDB(Base):
    __tablename__ = "indicators"
    id             = Column(Integer, primary_key=True, index=True)
    value          = Column(String, nullable=False, index=True)   # NOT unique=True — constraint is composite below
    ioc_type       = Column(String, index=True, nullable=False)
    confidence     = Column(Integer, default=50)
    source_node_id = Column(Integer, ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True, index=True)
    first_seen     = Column(DateTime, default=datetime.utcnow)
    last_seen      = Column(DateTime, default=datetime.utcnow)
    expire_at      = Column(DateTime, index=True)

    __table_args__ = (
        # Same IOC value can exist in multiple nodes (e.g. Miner + Whitelist).
        # Deduplication is per (value, source_node_id) — not global.
        UniqueConstraint("value", "source_node_id", name="uq_indicator_value_per_node"),
    )


class NodeRunLog(Base):
    __tablename__ = "node_run_logs"
    id             = Column(Integer, primary_key=True, index=True)
    node_id        = Column(Integer, ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    status         = Column(String, nullable=False)  # 'success', 'error', 'running'
    message        = Column(String)
    iocs_processed = Column(Integer, default=0)
    timestamp      = Column(DateTime, default=datetime.utcnow)


Index("idx_feed_extraction", IndicatorDB.ioc_type, IndicatorDB.confidence, IndicatorDB.expire_at)
