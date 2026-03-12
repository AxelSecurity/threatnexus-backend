from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime


class NodeCreate(BaseModel):
    name: str
    node_type: str
    config: Dict[str, Any]
    is_active: bool = True


class NodeResponse(NodeCreate):
    id: int
    last_run: Optional[datetime] = None

    class Config:
        from_attributes = True


class EdgeCreate(BaseModel):
    source_id: int
    target_id: int


class EdgeResponse(EdgeCreate):
    id: int

    class Config:
        from_attributes = True


class IndicatorResponse(BaseModel):
    id: int
    value: str
    ioc_type: str
    confidence: int
    expire_at: datetime

    class Config:
        from_attributes = True


class RunLogResponse(BaseModel):
    id: int
    status: str
    message: str
    iocs_processed: int
    timestamp: datetime

    class Config:
        from_attributes = True
