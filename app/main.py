import json
from datetime import datetime
from typing import List
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import engine, Base, get_db
from .models import NodeConfig, NodeEdge, IndicatorDB, NodeRunLog
from .schemas import NodeCreate, NodeResponse, EdgeCreate, EdgeResponse, RunLogResponse
from .tasks import execute_miner

# Create all tables on startup (use Alembic for production migrations)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ThreatNexus API",
    description="Dynamic Threat Intelligence Platform - IOC collection, deduplication, aging and feed distribution.",
    version="1.0.0",
)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# NODES CRUD (Miners, Aggregators, Outputs)
# ---------------------------------------------------------------------------

@app.post("/api/v1/nodes", response_model=NodeResponse)
def create_node(node: NodeCreate, db: Session = Depends(get_db)):
    db_node = NodeConfig(**node.model_dump())
    db.add(db_node)
    db.commit()
    db.refresh(db_node)
    return db_node


@app.get("/api/v1/nodes", response_model=list[NodeResponse])
def get_nodes(node_type: str = None, db: Session = Depends(get_db)):
    query = db.query(NodeConfig)
    if node_type:
        query = query.filter(NodeConfig.node_type == node_type)
    return query.all()


@app.put("/api/v1/nodes/{node_id}", response_model=NodeResponse)
def update_node(node_id: int, node_update: NodeCreate, db: Session = Depends(get_db)):
    db_node = db.query(NodeConfig).filter(NodeConfig.id == node_id).first()
    if not db_node:
        raise HTTPException(status_code=404, detail="Node not found")
    db_node.name = node_update.name
    db_node.node_type = node_update.node_type
    db_node.config = node_update.config
    db_node.is_active = node_update.is_active
    db.commit()
    db.refresh(db_node)
    return db_node


@app.delete("/api/v1/nodes/{node_id}")
def delete_node(node_id: int, db: Session = Depends(get_db)):
    db_node = db.query(NodeConfig).filter(NodeConfig.id == node_id).first()
    if not db_node:
        raise HTTPException(status_code=404, detail="Node not found")
    db.delete(db_node)
    db.commit()
    return {"message": "Node deleted successfully"}


# ---------------------------------------------------------------------------
# EDGES CRUD (Graph connections)
# ---------------------------------------------------------------------------

@app.post("/api/v1/edges", response_model=EdgeResponse)
def create_edge(edge: EdgeCreate, db: Session = Depends(get_db)):
    db_edge = NodeEdge(**edge.model_dump())
    db.add(db_edge)
    db.commit()
    db.refresh(db_edge)
    return db_edge


@app.get("/api/v1/edges", response_model=list[EdgeResponse])
def get_edges(db: Session = Depends(get_db)):
    return db.query(NodeEdge).all()


@app.delete("/api/v1/edges/{edge_id}")
def delete_edge(edge_id: int, db: Session = Depends(get_db)):
    db_edge = db.query(NodeEdge).filter(NodeEdge.id == edge_id).first()
    if not db_edge:
        raise HTTPException(status_code=404, detail="Edge not found")
    db.delete(db_edge)
    db.commit()
    return {"message": "Edge deleted successfully"}


# ---------------------------------------------------------------------------
# LOGS & DEBUG
# ---------------------------------------------------------------------------

@app.get("/api/v1/nodes/{node_id}/logs", response_model=list[RunLogResponse])
def get_node_logs(node_id: int, limit: int = 15, db: Session = Depends(get_db)):
    return (
        db.query(NodeRunLog)
        .filter(NodeRunLog.node_id == node_id)
        .order_by(NodeRunLog.id.desc())
        .limit(limit)
        .all()
    )


@app.get("/api/v1/nodes/{node_id}/iocs")
def get_node_iocs(node_id: int, limit: int = 50, db: Session = Depends(get_db)):
    """Returns classified IOCs (excludes unknown) for a given node."""
    iocs = (
        db.query(IndicatorDB)
        .filter(
            IndicatorDB.source_node_id == node_id,
            IndicatorDB.ioc_type != "unknown",
        )
        .order_by(IndicatorDB.id.desc())
        .limit(limit)
        .all()
    )
    return [{"id": ioc.id, "value": ioc.value, "type": ioc.ioc_type, "confidence": ioc.confidence} for ioc in iocs]


@app.get("/api/v1/nodes/{node_id}/iocs/unknown")
def get_unknown_iocs(node_id: int, db: Session = Depends(get_db)):
    """Returns all unclassified IOCs (ioc_type='unknown') for a given Miner node."""
    iocs = (
        db.query(IndicatorDB)
        .filter(
            IndicatorDB.source_node_id == node_id,
            IndicatorDB.ioc_type == "unknown",
        )
        .order_by(IndicatorDB.id.desc())
        .all()
    )
    return [{"id": ioc.id, "value": ioc.value} for ioc in iocs]


# ---------------------------------------------------------------------------
# IOC MANUAL RECLASSIFICATION
# ---------------------------------------------------------------------------

VALID_IOC_TYPES = {"ip", "ipv6", "domain", "url", "hash", "email"}


class IocTypeUpdate(BaseModel):
    ioc_ids: List[int]
    ioc_type: str


@app.patch("/api/v1/iocs/reclassify")
def reclassify_iocs(payload: IocTypeUpdate, db: Session = Depends(get_db)):
    """
    Manually reclassify one or more IOCs from 'unknown' to a valid type.
    Sets confidence to 50 (standard) after manual classification.
    """
    if payload.ioc_type not in VALID_IOC_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid type '{payload.ioc_type}'. Valid types: {sorted(VALID_IOC_TYPES)}"
        )
    updated = db.query(IndicatorDB).filter(IndicatorDB.id.in_(payload.ioc_ids)).all()
    if not updated:
        raise HTTPException(status_code=404, detail="No IOCs found with the provided IDs")
    for ioc in updated:
        ioc.ioc_type = payload.ioc_type
        ioc.confidence = 50  # Restore standard confidence after manual review
    db.commit()
    return {"message": f"{len(updated)} IOC(s) reclassified as '{payload.ioc_type}'"}


# ---------------------------------------------------------------------------
# MANUAL TRIGGER (Miners only)
# ---------------------------------------------------------------------------

@app.post("/api/v1/nodes/{node_id}/trigger")
def trigger_miner_manually(node_id: int, db: Session = Depends(get_db)):
    node = db.query(NodeConfig).filter(NodeConfig.id == node_id).first()
    if not node or node.node_type != "miner":
        raise HTTPException(
            status_code=400, detail="Only Miner nodes can be triggered manually"
        )
    execute_miner.delay(node_id)
    return {"message": f"Miner '{node.name}' started in background"}


# ---------------------------------------------------------------------------
# OUTPUT FEEDS (Graph traversal: Output -> Aggregator -> Miners -> IOCs)
# ---------------------------------------------------------------------------

@app.get("/feeds/{output_name}/{format}", response_class=PlainTextResponse)
def get_dynamic_feed(
    output_name: str, format: str, db: Session = Depends(get_db)
):
    """
    Retrieves active IOCs for a named Output node.
    Traverses the graph: Output <- Aggregator <- Miners to resolve IOC sources.
    Excludes IOCs with ioc_type='unknown' or confidence=0.
    Supports 'txt' (Palo Alto EDL) and 'json' output formats.
    """
    output_node = db.query(NodeConfig).filter(
        NodeConfig.name == output_name, NodeConfig.node_type == "output"
    ).first()
    if not output_node:
        raise HTTPException(status_code=404, detail="Output node not found")

    edge_to_output = db.query(NodeEdge).filter(NodeEdge.target_id == output_node.id).first()
    if not edge_to_output:
        return "" if format == "txt" else "[]"

    aggregator = db.query(NodeConfig).filter(NodeConfig.id == edge_to_output.source_id).first()
    if not aggregator:
        return "" if format == "txt" else "[]"

    edges_to_agg = db.query(NodeEdge).filter(NodeEdge.target_id == aggregator.id).all()
    miner_ids = [edge.source_id for edge in edges_to_agg]

    if not miner_ids:
        return "" if format == "txt" else "[]"

    min_confidence = aggregator.config.get("confidence_override", 50)

    active_iocs = (
        db.query(IndicatorDB)
        .filter(
            IndicatorDB.source_node_id.in_(miner_ids),
            IndicatorDB.ioc_type != "unknown",  # Always exclude unclassified
            IndicatorDB.confidence >= min_confidence,
            IndicatorDB.expire_at > datetime.utcnow(),
        )
        .all()
    )

    if format == "txt":
        return "\n".join(ioc.value for ioc in active_iocs)
    elif format == "json":
        return json.dumps(
            [{"value": ioc.value, "type": ioc.ioc_type, "confidence": ioc.confidence} for ioc in active_iocs]
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'txt' or 'json'.")
