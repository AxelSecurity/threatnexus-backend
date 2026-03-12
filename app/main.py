import io
import json
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import engine, Base, get_db
from .models import NodeConfig, NodeEdge, IndicatorDB, NodeRunLog
from .schemas import NodeCreate, NodeResponse, EdgeCreate, EdgeResponse, RunLogResponse
from .tasks import execute_miner, detect_ioc_type

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
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VALID_IOC_TYPES = {"ip", "ipv6", "domain", "url", "hash", "email"}


# ---------------------------------------------------------------------------
# NODES CRUD
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
    db_node.name       = node_update.name
    db_node.node_type  = node_update.node_type
    db_node.config     = node_update.config
    db_node.is_active  = node_update.is_active
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
# EDGES CRUD
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
# LOGS
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


# ---------------------------------------------------------------------------
# IOC READ
# ---------------------------------------------------------------------------

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

class IocTypeUpdate(BaseModel):
    ioc_ids: List[int]
    ioc_type: str


@app.patch("/api/v1/iocs/reclassify")
def reclassify_iocs(payload: IocTypeUpdate, db: Session = Depends(get_db)):
    if payload.ioc_type not in VALID_IOC_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid type '{payload.ioc_type}'. Valid types: {sorted(VALID_IOC_TYPES)}"
        )
    updated = db.query(IndicatorDB).filter(IndicatorDB.id.in_(payload.ioc_ids)).all()
    if not updated:
        raise HTTPException(status_code=404, detail="No IOCs found with the provided IDs")
    for ioc in updated:
        ioc.ioc_type   = payload.ioc_type
        ioc.confidence = 50
    db.commit()
    return {"message": f"{len(updated)} IOC(s) reclassified as '{payload.ioc_type}'"}


# ---------------------------------------------------------------------------
# WHITELIST MINER — Manual IOC management
# ---------------------------------------------------------------------------

def _get_whitelist_node(node_id: int, db: Session) -> NodeConfig:
    """Helper: returns node if it exists and is of type 'whitelist'."""
    node = db.query(NodeConfig).filter(NodeConfig.id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    if node.node_type != "whitelist":
        raise HTTPException(
            status_code=400,
            detail=f"Node '{node.name}' is not a Whitelist Miner (type='{node.node_type}')."
        )
    return node


class WhitelistAddRequest(BaseModel):
    value: str
    ioc_type: Optional[str] = None  # If omitted, auto-detected


@app.post("/api/v1/nodes/{node_id}/whitelist/add")
def whitelist_add_ioc(node_id: int, payload: WhitelistAddRequest, db: Session = Depends(get_db)):
    """
    Manually add a single IOC to a Whitelist Miner.
    If ioc_type is not provided, it is auto-detected via detect_ioc_type().
    """
    node  = _get_whitelist_node(node_id, db)
    value = payload.value.strip()
    if not value:
        raise HTTPException(status_code=400, detail="IOC value cannot be empty.")

    ioc_type = payload.ioc_type if payload.ioc_type in VALID_IOC_TYPES else detect_ioc_type(value)

    # Check for duplicate
    existing = db.query(IndicatorDB).filter(
        IndicatorDB.value == value,
        IndicatorDB.source_node_id == node_id,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"IOC '{value}' already exists in this whitelist.")

    ioc = IndicatorDB(
        value          = value,
        ioc_type       = ioc_type,
        confidence     = 100,           # Whitelist entries always have max confidence
        expire_at      = datetime.utcnow() + timedelta(days=3650),  # 10 years — effectively permanent
        source_node_id = node_id,
        last_seen      = datetime.utcnow(),
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return {"message": f"IOC '{value}' added to whitelist '{node.name}'.", "id": ioc.id, "type": ioc_type}


@app.post("/api/v1/nodes/{node_id}/whitelist/upload")
async def whitelist_upload_file(node_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Upload a plain-text file (.txt) to bulk-add IOCs to a Whitelist Miner.
    Format: one IOC per line. Lines starting with # or // are skipped.
    IOC type is auto-detected for each entry.
    Duplicate values (already in this whitelist) are silently skipped.
    Returns a summary of added vs skipped entries.
    """
    node = _get_whitelist_node(node_id, db)

    if not file.filename.endswith(".txt"):
        raise HTTPException(status_code=400, detail="Only .txt files are supported.")

    content  = await file.read()
    lines    = content.decode("utf-8", errors="ignore").splitlines()

    # Load existing values for this whitelist to detect duplicates efficiently
    existing_values = {
        row.value for row in db.query(IndicatorDB.value)
        .filter(IndicatorDB.source_node_id == node_id).all()
    }

    added   = 0
    skipped = 0
    invalid = 0
    batch   = []
    expire  = datetime.utcnow() + timedelta(days=3650)
    now     = datetime.utcnow()

    for line in lines:
        value = line.strip()
        if not value or value.startswith("#") or value.startswith("//"):
            continue
        if value in existing_values:
            skipped += 1
            continue

        ioc_type = detect_ioc_type(value)
        if ioc_type == "unknown":
            invalid += 1
            continue

        batch.append({
            "value":          value,
            "ioc_type":       ioc_type,
            "confidence":     100,
            "expire_at":      expire,
            "source_node_id": node_id,
            "last_seen":      now,
        })
        existing_values.add(value)  # Prevent intra-file duplicates
        added += 1

        if len(batch) >= 1000:
            db.bulk_insert_mappings(IndicatorDB, batch)
            db.commit()
            batch = []

    if batch:
        db.bulk_insert_mappings(IndicatorDB, batch)
        db.commit()

    return {
        "message": f"Upload complete for whitelist '{node.name}'.",
        "added":   added,
        "skipped": skipped,
        "invalid": invalid,
    }


@app.delete("/api/v1/nodes/{node_id}/whitelist/{ioc_id}")
def whitelist_delete_ioc(node_id: int, ioc_id: int, db: Session = Depends(get_db)):
    """
    Remove a single IOC from a Whitelist Miner by its ID.
    """
    _get_whitelist_node(node_id, db)
    ioc = db.query(IndicatorDB).filter(
        IndicatorDB.id == ioc_id,
        IndicatorDB.source_node_id == node_id,
    ).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found in this whitelist.")
    db.delete(ioc)
    db.commit()
    return {"message": f"IOC '{ioc.value}' removed from whitelist."}


# ---------------------------------------------------------------------------
# MANUAL TRIGGER (Miners only)
# ---------------------------------------------------------------------------

@app.post("/api/v1/nodes/{node_id}/trigger")
def trigger_miner_manually(node_id: int, db: Session = Depends(get_db)):
    node = db.query(NodeConfig).filter(NodeConfig.id == node_id).first()
    if not node or node.node_type not in ("miner", "whitelist"):
        raise HTTPException(
            status_code=400, detail="Only Miner or Whitelist nodes can be triggered manually"
        )
    execute_miner.delay(node_id)
    return {"message": f"Miner '{node.name}' started in background"}


# ---------------------------------------------------------------------------
# OUTPUT FEEDS
# ---------------------------------------------------------------------------

@app.get("/feeds/{output_name}/{format}", response_class=PlainTextResponse)
def get_dynamic_feed(output_name: str, format: str, db: Session = Depends(get_db)):
    """
    Retrieves active IOCs for a named Output node.
    Graph traversal: Output <- Aggregator <- Miners.
    Excludes whitelist nodes, unknown IOCs, expired IOCs, and low-confidence IOCs.
    Supports 'txt' and 'json' formats.
    """
    output_node = db.query(NodeConfig).filter(
        NodeConfig.name == output_name,
        NodeConfig.node_type == "output",
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

    # Only include regular miner nodes, not whitelist nodes
    miner_ids = [
        edge.source_id for edge in edges_to_agg
        if db.query(NodeConfig.node_type)
           .filter(NodeConfig.id == edge.source_id)
           .scalar() == "miner"
    ]

    if not miner_ids:
        return "" if format == "txt" else "[]"

    min_confidence  = aggregator.config.get("confidence_override", 50)
    ioc_types_filter = aggregator.config.get("ioc_types", [])

    ioc_query = db.query(IndicatorDB).filter(
        IndicatorDB.source_node_id.in_(miner_ids),
        IndicatorDB.ioc_type != "unknown",
        IndicatorDB.confidence >= min_confidence,
        IndicatorDB.expire_at > datetime.utcnow(),
    )

    if ioc_types_filter:
        ioc_query = ioc_query.filter(IndicatorDB.ioc_type.in_(ioc_types_filter))

    active_iocs = ioc_query.all()

    # Apply whitelist exclusion at feed level too
    whitelist_ids = [
        edge.source_id for edge in edges_to_agg
        if db.query(NodeConfig.node_type)
           .filter(NodeConfig.id == edge.source_id)
           .scalar() == "whitelist"
    ]
    whitelist_set = set()
    if whitelist_ids:
        whitelist_set = {
            row.value.strip().lower()
            for row in db.query(IndicatorDB.value)
            .filter(IndicatorDB.source_node_id.in_(whitelist_ids)).all()
        }

    filtered_iocs = [
        ioc for ioc in active_iocs
        if ioc.value.strip().lower() not in whitelist_set
    ]

    if format == "txt":
        return "\n".join(ioc.value for ioc in filtered_iocs)
    elif format == "json":
        return json.dumps(
            [{"value": ioc.value, "type": ioc.ioc_type, "confidence": ioc.confidence}
             for ioc in filtered_iocs]
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'txt' or 'json'.")
