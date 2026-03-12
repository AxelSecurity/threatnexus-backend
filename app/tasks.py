import os
import re
import json
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta
from celery import Celery
from celery.schedules import crontab
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import NodeConfig, NodeEdge, IndicatorDB, NodeRunLog

REDIS_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
celery_app = Celery("threatnexus", broker=REDIS_URL, backend=REDIS_URL)


# ---------------------------------------------------------------------------
# IOC AUTO-CLASSIFIER
# ---------------------------------------------------------------------------

_RE_HASH   = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_RE_IPV4   = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$")
_RE_IPV6   = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
_RE_EMAIL  = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_URL    = re.compile(r"^https?://", re.IGNORECASE)
_RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

_RE_STIX_PATTERN = re.compile(r"\[([\w-]+):[\w.]+ = '([^']+)'\]", re.IGNORECASE)
_STIX_TYPE_MAP = {
    "domain-name":     "domain",
    "ipv4-addr":       "ip",
    "ipv6-addr":       "ipv6",
    "url":             "url",
    "email-addr":      "email",
    "file":            "hash",
    "network-traffic": "ip",
}

VALID_IOC_TYPES = {"ip", "ipv6", "domain", "url", "hash", "email"}


def detect_ioc_type(value: str) -> str:
    v = value.strip()
    if _RE_HASH.match(v):   return "hash"
    if _RE_IPV4.match(v):   return "ip"
    if _RE_IPV6.match(v):   return "ipv6"
    if _RE_EMAIL.match(v):  return "email"
    if _RE_URL.match(v):    return "url"
    if _RE_DOMAIN.match(v): return "domain"
    return "unknown"


def parse_stix2_bundle(data: dict) -> list[tuple[str, str]]:
    results = []
    for obj in data.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        match = _RE_STIX_PATTERN.search(obj.get("pattern", ""))
        if not match:
            continue
        stix_obj_type = match.group(1).lower()
        ioc_value     = match.group(2).strip()
        ioc_type      = _STIX_TYPE_MAP.get(stix_obj_type) or detect_ioc_type(ioc_value)
        results.append((ioc_value, ioc_type))
    return results


# ---------------------------------------------------------------------------
# BULK UPSERT
# Uses the composite constraint uq_indicator_value_per_node (value, source_node_id).
# This allows the same IOC value to coexist in different nodes (Miner + Whitelist).
# On conflict: refresh last_seen, expire_at, confidence, ioc_type — never change source.
# ---------------------------------------------------------------------------

def perform_bulk_upsert(db: Session, ioc_data_list: list):
    if not ioc_data_list:
        return
    stmt = insert(IndicatorDB).values(ioc_data_list)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_indicator_value_per_node",
        set_={
            "last_seen":  stmt.excluded.last_seen,
            "expire_at":  stmt.excluded.expire_at,
            "confidence": stmt.excluded.confidence,
            "ioc_type":   stmt.excluded.ioc_type,
        },
    )
    db.execute(stmt)
    db.commit()


# ---------------------------------------------------------------------------
# MINER TASK
# ---------------------------------------------------------------------------

@celery_app.task(bind=True)
def execute_miner(self, miner_id: int):
    """
    Fetches IOCs from a remote source and persists them.
    Supported parsers: txt, csv, json, stix2.
    Triggers connected Aggregators on completion (Event-Driven Chain).
    """
    db = SessionLocal()
    try:
        miner = db.query(NodeConfig).filter(NodeConfig.id == miner_id).first()
        if not miner or not miner.is_active:
            return

        run_log = NodeRunLog(node_id=miner_id, status="running", message="Task started in background")
        db.add(run_log)
        db.commit()
        db.refresh(run_log)

        config      = miner.config
        url         = config.get("url")
        parser_type = config.get("parser", "txt")
        auth_type   = config.get("auth_type", "none")

        req_kwargs = {"timeout": 15}
        if auth_type == "basic":
            req_kwargs["auth"] = HTTPBasicAuth(
                config.get("auth_username", ""), config.get("auth_password", "")
            )
        elif auth_type == "bearer":
            req_kwargs["headers"] = {"Authorization": f"Bearer {config.get('auth_token', '')}"}

        expire_date = datetime.utcnow() + timedelta(days=30)
        response    = requests.get(url, **req_kwargs)
        response.raise_for_status()

        ioc_batch   = []
        type_counts = {}

        def build_ioc_entry(raw_value: str, forced_type: str = None) -> dict | None:
            value = raw_value.strip()
            if not value:
                return None
            detected = forced_type if forced_type else detect_ioc_type(value)
            type_counts[detected] = type_counts.get(detected, 0) + 1
            return {
                "value":          value,
                "ioc_type":       detected,
                "confidence":     0 if detected == "unknown" else 50,
                "expire_at":      expire_date,
                "source_node_id": miner.id,
                "last_seen":      datetime.utcnow(),
            }

        if parser_type == "csv":
            for line in response.text.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                raw = line.split(",")[0].replace('"', "") if "," in line else line.strip()
                entry = build_ioc_entry(raw)
                if entry:
                    ioc_batch.append(entry)
                if len(ioc_batch) >= 1000:
                    perform_bulk_upsert(db, ioc_batch); ioc_batch = []

        elif parser_type == "txt":
            for line in response.text.splitlines():
                if not line.strip() or line.strip().startswith(("#", "//")):
                    continue
                entry = build_ioc_entry(line)
                if entry:
                    ioc_batch.append(entry)
                if len(ioc_batch) >= 1000:
                    perform_bulk_upsert(db, ioc_batch); ioc_batch = []

        elif parser_type == "json":
            json_path  = config.get("json_path", "")
            json_field = config.get("json_field", "")
            data = response.json()
            if json_path:
                for key in json_path.split("."):
                    data = data.get(key, []) if isinstance(data, dict) else []
            if not isinstance(data, list):
                raise ValueError(f"JSON parser: expected list at '{json_path}', got {type(data).__name__}.")
            for item in data:
                raw = item if isinstance(item, str) else item.get(json_field, "") if isinstance(item, dict) else ""
                if not json_field and isinstance(item, dict):
                    raise ValueError("JSON parser: objects found but 'json_field' not configured.")
                entry = build_ioc_entry(str(raw))
                if entry:
                    ioc_batch.append(entry)
                if len(ioc_batch) >= 1000:
                    perform_bulk_upsert(db, ioc_batch); ioc_batch = []

        elif parser_type == "stix2":
            data = response.json()
            if data.get("type") != "bundle":
                raise ValueError(f"STIX2 parser: expected bundle, got type='{data.get('type')}'.")
            for ioc_value, ioc_type in parse_stix2_bundle(data):
                entry = build_ioc_entry(ioc_value, forced_type=ioc_type)
                if entry:
                    ioc_batch.append(entry)
                if len(ioc_batch) >= 1000:
                    perform_bulk_upsert(db, ioc_batch); ioc_batch = []

        else:
            raise ValueError(f"Unknown parser '{parser_type}'. Supported: txt, csv, json, stix2.")

        perform_bulk_upsert(db, ioc_batch)
        miner.last_run = datetime.utcnow()

        total         = sum(type_counts.values())
        unknown_count = type_counts.get("unknown", 0)
        type_summary  = ", ".join(f"{k}: {v}" for k, v in type_counts.items())
        log_msg = f"Fetch completed. Total: {total} IOCs. Types: [{type_summary}]."
        if unknown_count > 0:
            log_msg += f" WARNING: {unknown_count} unclassified IOCs require manual review."

        run_log.status         = "success"
        run_log.message        = log_msg
        run_log.iocs_processed = total
        db.commit()

        # Trigger all connected Aggregators (event-driven)
        edges_out = db.query(NodeEdge).filter(NodeEdge.source_id == miner.id).all()
        for edge in edges_out:
            agg = db.query(NodeConfig).filter(
                NodeConfig.id        == edge.target_id,
                NodeConfig.node_type == "aggregator",
                NodeConfig.is_active == True,
            ).first()
            if agg:
                execute_aggregator.delay(agg.id)

        return {"status": "success", "miner": miner.name, "processed": total, "types": type_counts}

    except Exception as e:
        db.rollback()
        err_log = db.query(NodeRunLog).filter(
            NodeRunLog.node_id == miner_id
        ).order_by(NodeRunLog.id.desc()).first()
        if err_log:
            err_log.status  = "error"
            err_log.message = str(e)
            db.commit()
        return {"status": "error", "error": str(e)}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# AGGREGATOR TASK
# ---------------------------------------------------------------------------

@celery_app.task(bind=True)
def execute_aggregator(self, aggregator_id: int):
    """
    Full Aggregator pipeline:
    1. Resolve Miners and Whitelist Miners connected via edges.
    2. Build whitelist exclusion set (case-insensitive).
    3. Query IOCs from regular Miners, apply ioc_types filter.
    4. Skip whitelisted IOCs, apply TTL + confidence override to the rest.
    5. Log: processed, dropped (whitelist), TTL applied.
    """
    db = SessionLocal()
    try:
        aggregator = db.query(NodeConfig).filter(NodeConfig.id == aggregator_id).first()
        if not aggregator or not aggregator.is_active:
            return

        run_log = NodeRunLog(
            node_id=aggregator_id,
            status="running",
            message="Aggregation pipeline started..."
        )
        db.add(run_log)
        db.commit()
        db.refresh(run_log)

        config              = aggregator.config
        ioc_types           = config.get("ioc_types", [])
        days_to_live        = int(config.get("days_to_live", 30))
        confidence_override = config.get("confidence_override", None)

        edges_in = db.query(NodeEdge).filter(NodeEdge.target_id == aggregator_id).all()
        if not edges_in:
            run_log.status  = "error"
            run_log.message = "Error: No nodes connected to this Aggregator."
            db.commit()
            return {"status": "error"}

        miner_ids     = []
        whitelist_ids = []
        for edge in edges_in:
            source = db.query(NodeConfig).filter(NodeConfig.id == edge.source_id).first()
            if not source:
                continue
            if source.node_type == "whitelist":
                whitelist_ids.append(source.id)
            elif source.node_type == "miner":
                miner_ids.append(source.id)

        if not miner_ids:
            run_log.status  = "error"
            run_log.message = "Error: No Miner nodes connected to this Aggregator."
            db.commit()
            return {"status": "error"}

        # Build whitelist exclusion set (case-insensitive)
        whitelist_set = set()
        if whitelist_ids:
            wl_iocs = db.query(IndicatorDB.value).filter(
                IndicatorDB.source_node_id.in_(whitelist_ids)
            ).all()
            whitelist_set = {row.value.strip().lower() for row in wl_iocs}

        ioc_query = db.query(IndicatorDB).filter(
            IndicatorDB.source_node_id.in_(miner_ids),
            IndicatorDB.ioc_type != "unknown",
        )
        if ioc_types:
            valid_filter = [t for t in ioc_types if t in VALID_IOC_TYPES]
            if valid_filter:
                ioc_query = ioc_query.filter(IndicatorDB.ioc_type.in_(valid_filter))

        iocs_to_process   = ioc_query.all()
        processed_count   = 0
        dropped_whitelist = 0
        new_expire        = datetime.utcnow() + timedelta(days=days_to_live)

        for ioc in iocs_to_process:
            if ioc.value.strip().lower() in whitelist_set:
                dropped_whitelist += 1
                continue
            ioc.expire_at = new_expire
            if confidence_override is not None:
                ioc.confidence = int(confidence_override)
            processed_count += 1

        db.commit()
        aggregator.last_run = datetime.utcnow()
        db.commit()

        type_filter_label = ", ".join(ioc_types) if ioc_types else "all"
        log_msg = (
            f"Aggregation completed. "
            f"Types filter: [{type_filter_label}]. "
            f"Processed: {processed_count}. "
            f"Dropped (Whitelist): {dropped_whitelist}. "
            f"TTL applied: {days_to_live} days."
        )
        run_log.status         = "success"
        run_log.message        = log_msg
        run_log.iocs_processed = processed_count
        db.commit()

        return {
            "status":    "success",
            "processed": processed_count,
            "dropped":   dropped_whitelist,
            "ttl_days":  days_to_live,
        }

    except Exception as e:
        db.rollback()
        err_log = db.query(NodeRunLog).filter(
            NodeRunLog.node_id == aggregator_id
        ).order_by(NodeRunLog.id.desc()).first()
        if err_log:
            err_log.status  = "error"
            err_log.message = str(e)
            db.commit()
        return {"status": "error", "error": str(e)}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# AGE-OUT CLEANUP TASK — runs every hour
# ---------------------------------------------------------------------------

@celery_app.task
def cleanup_expired_iocs():
    db = SessionLocal()
    try:
        now     = datetime.utcnow()
        expired = db.query(IndicatorDB).filter(IndicatorDB.expire_at < now).all()
        count   = len(expired)
        for ioc in expired:
            db.delete(ioc)
        db.commit()
        return {"status": "success", "expired_deleted": count}
    except Exception as e:
        db.rollback()
        return {"status": "error", "error": str(e)}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# MASTER SCHEDULER — runs every minute
# ---------------------------------------------------------------------------

@celery_app.task
def master_scheduler_task():
    db = SessionLocal()
    try:
        now    = datetime.utcnow()
        miners = db.query(NodeConfig).filter(
            NodeConfig.node_type.in_(["miner", "whitelist"]),
            NodeConfig.is_active == True,
        ).all()
        for miner in miners:
            polling_min = miner.config.get("polling_interval", 60)
            if not miner.last_run or (now - miner.last_run) >= timedelta(minutes=polling_min):
                execute_miner.delay(miner.id)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# CELERY BEAT SCHEDULE
# ---------------------------------------------------------------------------

celery_app.conf.beat_schedule = {
    "run-master-scheduler-every-minute": {
        "task":     "app.tasks.master_scheduler_task",
        "schedule": crontab(minute="*"),
    },
    "cleanup-expired-iocs-every-hour": {
        "task":     "app.tasks.cleanup_expired_iocs",
        "schedule": crontab(minute="0"),
    },
}
celery_app.conf.timezone = "UTC"
