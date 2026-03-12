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
# Regex patterns ordered from most specific to least specific.
# No fallback: unrecognized values are saved as 'unknown' with confidence=0.
# ---------------------------------------------------------------------------

_RE_HASH   = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_RE_IPV4   = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$")
_RE_IPV6   = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
_RE_EMAIL  = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_URL    = re.compile(r"^https?://", re.IGNORECASE)
_RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

# STIX2 pattern extractor: [domain-name:value = 'evil.com']
# Captures the object type and the quoted value
_RE_STIX_PATTERN = re.compile(
    r"\[([\w-]+):[\w.]+ = '([^']+)'\]",
    re.IGNORECASE
)

# Maps STIX2 object types to ThreatNexus ioc_type
_STIX_TYPE_MAP = {
    "domain-name":        "domain",
    "ipv4-addr":          "ip",
    "ipv6-addr":          "ipv6",
    "url":                "url",
    "email-addr":         "email",
    "file":               "hash",
    "network-traffic":    "ip",
}


def detect_ioc_type(value: str) -> str:
    """
    Auto-classifies an IOC string into one of the following types:
    hash, ip, ipv6, email, url, domain, unknown.

    Order of checks is intentional:
    - Hashes before IPs (a hex string could match both patterns)
    - Email before domain (emails contain a domain part)
    - URL before domain (URLs start with http/https)
    Returns 'unknown' when no pattern matches.
    """
    v = value.strip()
    if _RE_HASH.match(v):   return "hash"
    if _RE_IPV4.match(v):   return "ip"
    if _RE_IPV6.match(v):   return "ipv6"
    if _RE_EMAIL.match(v):  return "email"
    if _RE_URL.match(v):    return "url"
    if _RE_DOMAIN.match(v): return "domain"
    return "unknown"


# ---------------------------------------------------------------------------
# STIX2 PARSER HELPER
# Parses a STIX2 Bundle object and returns a list of (value, ioc_type) tuples.
# Handles both STIX 2.0 and 2.1 indicator pattern syntax.
# ---------------------------------------------------------------------------

def parse_stix2_bundle(data: dict) -> list[tuple[str, str]]:
    """
    Extracts IOC (value, type) pairs from a STIX2 bundle.
    Processes objects of type 'indicator' only.
    Falls back to detect_ioc_type() for unrecognized STIX object types.
    """
    results = []
    objects = data.get("objects", [])

    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        match = _RE_STIX_PATTERN.search(pattern)
        if not match:
            continue

        stix_obj_type = match.group(1).lower()   # e.g. 'domain-name'
        ioc_value     = match.group(2).strip()    # e.g. 'evil.com'
        ioc_type      = _STIX_TYPE_MAP.get(stix_obj_type, None)

        # If STIX type is not in our map, fall back to regex auto-detection
        if ioc_type is None:
            ioc_type = detect_ioc_type(ioc_value)

        results.append((ioc_value, ioc_type))

    return results


# ---------------------------------------------------------------------------
# BULK UPSERT
# ---------------------------------------------------------------------------

def perform_bulk_upsert(db: Session, ioc_data_list: list):
    """Bulk upsert IOCs into PostgreSQL. Deduplicates on 'value' field."""
    if not ioc_data_list:
        return
    stmt = insert(IndicatorDB).values(ioc_data_list)
    stmt = stmt.on_conflict_do_update(
        index_elements=["value"],
        set_={
            "last_seen": stmt.excluded.last_seen,
            "expire_at": stmt.excluded.expire_at,
            "confidence": stmt.excluded.confidence,
            "ioc_type": stmt.excluded.ioc_type,
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
    Celery task to fetch IOCs from a configured source URL.

    Supported parsers:
      - txt:   Plain text list, one IOC per line. Skips lines starting with # or //
      - csv:   Comma-separated values. IOC extracted from the first column.
      - json:  JSON response. Requires 'json_path' (dot-notation key to the array)
               and 'json_field' (key of the IOC value inside each object).
               Example config: { "json_path": "data", "json_field": "indicator" }
               If json_path is empty, the root of the response is treated as the array.
      - stix2: STIX 2.x Bundle JSON. Extracts indicators from 'indicator' type objects.
               Parses the 'pattern' field automatically. No extra config needed.

    Supports Basic Auth and Bearer Token authentication.
    Auto-classifies each IOC type using detect_ioc_type().
    Unrecognized IOCs are saved with ioc_type='unknown' and confidence=0.
    On completion, triggers downstream Aggregator nodes (Event-Driven Chain).
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

        config = miner.config
        url = config.get("url")
        parser_type = config.get("parser", "txt")

        # Authentication handling
        auth_type = config.get("auth_type", "none")
        req_kwargs = {"timeout": 15}
        if auth_type == "basic":
            req_kwargs["auth"] = HTTPBasicAuth(
                config.get("auth_username", ""), config.get("auth_password", "")
            )
        elif auth_type == "bearer":
            req_kwargs["headers"] = {"Authorization": f"Bearer {config.get('auth_token', '')}"}

        expire_date = datetime.utcnow() + timedelta(days=30)

        response = requests.get(url, **req_kwargs)
        response.raise_for_status()
        ioc_batch = []
        type_counts = {}

        def build_ioc_entry(raw_value: str, forced_type: str = None) -> dict | None:
            """
            Validates, auto-classifies and builds a single IOC dict.
            If forced_type is provided (e.g. from STIX2 parser), skip auto-detection.
            No fallback: unknown values are saved with ioc_type='unknown', confidence=0.
            """
            value = raw_value.strip()
            if not value:
                return None
            detected = forced_type if forced_type else detect_ioc_type(value)
            type_counts[detected] = type_counts.get(detected, 0) + 1
            return {
                "value": value,
                "ioc_type": detected,
                "confidence": 0 if detected == "unknown" else 50,
                "expire_at": expire_date,
                "source_node_id": miner.id,
                "last_seen": datetime.utcnow(),
            }

        # ------------------------------------------------------------------
        # CSV Parser
        # ------------------------------------------------------------------
        if parser_type == "csv":
            for line in response.text.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                raw = line.split(",")[0].replace('"', "") if "," in line else line.strip()
                entry = build_ioc_entry(raw)
                if entry:
                    ioc_batch.append(entry)
                if len(ioc_batch) >= 1000:
                    perform_bulk_upsert(db, ioc_batch)
                    ioc_batch = []

        # ------------------------------------------------------------------
        # TXT Parser
        # ------------------------------------------------------------------
        elif parser_type == "txt":
            for line in response.text.splitlines():
                if not line.strip() or line.strip().startswith("#") or line.strip().startswith("//"):
                    continue
                entry = build_ioc_entry(line)
                if entry:
                    ioc_batch.append(entry)
                if len(ioc_batch) >= 1000:
                    perform_bulk_upsert(db, ioc_batch)
                    ioc_batch = []

        # ------------------------------------------------------------------
        # JSON Parser
        # Requires config:
        #   json_path  (str): dot-notation path to the array, e.g. "data.indicators"
        #                     Leave empty if the root is already the array.
        #   json_field (str): key of the IOC value in each object, e.g. "value"
        #                     Leave empty if each element is a plain string.
        # ------------------------------------------------------------------
        elif parser_type == "json":
            json_path  = config.get("json_path", "")   # e.g. "data" or "results.indicators"
            json_field = config.get("json_field", "")  # e.g. "value" or "indicator"

            data = response.json()

            # Navigate to the target array using dot-notation path
            if json_path:
                for key in json_path.split("."):
                    if isinstance(data, dict):
                        data = data.get(key, [])
                    else:
                        data = []
                        break

            if not isinstance(data, list):
                raise ValueError(
                    f"JSON parser: expected a list at path '{json_path}', "
                    f"got {type(data).__name__}. Check 'json_path' config."
                )

            for item in data:
                if isinstance(item, str):
                    # Each element is already a plain string IOC
                    raw = item
                elif isinstance(item, dict):
                    if not json_field:
                        raise ValueError(
                            "JSON parser: response contains objects but 'json_field' "
                            "is not configured. Set it to the key containing the IOC value."
                        )
                    raw = item.get(json_field, "")
                else:
                    continue

                entry = build_ioc_entry(str(raw))
                if entry:
                    ioc_batch.append(entry)
                if len(ioc_batch) >= 1000:
                    perform_bulk_upsert(db, ioc_batch)
                    ioc_batch = []

        # ------------------------------------------------------------------
        # STIX2 Parser
        # Parses STIX 2.x Bundle JSON.
        # Extracts 'indicator' objects and decodes their 'pattern' field.
        # No extra config required beyond url + auth.
        # ------------------------------------------------------------------
        elif parser_type == "stix2":
            data = response.json()

            if data.get("type") != "bundle":
                raise ValueError(
                    f"STIX2 parser: expected a STIX Bundle (type='bundle'), "
                    f"got type='{data.get('type')}'. Verify the source URL."
                )

            extracted = parse_stix2_bundle(data)

            for ioc_value, ioc_type in extracted:
                entry = build_ioc_entry(ioc_value, forced_type=ioc_type)
                if entry:
                    ioc_batch.append(entry)
                if len(ioc_batch) >= 1000:
                    perform_bulk_upsert(db, ioc_batch)
                    ioc_batch = []

        else:
            raise ValueError(
                f"Unknown parser type '{parser_type}'. "
                f"Supported parsers: txt, csv, json, stix2."
            )

        perform_bulk_upsert(db, ioc_batch)  # Final flush
        miner.last_run = datetime.utcnow()

        # Build detailed log message with type breakdown
        total = sum(type_counts.values())
        unknown_count = type_counts.get("unknown", 0)
        type_summary = ", ".join(f"{k}: {v}" for k, v in type_counts.items())
        log_msg = f"Fetch completed. Total: {total} IOCs. Types: [{type_summary}]."
        if unknown_count > 0:
            log_msg += f" WARNING: {unknown_count} unclassified IOCs require manual review."

        run_log.status = "success"
        run_log.message = log_msg
        run_log.iocs_processed = total
        db.commit()

        # EVENT-DRIVEN CASCADE: Trigger connected Aggregators
        edges_out = db.query(NodeEdge).filter(NodeEdge.source_id == miner.id).all()
        for edge in edges_out:
            agg = db.query(NodeConfig).filter(
                NodeConfig.id == edge.target_id,
                NodeConfig.node_type == "aggregator",
                NodeConfig.is_active == True,
            ).first()
            if agg:
                execute_aggregator.delay(agg.id)

        return {"status": "success", "miner": miner.name, "processed": total, "types": type_counts}

    except Exception as e:
        db.rollback()
        err_log = (
            db.query(NodeRunLog)
            .filter(NodeRunLog.node_id == miner_id)
            .order_by(NodeRunLog.id.desc())
            .first()
        )
        if err_log:
            err_log.status = "error"
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
    Celery task triggered automatically by Miners (Event-Driven Chain).
    Applies whitelist filtering, confidence override and aging (TTL) to IOCs.
    IOCs with ioc_type='unknown' are skipped (confidence=0, excluded from feeds).
    """
    db = SessionLocal()
    try:
        aggregator = db.query(NodeConfig).filter(NodeConfig.id == aggregator_id).first()
        if not aggregator or not aggregator.is_active:
            return

        run_log = NodeRunLog(
            node_id=aggregator_id, status="running", message="Aggregation and deduplication in progress..."
        )
        db.add(run_log)
        db.commit()
        db.refresh(run_log)

        edges_in = db.query(NodeEdge).filter(NodeEdge.target_id == aggregator_id).all()
        miner_ids = [edge.source_id for edge in edges_in]

        if not miner_ids:
            run_log.status = "error"
            run_log.message = "Error: No Miner nodes connected to this Aggregator."
            db.commit()
            return {"status": "error"}

        config = aggregator.config
        confidence_override = config.get("confidence_override", None)
        days_to_live = config.get("days_to_live", 30)
        whitelist_domains = config.get("whitelist", [])

        # Exclude 'unknown' IOCs - they require manual reclassification first
        iocs_to_process = db.query(IndicatorDB).filter(
            IndicatorDB.source_node_id.in_(miner_ids),
            IndicatorDB.ioc_type != "unknown",
        ).all()

        processed_count = 0
        dropped_count = 0

        for ioc in iocs_to_process:
            if any(wl in ioc.value for wl in whitelist_domains):
                db.delete(ioc)
                dropped_count += 1
                continue
            if confidence_override:
                ioc.confidence = confidence_override
            ioc.expire_at = datetime.utcnow() + timedelta(days=days_to_live)
            processed_count += 1

        db.commit()
        aggregator.last_run = datetime.utcnow()

        run_log.status = "success"
        run_log.message = (
            f"Processed {processed_count} IOCs from Miners {miner_ids}. "
            f"Dropped (Whitelist): {dropped_count}."
        )
        run_log.iocs_processed = processed_count
        db.commit()

        return {"status": "success", "processed": processed_count, "dropped": dropped_count}

    except Exception as e:
        db.rollback()
        err_log = (
            db.query(NodeRunLog)
            .filter(NodeRunLog.node_id == aggregator_id)
            .order_by(NodeRunLog.id.desc())
            .first()
        )
        if err_log:
            err_log.status = "error"
            err_log.message = str(e)
            db.commit()
        return {"status": "error", "error": str(e)}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# MASTER SCHEDULER TASK
# ---------------------------------------------------------------------------

@celery_app.task
def master_scheduler_task():
    """
    Master scheduler task. Runs every minute via Celery Beat.
    Checks which active Miners are due for execution based on their polling_interval.
    Aggregators are NOT polled here - they are triggered by Miners (Event-Driven).
    """
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        miners = db.query(NodeConfig).filter(
            NodeConfig.node_type == "miner", NodeConfig.is_active == True
        ).all()
        for miner in miners:
            polling_min = miner.config.get("polling_interval", 60)
            if not miner.last_run or (now - miner.last_run) >= timedelta(minutes=polling_min):
                execute_miner.delay(miner.id)
    finally:
        db.close()


# Celery Beat Schedule
celery_app.conf.beat_schedule = {
    "run-master-scheduler-every-minute": {
        "task": "app.tasks.master_scheduler_task",
        "schedule": crontab(minute="*"),
    },
}
celery_app.conf.timezone = "UTC"
