import os
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
        },
    )
    db.execute(stmt)
    db.commit()


@celery_app.task(bind=True)
def execute_miner(self, miner_id: int):
    """
    Celery task to fetch IOCs from a configured source URL.
    Supports CSV and TXT parsers.
    Supports Basic Auth and Bearer Token authentication.
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
        ioc_type_default = config.get("ioc_type", "ip")

        # Authentication handling
        auth_type = config.get("auth_type", "none")
        req_kwargs = {"timeout": 15}
        if auth_type == "basic":
            req_kwargs["auth"] = HTTPBasicAuth(
                config.get("auth_username", ""), config.get("auth_password", "")
            )
        elif auth_type == "bearer":
            req_kwargs["headers"] = {"Authorization": f"Bearer {config.get('auth_token', '')}"}

        expire_date = datetime.utcnow() + timedelta(days=30)  # Default TTL pre-aggregation

        response = requests.get(url, **req_kwargs)
        response.raise_for_status()
        ioc_batch = []

        # CSV Parser
        if parser_type == "csv":
            for line in response.text.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                value = line.split(",")[0].replace('"', "") if "," in line else line.strip()
                ioc_batch.append({
                    "value": value, "ioc_type": ioc_type_default, "confidence": 50,
                    "expire_at": expire_date, "source_node_id": miner.id, "last_seen": datetime.utcnow(),
                })
                if len(ioc_batch) >= 1000:
                    perform_bulk_upsert(db, ioc_batch)
                    ioc_batch = []

        # TXT (Plain Text List) Parser
        elif parser_type == "txt":
            for line in response.text.splitlines():
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
                    continue
                ioc_batch.append({
                    "value": clean_line, "ioc_type": ioc_type_default, "confidence": 50,
                    "expire_at": expire_date, "source_node_id": miner.id, "last_seen": datetime.utcnow(),
                })
                if len(ioc_batch) >= 1000:
                    perform_bulk_upsert(db, ioc_batch)
                    ioc_batch = []

        perform_bulk_upsert(db, ioc_batch)  # Final flush
        miner.last_run = datetime.utcnow()

        run_log.status = "success"
        run_log.message = "Fetch completed successfully"
        run_log.iocs_processed = len(ioc_batch)
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

        return {"status": "success", "miner": miner.name, "processed": len(ioc_batch)}

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


@celery_app.task(bind=True)
def execute_aggregator(self, aggregator_id: int):
    """
    Celery task triggered automatically by Miners (Event-Driven Chain).
    Applies whitelist filtering, confidence override and aging (TTL) to IOCs.
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

        # Find parent Miners (source_id -> this aggregator as target_id)
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

        iocs_to_process = db.query(IndicatorDB).filter(
            IndicatorDB.source_node_id.in_(miner_ids)
        ).all()

        processed_count = 0
        dropped_count = 0

        for ioc in iocs_to_process:
            # Whitelist check
            if any(wl in ioc.value for wl in whitelist_domains):
                db.delete(ioc)
                dropped_count += 1
                continue
            # Apply confidence override
            if confidence_override:
                ioc.confidence = confidence_override
            # Apply aging (TTL)
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
