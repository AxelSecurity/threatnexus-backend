# ThreatNexus Backend

> Modern Threat Intelligence Platform — A production-ready evolution of Palo Alto Minemeld.

ThreatNexus is a dynamic IOC (Indicators of Compromise) management platform built with **FastAPI**, **PostgreSQL**, **Celery** and **Redis**. It features a graph-based architecture where data flows from **Miners** (input sources) → **Aggregators** (deduplication & aging processors) → **Outputs** (feed endpoints for Firewalls and SIEMs).

---

## Stack

| Component | Technology |
|---|---|
| API Backend | FastAPI + Uvicorn |
| Database | PostgreSQL + SQLAlchemy |
| Async Workers | Celery |
| Message Broker | Redis |
| DB Migrations | Alembic |
| Worker Monitoring | Flower |

---

## Architecture

```
[External Feed URL] --> [Miner Node] --> (Event-Driven) --> [Aggregator Node] --> [Output Node]
                           |                                       |                     |
                      CSV/TXT Parser                    Whitelist + Aging        /feeds/{name}/txt
                      Basic/Bearer Auth                 Confidence Override      /feeds/{name}/json
                      Bulk Upsert (PG)                  Deduplication
```

### Node Types

- **Miner**: Downloads IOC feeds from external URLs. Supports `csv` and `txt` parsers. Supports `none`, `basic`, and `bearer` authentication. Triggered by the Master Scheduler (Celery Beat) based on `polling_interval` (minutes).
- **Aggregator**: Automatically triggered (Event-Driven) when a connected Miner finishes. Applies whitelist filtering, confidence override, and TTL-based aging to IOCs.
- **Output**: Exposes a dynamic HTTP endpoint to serve active IOCs to Firewalls (Palo Alto EDL), SIEMs, or other consumers.

---

## Node `config` JSON Schema

### Miner
```json
{
  "url": "https://example.com/malicious-ips.txt",
  "parser": "txt",
  "ioc_type": "ip",
  "polling_interval": 60,
  "auth_type": "none",
  "auth_username": "",
  "auth_password": "",
  "auth_token": ""
}
```

### Aggregator
```json
{
  "confidence_override": 90,
  "days_to_live": 30,
  "whitelist": ["google.com", "microsoft.com"]
}
```

### Output
```json
{
  "ioc_type": "ip",
  "min_confidence": 50
}
```

---

## Setup & Installation (Native, no Docker)

### Prerequisites
- Python 3.11+
- PostgreSQL (running locally)
- Redis (running locally)

### 1. PostgreSQL Setup

```bash
sudo -u postgres psql
```
```sql
CREATE DATABASE threatnexus_db;
CREATE USER nexus_admin WITH PASSWORD 'nexus_password';
GRANT ALL PRIVILEGES ON DATABASE threatnexus_db TO nexus_admin;
\c threatnexus_db
GRANT ALL ON SCHEMA public TO nexus_admin;
```

### 2. Python Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Alembic Database Migrations

```bash
alembic init alembic
```

In `alembic.ini`, set:
```ini
sqlalchemy.url = postgresql://nexus_admin:nexus_password@localhost:5432/threatnexus_db
```

In `alembic/env.py`, add:
```python
from app.database import Base
from app.models import NodeConfig, NodeEdge, IndicatorDB, NodeRunLog
target_metadata = Base.metadata
```

Run migrations:
```bash
alembic revision --autogenerate -m "Initial migration" && alembic upgrade head
```

---

## Running the Application (4 Terminals)

Activate the virtual environment (`source venv/bin/activate`) in each terminal.

**Terminal 1 — FastAPI Backend:**
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
API docs: [http://localhost:8000/docs](http://localhost:8000/docs)

**Terminal 2 — Celery Worker:**
```bash
celery -A app.tasks worker --loglevel=info
```

**Terminal 3 — Celery Beat Scheduler:**
```bash
celery -A app.tasks beat --loglevel=info
```

**Terminal 4 — Flower Monitoring Dashboard (optional):**
```bash
celery -A app.tasks flower --port=5555
```
Flower UI: [http://localhost:5555](http://localhost:5555)

---

## API Endpoints Reference

### Nodes
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/nodes` | Create a node (Miner, Aggregator, Output) |
| GET | `/api/v1/nodes` | List all nodes (optional `?node_type=miner`) |
| PUT | `/api/v1/nodes/{id}` | Update a node |
| DELETE | `/api/v1/nodes/{id}` | Delete a node |

### Edges (Graph connections)
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/edges` | Create a connection between nodes |
| GET | `/api/v1/edges` | List all connections |
| DELETE | `/api/v1/edges/{id}` | Delete a connection |

### Debug & Monitoring
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/nodes/{id}/logs` | Get execution logs for a node |
| GET | `/api/v1/nodes/{id}/iocs` | Get IOCs collected by a node |
| POST | `/api/v1/nodes/{id}/trigger` | Manually trigger a Miner |

### Feed Output
| Method | Endpoint | Description |
|---|---|---|
| GET | `/feeds/{output_name}/txt` | Export active IOCs as plain text (Palo Alto EDL) |
| GET | `/feeds/{output_name}/json` | Export active IOCs as JSON (SIEM) |

---

## Frontend

The React frontend (ThreatNexus UI) is available at: [https://github.com/AxelSecurity/threatnexus-frontend](https://github.com/AxelSecurity/threatnexus-frontend)
