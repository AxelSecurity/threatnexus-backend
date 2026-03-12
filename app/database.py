import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Modify with your actual PostgreSQL credentials or set via environment variable
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://nexus_admin:nexus_password@localhost:5432/threatnexus_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
