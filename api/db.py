from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

from api.db_models import Base

DATABASE_URL = os.environ["FG_DB_URL"]

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

def init_db() -> None:
    # This is the missing piece
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
