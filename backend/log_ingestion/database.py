from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from dotenv import load_dotenv

load_dotenv()

# SQLite Database URL - file-based, simple and lightweight
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./airgap_sentinel.db"  # Creates DB file in project root
)

# SQLite specific settings
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite
    echo=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()