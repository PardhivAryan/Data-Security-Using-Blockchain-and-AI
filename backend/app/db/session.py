from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.core.config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, class_=Session)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
        # normal request, commit is done explicitly in code where needed
    except Exception:
        # IMPORTANT: prevents "current transaction is aborted"
        db.rollback()
        raise
    finally:
        db.close()