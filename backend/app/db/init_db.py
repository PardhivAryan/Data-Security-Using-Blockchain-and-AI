from app.db.session import engine
from app.db.base import Base
import app.models  # noqa: F401


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
    print("✅ DB tables created")