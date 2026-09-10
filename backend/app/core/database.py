from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.core.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        from sqlalchemy import text
        migrations = [
            "ALTER TABLE incidents ADD COLUMN alert_count INTEGER DEFAULT 1",
            "ALTER TABLE pending_approvals ADD COLUMN ttl_minutes INTEGER DEFAULT 60",
            "ALTER TABLE pending_approvals ADD COLUMN expires_at DATETIME",
            "ALTER TABLE pending_approvals ADD COLUMN is_expired BOOLEAN DEFAULT 0",
            "ALTER TABLE action_logs ADD COLUMN ttl_minutes INTEGER",
            "ALTER TABLE action_logs ADD COLUMN expires_at DATETIME",
            "ALTER TABLE action_logs ADD COLUMN is_expired BOOLEAN DEFAULT 0",
            "ALTER TABLE action_logs ADD COLUMN rollback_status VARCHAR(32)"
        ]
        for m in migrations:
            try:
                await conn.execute(text(m))
            except Exception:
                pass
