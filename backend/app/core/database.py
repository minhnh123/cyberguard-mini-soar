from sqlalchemy import event
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.core.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

# Tối ưu hóa SQLite WAL mode chống khóa cơ sở dữ liệu khi chịu tải cao
if "sqlite" in settings.DATABASE_URL:
    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=10000")  # Chờ tối đa 10s thay vì báo lỗi lock ngay
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

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
            "ALTER TABLE action_logs ADD COLUMN rollback_status VARCHAR(32)",
            # Durable Execution & Checkpointing Migrations
            "ALTER TABLE playbook_executions ADD COLUMN current_step_index INTEGER DEFAULT 0",
            "ALTER TABLE playbook_executions ADD COLUMN current_node_id VARCHAR(64)",
            "ALTER TABLE playbook_executions ADD COLUMN context_state JSON",
            "ALTER TABLE playbook_executions ADD COLUMN checkpoint_history JSON",
            "ALTER TABLE playbook_executions ADD COLUMN is_resumable BOOLEAN DEFAULT 1",
            "ALTER TABLE playbook_executions ADD COLUMN error_message TEXT",
            # Phase 4: Dual-Custody 4-Eyes Migrations
            "ALTER TABLE pending_approvals ADD COLUMN requires_dual_custody BOOLEAN DEFAULT 0",
            "ALTER TABLE pending_approvals ADD COLUMN first_approver VARCHAR(128)",
            "ALTER TABLE pending_approvals ADD COLUMN first_approver_role VARCHAR(64)",
            "ALTER TABLE pending_approvals ADD COLUMN first_approved_at DATETIME",
            "ALTER TABLE pending_approvals ADD COLUMN second_approver VARCHAR(128)",
            "ALTER TABLE pending_approvals ADD COLUMN second_approver_role VARCHAR(64)",
            "ALTER TABLE pending_approvals ADD COLUMN second_approved_at DATETIME",
            "ALTER TABLE pending_approvals ADD COLUMN dual_custody_status VARCHAR(32) DEFAULT 'not_required'"
        ]
        for m in migrations:
            try:
                await conn.execute(text(m))
            except Exception:
                pass
