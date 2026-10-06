import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc

from app.core.database import get_db
from app.models.models import DesiredSecurityState
from app.schemas.schemas import (
    DesiredSecurityStateResponse,
    ReconciliationStatusResponse,
    SimulateDriftRequest
)
from app.services.reconciliation_service import ReconciliationService

router = APIRouter(prefix="/reconciliation", tags=["Reconciliation & Self-Healing"])

@router.get("/status", response_model=ReconciliationStatusResponse)
async def get_reconciliation_status(
    auto_heal: bool = Query(True, description="Tự động vá lỗi lệch cấu hình nếu phát hiện"),
    db: AsyncSession = Depends(get_db)
):
    """
    Closed-Loop Reconciliation Audit:
    Audits live infrastructure against Desired State and automatically heals configuration drift.
    """
    return await ReconciliationService.reconcile_all(db=db)

@router.get("/states", response_model=List[DesiredSecurityStateResponse])
async def list_desired_states(
    active_only: bool = Query(True, description="Chỉ lấy các trạng thái đang có hiệu lực"),
    db: AsyncSession = Depends(get_db)
):
    """
    Lists all tracked Desired Security States.
    """
    stmt = select(DesiredSecurityState).order_by(desc(DesiredSecurityState.created_at))
    if active_only:
        stmt = stmt.where(DesiredSecurityState.is_active == True)
    res = await db.execute(stmt)
    return res.scalars().all()

@router.post("/reconcile-now", response_model=ReconciliationStatusResponse)
async def trigger_reconciliation_now(
    db: AsyncSession = Depends(get_db)
):
    """
    Triggers an immediate closed-loop reconciliation cycle with self-healing.
    """
    return await ReconciliationService.reconcile_all(db=db)

@router.post("/simulate-drift")
async def simulate_configuration_drift(
    payload: SimulateDriftRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Simulates configuration drift on live infrastructure for testing and demonstration
    (e.g. unexpected iptables flush or EDR re-connection).
    """
    result = await ReconciliationService.simulate_drift(
        target=payload.target,
        action=payload.action,
        db=db
    )
    return result
