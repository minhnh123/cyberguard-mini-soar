import yaml
import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc

from app.core.database import get_db
from app.models.models import Playbook, PlaybookExecution, Incident, Alert
from app.schemas.schemas import PlaybookCreate, PlaybookUpdate, PlaybookResponse
from app.services.playbook_engine import PlaybookEngine

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])

@router.get("", response_model=List[PlaybookResponse])
async def list_playbooks(
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(Playbook).order_by(desc(Playbook.updated_at))
    if category:
        query = query.where(Playbook.category == category)
    result = await db.execute(query)
    return result.scalars().all()

@router.post("", response_model=PlaybookResponse)
async def create_playbook(payload: PlaybookCreate, db: AsyncSession = Depends(get_db)):
    yaml_text = payload.yaml_definition
    if not yaml_text and payload.graph_data:
        yaml_text = yaml.dump({
            "name": payload.name,
            "category": payload.category,
            "trigger_conditions": payload.trigger_conditions or {},
            "nodes": payload.graph_data.get("nodes", []),
            "edges": payload.graph_data.get("edges", [])
        }, sort_keys=False)

    new_pb = Playbook(
        name=payload.name,
        description=payload.description,
        category=payload.category,
        is_active=payload.is_active,
        trigger_conditions=payload.trigger_conditions or {},
        graph_data=payload.graph_data or {},
        yaml_definition=yaml_text
    )
    db.add(new_pb)
    await db.commit()
    await db.refresh(new_pb)
    return new_pb

@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(playbook_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    pb = result.scalars().first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb

@router.put("/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(playbook_id: int, payload: PlaybookUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    pb = result.scalars().first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if payload.name is not None:
        pb.name = payload.name
    if payload.description is not None:
        pb.description = payload.description
    if payload.category is not None:
        pb.category = payload.category
    if payload.is_active is not None:
        pb.is_active = payload.is_active
    if payload.trigger_conditions is not None:
        pb.trigger_conditions = payload.trigger_conditions
    if payload.graph_data is not None:
        pb.graph_data = payload.graph_data
    if payload.yaml_definition is not None:
        pb.yaml_definition = payload.yaml_definition

    pb.updated_at = datetime.datetime.utcnow()
    await db.commit()
    await db.refresh(pb)
    return pb

@router.delete("/{playbook_id}")
async def delete_playbook(playbook_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    pb = result.scalars().first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    await db.delete(pb)
    await db.commit()
    return {"status": "deleted", "id": playbook_id}

@router.post("/{playbook_id}/run")
async def run_playbook_manually(playbook_id: int, incident_id: int, db: AsyncSession = Depends(get_db)):
    """
    Manually trigger a playbook against an existing incident.
    """
    pb_res = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    pb = pb_res.scalars().first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    inc_res = await db.execute(
        select(Incident).where(Incident.id == incident_id).options(selectinload(Incident.alerts))
    )
    inc = inc_res.scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    alert = inc.alerts[0] if inc.alerts else Alert(
        title=inc.title,
        severity=inc.severity,
        source="Manual Run",
        source_ip=None,
        description=inc.summary
    )

    execution = PlaybookExecution(
        playbook_id=pb.id,
        incident_id=inc.id,
        status="running",
        current_step="start",
        logs=[{"time": datetime.datetime.utcnow().isoformat(), "step": "manual_trigger", "message": f"Manually started playbook {pb.name}"}]
    )
    db.add(execution)
    await db.commit()
    await db.refresh(execution)

    await PlaybookEngine.execute_playbook(pb, execution, inc, alert, db)

    return {
        "status": "triggered",
        "execution_id": execution.id,
        "playbook_name": pb.name,
        "incident_number": inc.incident_number
    }
