from typing import List
from fastapi import APIRouter
from app.services.mitre_service import MitreService

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])

@router.get("/techniques")
async def list_mitre_techniques():
    return MitreService.get_all_techniques()
