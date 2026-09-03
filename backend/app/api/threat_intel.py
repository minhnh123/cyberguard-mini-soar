from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.services.enrichment_service import EnrichmentService

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

@router.get("/lookup")
async def lookup_ioc(
    ioc_type: str = Query(..., description="ip, domain, or hash"),
    ioc_value: str = Query(..., description="The IP address, domain name, or file hash"),
    db: AsyncSession = Depends(get_db)
):
    ioc_type = ioc_type.lower().strip()
    ioc_value = ioc_value.strip()

    if not ioc_value:
        raise HTTPException(status_code=400, detail="IOC value cannot be empty")

    results = {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "enrichment": {}
    }

    if ioc_type == "ip":
        geo = await EnrichmentService.lookup_ip_geo(ioc_value, db=db)
        vt = await EnrichmentService.lookup_virustotal("ip", ioc_value, db=db)
        results["enrichment"]["ip_geo"] = geo
        results["enrichment"]["virustotal"] = vt
        results["reputation"] = vt.get("reputation", "clean" if geo.get("is_private") else "unknown")

    elif ioc_type == "domain":
        vt = await EnrichmentService.lookup_virustotal("domain", ioc_value, db=db)
        results["enrichment"]["virustotal"] = vt
        results["reputation"] = vt.get("reputation", "unknown")

    elif ioc_type == "hash":
        vt = await EnrichmentService.lookup_virustotal("hash", ioc_value, db=db)
        results["enrichment"]["virustotal"] = vt
        results["reputation"] = vt.get("reputation", "unknown")

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported IOC type: {ioc_type}. Use 'ip', 'domain', or 'hash'.")

    return results
