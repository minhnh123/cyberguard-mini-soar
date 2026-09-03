import ipaddress
import datetime
from typing import Dict, Any, Optional
import httpx
from sqlalchemy.future import select
from app.core.config import settings
from app.models.models import ThreatIntelCache, SystemSetting

def is_private_or_bogon_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except ValueError:
        return False

class EnrichmentService:
    @staticmethod
    async def get_cached_ioc(db, ioc_type: str, ioc_value: str, source: str) -> Optional[Dict[str, Any]]:
        result = await db.execute(
            select(ThreatIntelCache).where(
                ThreatIntelCache.ioc_type == ioc_type,
                ThreatIntelCache.ioc_value == ioc_value,
                ThreatIntelCache.source == source
            )
        )
        cache_entry = result.scalars().first()
        if cache_entry:
            if cache_entry.expires_at and cache_entry.expires_at < datetime.datetime.utcnow():
                await db.delete(cache_entry)
                await db.commit()
                return None
            return cache_entry.data
        return None

    @staticmethod
    async def set_cached_ioc(db, ioc_type: str, ioc_value: str, source: str, data: Dict[str, Any], score: int = 0, ttl_hours: int = 24):
        expires = datetime.datetime.utcnow() + datetime.timedelta(hours=ttl_hours)
        cache_entry = ThreatIntelCache(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            source=source,
            data=data,
            malicious_score=score,
            expires_at=expires
        )
        db.add(cache_entry)
        await db.commit()

    @classmethod
    async def lookup_ip_geo(cls, ip: str, db=None) -> Dict[str, Any]:
        if not ip:
            return {"status": "fail", "message": "Empty IP"}

        if is_private_or_bogon_ip(ip):
            return {
                "status": "success",
                "ip": ip,
                "country": "Local / Private Network",
                "countryCode": "LAN",
                "city": "Internal Subnet",
                "isp": "Private RFC1918",
                "org": "Internal Infrastructure",
                "as": "Private",
                "is_private": True
            }

        if db:
            cached = await cls.get_cached_ioc(db, "ip", ip, "ipapi")
            if cached:
                return cached

        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    data["is_private"] = False
                    if db and data.get("status") == "success":
                        await cls.set_cached_ioc(db, "ip", ip, "ipapi", data, score=0, ttl_hours=48)
                    return data
        except Exception as e:
            return {"status": "error", "message": str(e), "ip": ip}

        return {"status": "fail", "message": "Lookup failed", "ip": ip}

    @classmethod
    async def lookup_virustotal(cls, ioc_type: str, ioc_value: str, db=None, api_key: Optional[str] = None) -> Dict[str, Any]:
        if not ioc_value:
            return {"status": "fail", "message": "Empty IOC"}

        if not api_key:
            # Check db system settings if available
            if db:
                res = await db.execute(select(SystemSetting).where(SystemSetting.key == "VIRUSTOTAL_API_KEY"))
                setting_row = res.scalars().first()
                if setting_row and setting_row.value:
                    api_key = setting_row.value
            if not api_key:
                api_key = settings.VIRUSTOTAL_API_KEY

        if not api_key:
            return {
                "status": "skipped",
                "message": "VirusTotal API key not configured. Using local reputation heuristics.",
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "reputation": "unknown",
                "malicious_votes": 0,
                "harmless_votes": 0
            }

        if db:
            cached = await cls.get_cached_ioc(db, ioc_type, ioc_value, "virustotal")
            if cached:
                return cached

        endpoint_map = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{ioc_value}",
            "hash": f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        }
        target_url = endpoint_map.get(ioc_type)
        if not target_url:
            return {"status": "error", "message": f"Unsupported IOC type {ioc_type}"}

        headers = {"x-apikey": api_key}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(target_url, headers=headers)
                if resp.status_code == 200:
                    res_json = resp.json()
                    attrs = res_json.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)

                    reputation = "clean"
                    if malicious >= 3:
                        reputation = "malicious"
                    elif malicious > 0 or suspicious > 0:
                        reputation = "suspicious"

                    result_data = {
                        "status": "success",
                        "ioc_type": ioc_type,
                        "ioc_value": ioc_value,
                        "reputation": reputation,
                        "malicious_score": malicious,
                        "suspicious_score": suspicious,
                        "harmless_score": harmless,
                        "stats": stats,
                        "reputation_score": attrs.get("reputation", 0),
                        "tags": attrs.get("tags", [])
                    }
                    if db:
                        await cls.set_cached_ioc(db, ioc_type, ioc_value, "virustotal", result_data, score=malicious, ttl_hours=24)
                    return result_data
                elif resp.status_code == 404:
                    return {
                        "status": "not_found",
                        "ioc_type": ioc_type,
                        "ioc_value": ioc_value,
                        "reputation": "clean",
                        "malicious_score": 0,
                        "message": "Not found in VirusTotal database"
                    }
                else:
                    return {"status": "error", "message": f"VT API returned {resp.status_code}", "raw": resp.text}
        except Exception as e:
            return {"status": "error", "message": str(e), "ioc_type": ioc_type, "ioc_value": ioc_value}
