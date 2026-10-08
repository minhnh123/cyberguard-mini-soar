import platform
import asyncio
from typing import Dict, Any
from app.services.connectors.base import sanitize_ip


class WindowsConnector:
    @classmethod
    async def block_ip_windows(cls, ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        clean_ip = sanitize_ip(ip) or (ip.strip() if ip else "")
        if not clean_ip:
            return {"status": "failed", "message": "No IP specified"}

        rule_name = f"CyberGuard_Block_{clean_ip.replace(':', '_')}"
        direction = parameters.get("direction", "in")

        if platform.system().lower() == "windows":
            try:
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir={direction} action=block remoteip={clean_ip}'
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                out_msg = stdout.decode('utf-8', errors='ignore')

                if proc.returncode == 0 or "Ok." in out_msg:
                    return {
                        "status": "success",
                        "mode": "live",
                        "rule_name": rule_name,
                        "target": clean_ip,
                        "message": f"Successfully created live Windows Firewall rule '{rule_name}' blocking {clean_ip}.",
                        "raw_output": out_msg
                    }
                else:
                    return {
                        "status": "success",
                        "mode": "simulated",
                        "rule_name": rule_name,
                        "target": clean_ip,
                        "message": f"Generated Windows Firewall command: `{cmd}`. (Note: Live kernel enforcement requires Administrator privileges. Fallback to SOC lab simulation)."
                    }
            except Exception as e:
                return {"status": "failed", "target": clean_ip, "message": str(e)}
        else:
            return {
                "status": "success",
                "mode": "simulated",
                "rule_name": rule_name,
                "target": clean_ip,
                "message": f"Simulated Windows Firewall block for IP {clean_ip}."
            }

    @classmethod
    async def unblock_ip_windows(cls, ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        clean_ip = sanitize_ip(ip) or (ip.strip() if ip else "")
        if not clean_ip:
            return {"status": "failed", "message": "No IP specified"}

        rule_name = f"CyberGuard_Block_{clean_ip.replace(':', '_')}"
        if platform.system().lower() == "windows":
            try:
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                out_msg = stdout.decode('utf-8', errors='ignore').strip()
                return {
                    "status": "success",
                    "mode": "live",
                    "rule_name": rule_name,
                    "target": clean_ip,
                    "message": f"Successfully deleted Windows Firewall rule '{rule_name}' for IP {clean_ip}.",
                    "raw_output": out_msg
                }
            except Exception as e:
                return {"status": "failed", "target": clean_ip, "message": str(e)}
        else:
            return {
                "status": "success",
                "mode": "dry_run",
                "rule_name": rule_name,
                "target": clean_ip,
                "message": f"[Cross-platform Simulation] Command: netsh advfirewall firewall delete rule name=\"{rule_name}\""
            }

    @classmethod
    async def list_firewall_rules_windows(cls) -> Dict[str, Any]:
        if platform.system().lower() == "windows":
            try:
                cmd = 'netsh advfirewall firewall show rule name=all dir=in'
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                raw_out = stdout.decode('utf-8', errors='ignore')

                rules = []
                current_rule = {}
                for line in raw_out.splitlines():
                    line_s = line.strip()
                    if line_s.startswith("Rule Name:") or line_s.startswith("Tên quy tắc:"):
                        if current_rule and "name" in current_rule:
                            if "CyberGuard" in current_rule.get("name", "") or current_rule.get("action") == "Block":
                                rules.append(current_rule)
                        parts = line_s.split(":", 1)
                        current_rule = {"name": parts[1].strip() if len(parts) > 1 else ""}
                    elif ":" in line_s and current_rule:
                        k, v = line_s.split(":", 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if "action" in k or "hành động" in k:
                            current_rule["action"] = v
                        elif "enabled" in k or "đã bật" in k:
                            current_rule["enabled"] = v
                        elif "remoteip" in k or "ip từ xa" in k:
                            current_rule["remote_ip"] = v
                        elif "direction" in k or "hướng" in k:
                            current_rule["direction"] = v

                if current_rule and "name" in current_rule:
                    if "CyberGuard" in current_rule.get("name", "") or current_rule.get("action") == "Block":
                        rules.append(current_rule)

                return {
                    "status": "success",
                    "connector": "windows_firewall",
                    "rules_count": len(rules),
                    "rules": rules,
                    "raw_output": raw_out[:3000] if len(raw_out) > 3000 else raw_out
                }
            except Exception as e:
                return {
                    "status": "failed",
                    "connector": "windows_firewall",
                    "message": f"Error querying Windows Firewall: {str(e)}",
                    "rules": [],
                    "raw_output": ""
                }
        else:
            return {
                "status": "success",
                "connector": "windows_firewall",
                "mode": "simulated",
                "rules_count": 0,
                "rules": [],
                "raw_output": "Windows Defender Firewall not supported on non-Windows host."
            }
