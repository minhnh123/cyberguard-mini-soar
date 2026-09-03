import re
from typing import List, Dict, Any

MITRE_ENTERPRISE_TECHNIQUES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt credential guessing or password spraying.",
        "keywords": ["brute force", "failed password", "ssh invalid user", "authentication failure", "logon failure", "password spray", "hydra", "medusa", "ncrack"]
    },
    {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may guess passwords to gain access to target systems or accounts.",
        "keywords": ["password guess", "repeated login failure", "wrong password", "brute force login"]
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters (PowerShell, Bash, Python, Cmd) to execute commands.",
        "keywords": ["powershell -enc", "powershell.exe -w hidden", "cmd.exe /c", "bash -c", "wscript", "cscript", "eval(", "sh -i >& /dev/tcp"]
    },
    {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "keywords": ["powershell", "invoke-expression", "iex", "downloadstring", "invoke-webrequest"]
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may exploit vulnerabilities in Internet-facing applications or web services.",
        "keywords": ["sql injection", "sqli", "union select", "1=1", "rce", "remote code execution", "path traversal", "../..", "log4j", "spring4shell", "cve-"]
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from the operating system (LSASS, SAM, /etc/shadow).",
        "keywords": ["mimikatz", "sekurlsa", "lsass.exe", "procdump", "sam dump", "ntds.dit", "pwdump", "hashdump"]
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or port scan.",
        "keywords": ["port scan", "nmap", "masscan", "syn scan", "tcp connect scan", "stealth scan", "zenmap"]
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability and demand ransom.",
        "keywords": ["ransomware", "encrypt files", ".locked", ".crypto", "readme_for_decrypt", "vssadmin delete shadows", "wbadmin delete catalog"]
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP/S, DNS) to avoid detection.",
        "keywords": ["c2 beacon", "cobalt strike", "meterpreter", "reverse shell", "dns tunneling", "suspicious outbound http"]
    },
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems or steal credentials.",
        "keywords": ["phishing", "suspicious attachment", ".exe inside zip", "macro enabled document", "invoice.docm", "fake login page"]
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or alter generated artifacts on a host system, such as event logs.",
        "keywords": ["wevtutil cl", "clear-eventlog", "rm -rf /var/log", "history -c", "delete audit log"]
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Adversaries may abuse task scheduling functionality (schtasks, cron) to facilitate initial or recurring execution.",
        "keywords": ["schtasks /create", "crontab -e", "at.exe", "systemd service created"]
    }
]

class MitreService:
    @staticmethod
    def match_mitre_techniques(text_to_analyze: str) -> List[Dict[str, Any]]:
        """
        Analyze alert text, title, rule descriptions or raw payload to match MITRE ATT&CK techniques.
        """
        matched = []
        if not text_to_analyze:
            return matched

        lower_text = text_to_analyze.lower()

        for tech in MITRE_ENTERPRISE_TECHNIQUES:
            for kw in tech["keywords"]:
                pattern = r'\b' + re.escape(kw) + r'\b'
                if re.search(pattern, lower_text, re.IGNORECASE) or kw in lower_text:
                    if not any(m["id"] == tech["id"] for m in matched):
                        matched.append({
                            "id": tech["id"],
                            "name": tech["name"],
                            "tactic": tech["tactic"],
                            "description": tech["description"]
                        })
                    break

        return matched

    @staticmethod
    def get_all_techniques() -> List[Dict[str, Any]]:
        return MITRE_ENTERPRISE_TECHNIQUES

    @staticmethod
    def get_technique_by_id(tech_id: str) -> Dict[str, Any]:
        for tech in MITRE_ENTERPRISE_TECHNIQUES:
            if tech["id"].lower() == tech_id.lower():
                return tech
        return None
