import io
from typing import Dict, Any, Optional, Tuple
from app.services.connectors.base import BaseConnector, sanitize_ip


class LinuxSSHConnector:
    @classmethod
    async def get_linux_ssh_config(
        cls, db=None, parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Unified resolver for Linux SSH connector settings across database and parameters.
        Eliminates duplicate SSH config resolution code across methods.
        """
        params = parameters or {}
        configs = await BaseConnector.get_connector_settings(db, "LINUX_SSH")
        host = params.get("host") or configs.get("LINUX_SSH_HOST") or "192.168.56.107"
        user = params.get("user") or configs.get("LINUX_SSH_USER") or "minh"
        password = params.get("password") or configs.get("LINUX_SSH_PASSWORD") or "kali"
        private_key = configs.get("LINUX_SSH_PRIVATE_KEY") or ""
        auth_type = configs.get("LINUX_SSH_AUTH_TYPE") or "key"
        use_nopasswd = (configs.get("LINUX_SSH_USE_SUDO_NOPASSWD") or "").lower() in ["true", "1", "yes"]
        port = int(params.get("port") or configs.get("LINUX_SSH_PORT") or 22)

        return {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "private_key": private_key,
            "auth_type": auth_type,
            "use_nopasswd": use_nopasswd,
            "configs": configs,
        }

    @classmethod
    def connect_ssh_client(
        cls,
        host: str,
        port: int,
        user: str,
        password: str,
        private_key_pem: str = "",
        auth_type: str = "key"
    ) -> Tuple[Any, str, str, str]:
        """
        Connects via SSH using Ed25519/RSA Keypair from Vault first,
        falling back to securely decrypted password if key is not configured.
        Returns: (client, active_user, active_password, auth_method)
        """
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # 1. Attempt Key-Based Authentication if key provided and not forced password
        if private_key_pem and str(auth_type).lower() != "password":
            try:
                pkey = None
                try:
                    pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(private_key_pem.strip()))
                except Exception:
                    try:
                        pkey = paramiko.RSAKey.from_private_key(io.StringIO(private_key_pem.strip()))
                    except Exception:
                        pass

                if pkey:
                    client.connect(
                        hostname=host,
                        port=port,
                        username=user,
                        pkey=pkey,
                        timeout=3.0,
                        look_for_keys=False,
                        allow_agent=False
                    )
                    return client, user, "", "key"
            except Exception:
                pass

        # 2. Attempt Password Authentication with configured credentials only.
        if not password:
            raise ConnectionError(
                f"SSH password authentication to {host} failed: No password configured. "
                "Set LINUX_SSH_PASSWORD in Settings or configure SSH key-based auth."
            )

        try:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=3.0,
                look_for_keys=False,
                allow_agent=False
            )
            return client, user, password, "password"
        except Exception as ex:
            raise ConnectionError(f"SSH connection to VM {host} failed: {ex}")

    @classmethod
    def execute_sudo_command(
        cls,
        client: Any,
        command: str,
        active_user: str,
        active_pass: str,
        auth_method: str = "password",
        use_nopasswd: bool = False
    ) -> Tuple[int, str, str]:
        """
        Executes a privileged command securely over SSH.
        Redacts credentials from stdout/stderr.
        """
        from app.core.vault import VaultService

        if active_user == "root" or use_nopasswd:
            full_cmd = f"sudo -n {command}" if (active_user != "root" and not command.startswith("sudo")) else command
            stdin, stdout, stderr = client.exec_command(full_cmd)
        else:
            full_cmd = f"sudo -S -p '' {command}"
            stdin, stdout, stderr = client.exec_command(full_cmd)
            if active_pass:
                stdin.write(f"{active_pass}\n")
                stdin.flush()

        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        exit_code = stdout.channel.recv_exit_status()

        # Redact sensitive strings and passwords
        clean_out = VaultService.redact_sensitive_strings(out, extra_secrets=[active_pass] if active_pass else None)
        clean_err = VaultService.redact_sensitive_strings(err, extra_secrets=[active_pass] if active_pass else None)

        return exit_code, clean_out, clean_err

    @classmethod
    async def test_linux_ssh(cls, parameters: Dict[str, Any], db=None) -> Dict[str, Any]:
        cfg = await cls.get_linux_ssh_config(db, parameters)
        # For testing, prefer explicit password from params or configs
        password = (parameters and parameters.get("password")) or cfg["password"] or ""

        try:
            client, active_user, active_pass, auth_method = cls.connect_ssh_client(
                host=cfg["host"],
                port=cfg["port"],
                user=cfg["user"],
                password=password,
                private_key_pem=cfg["private_key"],
                auth_type=cfg["auth_type"]
            )
            exit_code, out, err = cls.execute_sudo_command(
                client=client,
                command="uname -a; whoami",
                active_user=active_user,
                active_pass=active_pass,
                auth_method=auth_method,
                use_nopasswd=cfg["use_nopasswd"]
            )
            client.close()
            return {
                "status": "success",
                "mode": "live",
                "auth_method": auth_method,
                "message": f"Kết nối SSH thành công tới máy ảo {cfg['host']} (User: {active_user}, Auth: {auth_method})!",
                "output": out.strip()
            }
        except Exception as e:
            return {
                "status": "failed",
                "mode": "live",
                "message": f"Không thể kết nối SSH tới máy ảo {cfg['host']}: {str(e)}"
            }

    @classmethod
    async def block_ip_linux_ssh(cls, ip: str, parameters: Dict[str, Any], db=None) -> Dict[str, Any]:
        clean_ip = sanitize_ip(ip)
        if not clean_ip:
            return {"status": "failed", "message": f"Invalid IP address format: {ip}"}

        cfg = await cls.get_linux_ssh_config(db, parameters)

        try:
            client, active_user, active_pass, auth_method = cls.connect_ssh_client(
                host=cfg["host"],
                port=cfg["port"],
                user=cfg["user"],
                password=cfg["password"],
                private_key_pem=cfg["private_key"],
                auth_type=cfg["auth_type"]
            )
            command = f"iptables -I INPUT -s {clean_ip} -j DROP"
            exit_code, out, err = cls.execute_sudo_command(
                client=client,
                command=command,
                active_user=active_user,
                active_pass=active_pass,
                auth_method=auth_method,
                use_nopasswd=cfg["use_nopasswd"]
            )
            client.close()

            if exit_code == 0:
                return {
                    "status": "success",
                    "mode": "live",
                    "auth_method": auth_method,
                    "target": clean_ip,
                    "host": cfg["host"],
                    "message": f"Đã chặn thành công IP {clean_ip} trên máy ảo {cfg['host']} (Auth: {auth_method}) qua iptables."
                }
            else:
                return {
                    "status": "failed",
                    "target": clean_ip,
                    "message": f"Lỗi thực thi iptables trên {cfg['host']}: {err.strip() or out.strip()}"
                }
        except Exception as e:
            return {
                "status": "failed",
                "target": clean_ip,
                "message": f"Lỗi SSH khi kết nối tới máy ảo {cfg['host']}: {str(e)}"
            }

    @classmethod
    async def unblock_ip_linux_ssh(cls, ip: str, parameters: Dict[str, Any], db=None) -> Dict[str, Any]:
        clean_ip = sanitize_ip(ip)
        if not clean_ip:
            return {"status": "failed", "message": f"Invalid IP address format: {ip}"}

        cfg = await cls.get_linux_ssh_config(db, parameters)

        try:
            client, active_user, active_pass, auth_method = cls.connect_ssh_client(
                host=cfg["host"],
                port=cfg["port"],
                user=cfg["user"],
                password=cfg["password"],
                private_key_pem=cfg["private_key"],
                auth_type=cfg["auth_type"]
            )
            command = f"iptables -D INPUT -s {clean_ip} -j DROP"
            exit_code, out, err = cls.execute_sudo_command(
                client=client,
                command=command,
                active_user=active_user,
                active_pass=active_pass,
                auth_method=auth_method,
                use_nopasswd=cfg["use_nopasswd"]
            )
            client.close()

            if exit_code == 0:
                return {
                    "status": "success",
                    "mode": "live",
                    "auth_method": auth_method,
                    "message": f"Đã bỏ chặn thành công IP {clean_ip} trên máy ảo {cfg['host']} (Auth: {auth_method})."
                }
            else:
                # If rule didn't exist, try unblocking by line scanning or return clean message
                if "Bad rule" in err or "does not exist" in err:
                    return {
                        "status": "success",
                        "mode": "live",
                        "auth_method": auth_method,
                        "message": f"Rule chặn IP {clean_ip} không tồn tại trên iptables của {cfg['host']} (đã sạch)."
                    }
                return {
                    "status": "failed",
                    "message": f"Không thể bỏ chặn IP {clean_ip} trên {cfg['host']}: {err.strip() or out.strip()}"
                }
        except Exception as e:
            return {
                "status": "failed",
                "message": f"Lỗi SSH khi kết nối tới máy ảo {cfg['host']}: {str(e)}"
            }

    @classmethod
    async def delete_rule_linux_ssh_by_num(
        cls, line_num: str, parameters: Optional[Dict[str, Any]] = None, db=None
    ) -> Dict[str, Any]:
        if not line_num or not str(line_num).strip().isdigit():
            return {"status": "failed", "message": "Invalid rule line number"}
        clean_num = str(int(str(line_num).strip()))

        cfg = await cls.get_linux_ssh_config(db, parameters)

        try:
            client, active_user, active_pass, auth_method = cls.connect_ssh_client(
                host=cfg["host"],
                port=cfg["port"],
                user=cfg["user"],
                password=cfg["password"],
                private_key_pem=cfg["private_key"],
                auth_type=cfg["auth_type"]
            )
            cmd = f"iptables -D INPUT {clean_num}"
            exit_code, out, err = cls.execute_sudo_command(
                client=client,
                command=cmd,
                active_user=active_user,
                active_pass=active_pass,
                auth_method=auth_method,
                use_nopasswd=cfg["use_nopasswd"]
            )
            client.close()

            if exit_code == 0:
                return {
                    "status": "success",
                    "mode": "live",
                    "auth_method": auth_method,
                    "message": f"Đã xoá rule #{clean_num} thành công khỏi iptables trên máy ảo {cfg['host']} (Auth: {auth_method})."
                }
            else:
                return {
                    "status": "failed",
                    "message": f"Không thể xoá rule #{clean_num} trên máy ảo {cfg['host']}: {err.strip() or out.strip()}"
                }
        except Exception as e:
            return {"status": "failed", "message": f"Lỗi SSH khi xoá rule trên {cfg['host']}: {str(e)}"}

    @classmethod
    async def list_firewall_rules_linux_ssh(cls, db=None) -> Dict[str, Any]:
        cfg = await cls.get_linux_ssh_config(db)

        try:
            client, active_user, active_pass, auth_method = cls.connect_ssh_client(
                host=cfg["host"],
                port=cfg["port"],
                user=cfg["user"],
                password=cfg["password"],
                private_key_pem=cfg["private_key"],
                auth_type=cfg["auth_type"]
            )
            cmd = "iptables -L INPUT -n --line-numbers"
            exit_code, raw_out, raw_err = cls.execute_sudo_command(
                client=client,
                command=cmd,
                active_user=active_user,
                active_pass=active_pass,
                auth_method=auth_method,
                use_nopasswd=cfg["use_nopasswd"]
            )
            client.close()

            rules = []
            for line in raw_out.splitlines():
                line_s = line.strip()
                if not line_s:
                    continue
                parts = line_s.split()
                if parts and parts[0].isdigit():
                    num = int(parts[0])
                    target = parts[1] if len(parts) > 1 else ""
                    prot = parts[2] if len(parts) > 2 else ""
                    opt = parts[3] if len(parts) > 3 else ""
                    src = parts[4] if len(parts) > 4 else ""
                    dst = parts[5] if len(parts) > 5 else ""
                    rules.append({
                        "line_num": num,
                        "target": target,
                        "protocol": prot,
                        "options": opt,
                        "source": src,
                        "destination": dst,
                        "raw": line_s
                    })

            return {
                "status": "success",
                "connector": "linux_ssh",
                "host": cfg["host"],
                "user": active_user,
                "auth_method": auth_method,
                "rules_count": len(rules),
                "rules": rules,
                "raw_output": raw_out
            }
        except Exception as e:
            return {
                "status": "error",
                "connector": "linux_ssh",
                "host": cfg["host"],
                "message": f"Lỗi truy vấn iptables trên máy ảo {cfg['host']}: {str(e)}",
                "rules_count": 0,
                "rules": [],
                "raw_output": ""
            }
