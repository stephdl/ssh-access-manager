import ipaddress
import os
import subprocess

import yaml

import db

SERVERS_YML = os.environ.get("SERVERS_YML", "/data/config/servers.yml")
KNOWN_HOSTS = os.environ.get("KNOWN_HOSTS", "/data/keys/known_hosts")


def load_servers_yml(path: str = SERVERS_YML) -> list[dict]:
    """Parse servers.yml and return the list of server dicts."""
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("servers") or []


def _hostname_in_known_hosts(hostname: str, known_hosts: str = KNOWN_HOSTS) -> bool:
    try:
        with open(known_hosts) as f:
            return any(hostname in line for line in f)
    except FileNotFoundError:
        return False


def add_to_known_hosts(ip: str, port: int = 22, known_hosts: str = KNOWN_HOSTS) -> None:
    """Run ssh-keyscan on ip (and port) and append to known_hosts if not present."""
    ip = str(ipaddress.ip_address(ip.strip()))
    if _hostname_in_known_hosts(ip, known_hosts):
        return
    cmd = ["ssh-keyscan", "-H", "-T", "10"]
    if port != 22:
        cmd += ["-p", str(port)]
    cmd.append(ip)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        with open(known_hosts, "a") as f:
            f.write(result.stdout)
    else:
        raise RuntimeError(f"ssh-keyscan failed for {ip}")


def sync_servers(path: str = SERVERS_YML) -> list[dict]:
    """
    Sync servers.yml into the servers table.

    Upserts each server by hostname. Returns the list of active server dicts
    as loaded from the YAML (not re-queried from DB).
    """
    servers = load_servers_yml(path)
    for s in servers:
        db.execute(
            """
            INSERT INTO servers (hostname, ip_address, environment, os_family, ssh_port)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (hostname) DO UPDATE SET
                ip_address  = EXCLUDED.ip_address,
                environment = EXCLUDED.environment,
                os_family   = EXCLUDED.os_family,
                ssh_port    = EXCLUDED.ssh_port,
                is_active   = true
            """,
            (
                s["hostname"],
                s["ip"],
                s.get("environment"),
                s.get("os_family"),
                s.get("ssh_port", 22),
            ),
        )
    return servers


def get_active_servers() -> list[dict]:
    """Return all active servers from the database."""
    return db.query(
        "SELECT * FROM servers WHERE is_active = true ORDER BY hostname"
    )
