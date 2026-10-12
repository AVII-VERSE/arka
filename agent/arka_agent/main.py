"""
ARKA Agent CLI Daemon Entrypoint.
Continuously enrolls, collects telemetry, buffers to local SQLite queue, and transmits to ARKA server.
"""

import os
import platform
import socket
import time

from arka_agent.buffer.sqlite_queue import SQLiteQueue
from arka_agent.collectors.base import BaseCollector
from arka_agent.collectors.linux_syslog import LinuxSyslogCollector
from arka_agent.collectors.windows_event_log import WindowsEventLogCollector
from arka_agent.transport.http_client import AgentHTTPTransport


def get_local_ip() -> str:
    """Discovers host non-loopback IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main() -> None:
    server_url = os.getenv("ARKA_AGENT_SERVER_URL", "http://localhost:8000")
    agent_token = os.getenv("ARKA_AGENT_TOKEN", "dev-agent-token")
    tenant_id = os.getenv("ARKA_TENANT_ID", "default-tenant")

    hostname = platform.node()
    ip_address = get_local_ip()
    os_type = platform.system().lower()
    os_version = f"{platform.system()} {platform.release()} ({platform.version()})"
    agent_id = os.getenv("ARKA_AGENT_ID", "")

    print(f"[*] Initializing ARKA Agent Daemon on host: {hostname} ({ip_address})")
    print(f"[*] Target ARKA Endpoint: {server_url}")

    queue = SQLiteQueue("agent_buffer.db")
    transport = AgentHTTPTransport(server_url=server_url, agent_token=agent_token)

    # 1. Enroll Agent with ARKA Backend
    enrollment_payload = {
        "enrollment_token": agent_token,
        "hostname": hostname,
        "ip_address": ip_address,
        "os_type": os_type,
        "os_version": os_version,
        "agent_version": "0.1.0",
    }
    enrolled_data = transport.enroll(enrollment_payload)
    if enrolled_data and "id" in enrolled_data:
        agent_id = enrolled_data["id"]
        print(f"[+] Successfully registered with ARKA Fleet! Agent ID: {agent_id}")
    else:
        if not agent_id:
            agent_id = f"agent-{hostname.lower()}"
        print(f"[!] Enrollment deferred; proceeding with local identifier: {agent_id}")

    collector: BaseCollector
    if platform.system().lower() == "windows":
        collector = WindowsEventLogCollector(agent_id=agent_id, tenant_id=tenant_id)
    else:
        collector = LinuxSyslogCollector(agent_id=agent_id, tenant_id=tenant_id)

    print("[+] Telemetry collector active. Starting real-time ingestion loop...")

    cycle = 0
    while True:
        cycle += 1
        try:
            # Harvest security telemetry
            events = collector.collect()
            if events:
                for event in events:
                    # Guarantee agent_id is accurate
                    event["agent_id"] = agent_id
                    event["tenant_id"] = tenant_id
                    queue.push(event)

            # Flush local queue to Ingestion Gateway
            pending_batch = queue.pop_batch(batch_size=50)
            if pending_batch:
                success = transport.send_events(pending_batch)
                if success:
                    queue.delete_batch(batch_size=len(pending_batch))
                    if cycle % 3 == 0:
                        print(f"[+] Ingested {len(pending_batch)} security events into ARKA SIEM.")
                else:
                    print(f"[-] Transport retry: {len(pending_batch)} events safely queued.")

            # Send Agent Heartbeat Ping with host metrics
            transport.send_heartbeat(
                agent_id=agent_id,
                metrics={
                    "hostname": hostname,
                    "ip": ip_address,
                    "os": os_version,
                    "status": "ONLINE",
                    "uptime_cycles": cycle,
                },
            )
        except Exception as err:
            print(f"[-] Daemon cycle error: {err}")

        time.sleep(5)


if __name__ == "__main__":
    main()
