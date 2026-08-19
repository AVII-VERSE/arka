"""
ARKA Agent CLI Daemon Entrypoint.
"""

import os
import platform

from arka_agent.buffer.sqlite_queue import SQLiteQueue
from arka_agent.collectors.linux_syslog import LinuxSyslogCollector
from arka_agent.collectors.windows_event_log import WindowsEventLogCollector
from arka_agent.transport.http_client import AgentHTTPTransport


def main() -> None:
    server_url = os.getenv("ARKA_AGENT_SERVER_URL", "http://localhost:8000")
    agent_token = os.getenv("ARKA_AGENT_TOKEN", "dev-agent-token")
    agent_id = os.getenv("ARKA_AGENT_ID", "agent-dev-01")
    tenant_id = os.getenv("ARKA_TENANT_ID", "default-tenant")

    print(f"[*] Starting ARKA Agent Daemon (ID: {agent_id}, Target: {server_url})")

    queue = SQLiteQueue("agent_buffer.db")
    transport = AgentHTTPTransport(server_url=server_url, agent_token=agent_token)

    if platform.system().lower() == "windows":
        collector = WindowsEventLogCollector(agent_id=agent_id, tenant_id=tenant_id)
    else:
        collector = LinuxSyslogCollector(agent_id=agent_id, tenant_id=tenant_id)

    # Harvest security events
    events = collector.collect()
    print(f"[*] Collected {len(events)} security events from OS telemetry.")

    for event in events:
        queue.push(event)

    # Flush local queue to Ingestion Gateway
    pending_batch = queue.pop_batch(batch_size=50)
    if pending_batch:
        success = transport.send_events(pending_batch)
        if success:
            queue.delete_batch(batch_size=len(pending_batch))
            print(f"[+] Successfully transmitted {len(pending_batch)} events to ARKA Ingestion API.")
        else:
            print(f"[-] Transport failed. {len(pending_batch)} events buffered in SQLite queue.")

    # Send Agent Heartbeat
    transport.send_heartbeat(agent_id=agent_id, metrics={"hostname": platform.node()})


if __name__ == "__main__":
    main()
