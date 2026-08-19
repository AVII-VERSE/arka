# ARKA Endpoint Agent Architecture

## Overview

The ARKA Agent is a lightweight cross-platform daemon responsible for harvesting operating system security events, normalizing metadata locally, buffering payloads safely during network disruptions, and transmitting events to the ARKA Ingestion API.

---

## Agent Components

```
+-------------------------------------------------------------------+
|                            ARKA AGENT                             |
|                                                                   |
|   +---------------------+   +---------------------+               |
|   | Windows EventLog    |   | Linux Syslog /      |               |
|   | Collector           |   | Journald Collector  |               |
|   +----------+----------+   +----------+----------+               |
|              |                         |                          |
|              +------------+------------+                          |
|                           | Raw Event                             |
|                           v                                       |
|               +-----------------------+                           |
|               | Disk SQLite Queue     | (Local Buffer)            |
|               +-----------+-----------+                           |
|                           | Flush Batches                         |
|                           v                                       |
|               +-----------------------+                           |
|               | Transport Engine      | (HTTPS / Retry Backoff)   |
|               +-----------+-----------+                           |
+---------------------------|---------------------------------------+
                            | PUSH
                            v
                 [ARKA Ingestion API]
```

---

## Key Responsibilities

1. **Telemetry Collection**:
   - **Windows**: Windows Security Event Log (ID 4624, 4625, 4672, 7045), PowerShell Operational Log (ID 4104).
   - **Linux**: `/var/log/auth.log`, `/var/log/syslog`, `journalctl` (SSH failures, `sudo` execution).
2. **Local Resilient Queue**: Uses an embedded SQLite database (`queue.sqlite3`) as a FIFO ring buffer. If the backend is unreachable, events accumulate locally (up to configured disk limits) and flush automatically upon reconnection.
3. **Heartbeat Daemon**: Periodically reports host telemetry (CPU, memory, disk usage, agent uptime) to `/api/v1/agents/heartbeat`.
4. **Non-Intrusive Privacy Enforcement**: Never records keystrokes, clipboard contents, network packet payloads, or user credentials.
