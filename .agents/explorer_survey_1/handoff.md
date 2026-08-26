# Explorer Survey Handoff Report: Agent Architecture & Collectors Deep Dive

**Explorer Agent**: `explorer_survey_1` (Teamwork Explorer #1)
**Scope**: ARKA Agent Daemon (`agent/`), Collectors (`agent/arka_agent/collectors/`), Active Response (`agent/arka_agent/active_response.py`), Transport & Buffering (`agent/arka_agent/transport/`, `agent/arka_agent/buffer/`), Test Suite (`agent/tests/`), and Backend Telemetry Ingestion Contract.
**Date**: 2026-08-26

---

## 1. Observation

### 1.1 Codebase Structure & File Inventory
Inspection of `d:/ARKA/agent/` revealed 12 Python source files and 7 test files:
- **Core Agent & Daemon Loop**:
  - `agent/arka_agent/main.py` (62 lines): CLI daemon entrypoint.
  - `agent/arka_agent/buffer/sqlite_queue.py` (71 lines): Local disk FIFO buffer (`event_queue` table).
  - `agent/arka_agent/transport/http_client.py` (54 lines): HTTP client with backoff for `/api/v1/events/ingest` and `/api/v1/agents/heartbeat`.
- **Collectors & Security Harvesters**:
  - `agent/arka_agent/collectors/base.py` (19 lines): Abstract `BaseCollector` interface with `collect() -> list[dict[str, Any]]`.
  - `agent/arka_agent/collectors/rootcheck.py` (113 lines): `RootcheckScanner`.
  - `agent/arka_agent/collectors/sca.py` (143 lines): `SCAScanner`.
  - `agent/arka_agent/collectors/syscollector.py` (121 lines): `SyscollectorHarvester`.
  - `agent/arka_agent/collectors/fim.py` (136 lines): `FileIntegrityMonitor`.
  - `agent/arka_agent/collectors/vulnerability.py` (57 lines): `PackageVulnerabilityScanner`.
  - `agent/arka_agent/collectors/linux_syslog.py` (42 lines): `LinuxSyslogCollector`.
  - `agent/arka_agent/collectors/windows_event_log.py` (47 lines): `WindowsEventLogCollector`.
- **Containment & Response**:
  - `agent/arka_agent/active_response.py` (107 lines): `ActiveResponseExecutor`.
- **Test Suite** (`agent/tests/`):
  - `test_active_response.py` (43 lines)
  - `test_collectors.py` (22 lines)
  - `test_fim_and_process_lineage.py` (68 lines)
  - `test_queue.py` (25 lines)
  - `test_rootcheck_and_syscollector.py` (35 lines)
  - `test_sca_benchmarks.py` (42 lines)
  - `test_vulnerability_engine.py` (36 lines)

### 1.2 Observations of Current Implementations and Gaps

#### Gap 1: Disconnected Collector Interface & Daemon Loop
In `agent/arka_agent/main.py:27-57`:
- Only one collector (`WindowsEventLogCollector` or `LinuxSyslogCollector`) is instantiated based on `platform.system()`.
- `RootcheckScanner`, `SCAScanner`, `SyscollectorHarvester`, `FileIntegrityMonitor`, and `ActiveResponseExecutor` are **not invoked or scheduled anywhere** in `main.py`.
- None of `RootcheckScanner`, `SCAScanner`, `SyscollectorHarvester`, `FileIntegrityMonitor`, or `PackageVulnerabilityScanner` inherit from `BaseCollector` or share a uniform execution interface.

#### Gap 2: R1 Rootcheck Scanner Limitations (`rootcheck.py:20-112`)
- **Filesystem Scan**: Checks only 2 static paths on Windows and 6 static paths on Linux (`rootcheck.py:24-38`). Lacks recursive directory scanning for hidden directories (`/dev/.udev`, `/dev/.shm`, `/tmp/.*`), LKM rootkits (Diamorphine, Reptile, Azazel, adore-ng), trojaned system binaries (`/bin/ps`, `/bin/netstat`, `/bin/ls`, `/usr/sbin/sshd`), or Windows `AppInit_DLLs` / Driver artifacts.
- **Hidden Processes**: No hidden process detection. Does not cross-verify standard OS APIs (`psutil.pids()`) against raw filesystem enumeration (`/proc/[0-9]+` on Linux or low-level API queries).
- **Network Ports**: Scans only 5 hardcoded ports (`(31337, 6667, 4444, 12345, 65535)`) in `rootcheck.py:73`. Lacks promiscuous interface detection (`IFF_PROMISC`), raw socket detection, or unlinked listener sockets.

#### Gap 3: R2 SCA & CIS Benchmarks Engine Limitations (`sca.py:20-142`)
- Contains only 3 static checks:
  1. `check_ssh_root_login` (checks `/etc/ssh/sshd_config` for `PermitRootLogin no`)
  2. `check_host_firewall` (`netsh` check on Windows, `/usr/sbin/ufw` file existence on Linux)
  3. `check_password_policy` (hardcoded static `PASS` with zero actual OS evaluation in `sca.py:102-110`) -> **Fake Data Violation**.
- Lacks a policy engine for extensible CIS Benchmark evaluations (Linux Distribution Independent v2.0, Windows Server/Desktop CIS benchmarks).
- Lacks evaluators for Linux PAM (`/etc/pam.d/common-password`, `/etc/login.defs`), file permissions/ownership on critical files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`), Windows Registry policies, Windows UAC, SMBv1, and safe command evaluators.

#### Gap 4: R3 Syscollector System Inventory Harvester Limitations (`syscollector.py:20-120`)
- Gathers hardware info, OS info, network interfaces, and up to 50 processes.
- **Completely missing installed software package harvesting**! (In `vulnerability.py:26-41`, packages were hardcoded mock dictionaries `{"name": "openssl", "version": "1.1.1t"}`).
- Lacks real OS package extraction across Linux Debian/Ubuntu (`dpkg-query`), RedHat/CentOS (`rpm -qa`), Alpine (`apk info -v`), Windows Registry (`Uninstall` 32-bit & 64-bit), and Python environment (`importlib.metadata.distributions()`).
- Lacks detailed open port enumeration and process lineage metadata.

#### Gap 5: R4 Automated Active Response Executor Limitations (`active_response.py:31-106`)
- `block_ip(ip_address)`: Returns dummy status `SUCCESS` without actually modifying host firewall rules (`active_response.py:35-44`).
- `kill_process(pid)`: Calls `proc.terminate()`, but lacks safety allowlists (can kill critical system processes PID 0, 1, 4, lsass, or agent daemon itself), lacks force kill fallback (`proc.kill()`), and lacks child process tree termination.
- `quarantine_file` / `unquarantine_file`: Directory is created, but file isolation, hashing, permission restriction, manifest tracking, and rollback are completely unimplemented.
- No command execution timeout, no safety policy validation, and no automatic rollback mechanism.

#### Gap 6: Backend Transport & Ingestion Contracts
Backend inspection revealed the following target endpoints:
- `POST /api/v1/events/ingest` (batch `NormalizedEvent`)
- `POST /api/v1/agents/heartbeat` (`AgentHeartbeat`)
- `POST /api/v1/sca/report` (`SCAPayload`)
- `POST /api/v1/inventory/snapshot` (`InventorySnapshotPayload`)
- `POST /api/v1/active_response/trigger` and `GET /api/v1/active_response`

---

## 2. Logic Chain

1. **System Integrity & Trust Model**: An endpoint agent is the foundation of SIEM/EDR detection. If telemetry is hardcoded or fake (as observed in `sca.py:107` and `vulnerability.py:26`), downstream detection rules, CVE correlation engines, and compliance dashboards are invalidated.
2. **Collector Scheduling & Thread Isolation**: Continuous log streams require low latency (0-5s), while heavy audits take 1-30 seconds. A multi-threaded or asynchronous scheduler with isolated worker threads is required so that periodic heavy audits do not block real-time event streaming.
3. **Cross-Platform Abstraction with Zero Fake Data**: The agent must run on Linux, Windows, and macOS without crashing. Operating system APIs (`winreg`, `psutil`, `/proc`, `dpkg`, `rpm`, `iptables`, `netsh`) must be accessed natively on host OS, with clean abstractions for cross-platform test suites.
4. **Active Response Safety & Rollback**: Automated active response carries operational risk. Strict safety guardrails (protected PID allowlist, RFC1918/gateway IP protection, execution timeouts, atomic quarantine vaults, rollback timers) are mandatory.

---

## 3. Caveats

1. **OS Privileges**: Certain telemetry harvesters require root/admin privileges. When run as a standard user, collectors must gracefully catch permission exceptions (`PermissionError`, `psutil.AccessDenied`), report `PERMISSION_DENIED` status, and continue operation without crashing.
2. **Platform Native Binaries**: Linux package tools (`dpkg-query`, `rpm`, `apk`) and Windows registry (`winreg`) are platform-specific. Code must check `platform.system()` and tool availability before invoking external utilities.
3. **Performance Budget**: Heavy filesystem crawls must be scoped to standard system directories to prevent excessive CPU or I/O load.

---

## 4. Conclusion & Technical Implementation Blueprint

### 4.1 Architecture of the Enhanced Agent

```
                        +---------------------------------------------+
                        |             ARKA Agent Daemon               |
                        |          (arka_agent/main.py)               |
                        +---------------------------------------------+
                                       |              |
                      +----------------+              +-----------------+
                      | Multi-Collector Scheduler                       | Active Response Handler
                      | (Threaded / Periodic Workers)                   | (Command Dispatcher)
                      +--------------------------------                 +-----------------------+
                      |                                                 |
       +--------------+--------------+-------------+                    | - Safe Process Term
       |              |              |             |                    | - Firewall IP Block
+------------+ +------------+ +------------+ +------------+             | - File Quarantine Vault
| Rootcheck  | |    SCA     | |Syscollector| | Log/FIM    |             | - Timed Rollback
| Scanner    | | CIS Engine | | Harvester  | | Collectors |             +-----------------------+
+------------+ +------------+ +------------+ +------------+                         |
       |              |              |             |                                |
       +--------------+--------------+-------------+                                |
                      |                                                             |
                      v                                                             v
             +------------------+                                          +-----------------+
             |   SQLiteQueue    | <======================================= |  Audit Logger   |
             | (Offline Buffer) |                                          +-----------------+
             +------------------+
                      |
                      v
             +----------------------+
             |  AgentHTTPTransport  |
             +----------------------+
               |        |        |
               |        |        +----> POST /api/v1/inventory/snapshot
               |        +-------------> POST /api/v1/sca/report
               +----------------------> POST /api/v1/events/ingest
                                        POST /api/v1/agents/heartbeat
```

### 4.2 Detailed Blueprint for R1: Rootcheck & System Anomaly Harvester
**Target File**: `agent/arka_agent/collectors/rootcheck.py`

#### Key Capabilities & Methods:
1. **Rootkit Signature Harvester (`scan_suspicious_files`)**:
   - Expanded known rootkit artifact database:
     - Linux: Diamorphine (`/dev/diamorphine`), Reptile (`/dev/reptile`, `/tmp/.reptile*`), Azazel (`/etc/ld.so.preload` entries), adore-ng, Knark, t0rn, Ebury, `/dev/.udev`, `/dev/.shm`, hidden directories in `/dev`, `/tmp`, `/var/tmp`.
     - Windows: Suspicious driver binaries in `C:\Windows\System32\drivers\`, hidden files in `System32\config\`, suspicious registry startup keys (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, `AppInit_DLLs`).
   - SUID/SGID rootkit binary scanner on Linux: Scans `/bin`, `/sbin`, `/usr/bin` for unexpected SUID/SGID permissions (`stat.S_ISUID | stat.S_ISGID`).
2. **Hidden Process Detection (`scan_hidden_processes`)**:
   - Dual-view cross-validation:
     - View 1: Standard API process list `psutil.pids()`.
     - View 2: Direct OS filesystem scan (`/proc/[0-9]+` directory listing on Linux, or Toolhelp32/low-level API on Windows).
     - Cross-check: If a PID exists in `/proc` but is absent from `psutil.pids()`, or responds to `os.kill(pid, 0)` without appearing in process enumeration -> Flag `hidden_process_detected` (MITRE `T1014` / `T1057`).
3. **Hidden / Promiscuous Network Port Scanner (`scan_listening_ports`)**:
   - Sockets with missing/unresolved PID or anomalous process association.
   - Promiscuous network interface mode detection on Linux (reads `/sys/class/net/<iface>/flags` and checks `0x100` / `IFF_PROMISC` flag).
   - High-risk backdoor and C2 listening port detection (31337, 6667, 4444, 12345, 65535, 8080/8443 unauthenticated reverse shells).
4. **System Binary & Preload Tampering (`scan_system_binaries`)**:
   - Inspect `/etc/ld.so.preload` for unauthorized shared object injection (Linux).
   - Inspect Windows `AppInit_DLLs` registry key.
   - Check critical system binary existence and permission anomalies (`/bin/ps`, `/bin/netstat`, `/bin/ls`, `/bin/login`, `/usr/sbin/sshd`).
5. **Event Emission**:
   - Emits standardized `NormalizedEvent` with severity `CRITICAL` or `HIGH`, MITRE ATT&CK technique tags, and full structured metadata.

### 4.3 Detailed Blueprint for R2: SCA & CIS Benchmarks Engine
**Target File**: `agent/arka_agent/collectors/sca.py` & `backend/app/services/sca_engine.py`

#### Key Capabilities & Methods:
1. **Rule Definition Schema & CIS Profiles**:
   - Define structured check types:
     - `file_content`: Regex pattern matching in target configuration files.
     - `file_permissions`: Verification of file mode bits (`<= 0644`, `0600`) and ownership (`UID == 0`, `GID == 0`).
     - `registry_value`: Windows registry key, value name, expected type, and expected data.
     - `command_output`: Safe execution of system audit command (`sysctl`, `auditctl`, `semanage`, `netsh`) with output pattern matching.
     - `service_status`: Verifies target service is inactive/disabled or active.
2. **Multi-Platform CIS Benchmarks**:
   - **Linux CIS Profile (CIS Linux v2.0)**:
     - `CIS-1.1.1`: Verify permissions on `/etc/passwd` (`<= 0644`, root:root).
     - `CIS-1.1.2`: Verify permissions on `/etc/shadow` (`<= 0600` or `0640`, root:shadow/root).
     - `CIS-1.1.3`: Verify permissions on `/etc/sudoers` (`<= 0440`, root:root).
     - `CIS-2.1.1`: Ensure SSH `PermitRootLogin no` in `/etc/ssh/sshd_config`.
     - `CIS-2.1.2`: Ensure SSH `Protocol 2` or `MaxAuthTries <= 4`.
     - `CIS-3.1.1`: Ensure IP forwarding is disabled (`net.ipv4.ip_forward == 0`).
     - `CIS-3.1.2`: Ensure ICMP redirect acceptance is disabled (`net.ipv4.conf.all.accept_redirects == 0`).
     - `CIS-3.2.1`: Ensure Host Firewall is active (UFW, NFTables, or IPtables).
     - `CIS-4.1.1`: Verify `auditd` daemon is installed and active.
     - `CIS-5.1.1`: Password expiration policy (`PASS_MAX_DAYS <= 90` in `/etc/login.defs`).
     - `CIS-5.1.2`: Password minimum length (`PASS_MIN_LEN >= 14` or `pam_pwquality.so minlen=14`).
   - **Windows CIS Profile (CIS Windows Server/Client)**:
     - `CIS-WIN-1.1`: Windows Defender Firewall enabled for Domain, Private, and Public profiles.
     - `CIS-WIN-1.2`: User Account Control (UAC) enabled (`EnableLUA == 1`).
     - `CIS-WIN-1.3`: Disable SMBv1 Protocol (`LanmanServer\Parameters\SMB1 == 0`).
     - `CIS-WIN-1.4`: Account Lockout Threshold configured (`<= 5` attempts).
     - `CIS-WIN-1.5`: Minimum Password Length (`>= 14` characters).
     - `CIS-WIN-1.6`: Disable Guest Account status.
3. **Zero Fake Data Rule Evaluators**:
   - Real filesystem stat checks with `os.stat`.
   - Real file reading and regex pattern analysis.
   - Real `winreg` registry queries on Windows.
   - Safe `subprocess.run(..., shell=False, timeout=5)` execution.
4. **Scoring & Compliance Output**:
   - Generates complete `SCAPayload` compliant with `backend/app/api/v1/endpoints/sca.py`.
   - Compliance score = `round((passed / (passed + failed)) * 100, 1)`.
   - Section-by-section breakdown and actionable remediation guidance for each failing check.

### 4.4 Detailed Blueprint for R3: Syscollector System Inventory Harvester
**Target File**: `agent/arka_agent/collectors/syscollector.py` & `backend/app/api/v1/endpoints/inventory.py`

#### Key Capabilities & Methods:
1. **Installed Software Package Harvester (`get_installed_packages`)**:
   - Linux Debian/Ubuntu: Run `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n'` or parse `/var/lib/dpkg/status` if subprocess fails.
   - Linux RedHat/CentOS/Rocky: Run `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'`.
   - Linux Alpine: Run `apk info -v`.
   - Windows: Query `winreg` registry at `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` and `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall` for `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`.
   - Python Environment: Query `importlib.metadata.distributions()` for installed python modules and versions.
2. **Network Ports & Listening Sockets (`get_network_ports`)**:
   - Iterate over `psutil.net_connections(kind="inet")`.
   - Extract: Protocol (`tcp`/`udp`), Local IP, Local Port, Remote IP, Remote Port, Status (`LISTEN`, `ESTABLISHED`), PID, Process Name, Executable Path.
3. **Enhanced Network Interfaces (`get_network_interfaces`)**:
   - Interface name, IPv4 addresses, IPv6 addresses, MAC address, Netmask, Broadcast address, MTU, Status (isup), Speed.
4. **Enhanced Hardware & OS Inventory**:
   - Hardware: CPU model name, physical cores, logical cores, architecture, RAM total/available/used, Swap memory total/used, Disk partitions (device, mountpoint, fstype, total/used/free GB), System Boot Time, Uptime.
   - OS: Name, Release, Version, Kernel Architecture, Hostname, Python Version, Machine/Product UUID.
5. **Running Processes with Detailed Lineage (`get_running_processes`)**:
   - Enumerate active processes with attributes: `pid`, `ppid`, `name`, `exe`, `cmdline`, `username`, `cpu_percent`, `memory_percent`, `status`, `create_time`, `num_threads`.
6. **Snapshot Payload Generation**:
   - Returns complete dictionary matching `InventorySnapshotPayload` ready for transmission to `POST /api/v1/inventory/snapshot`.

### 4.5 Detailed Blueprint for R4: Automated Active Response Container
**Target File**: `agent/arka_agent/active_response.py` & `backend/app/services/active_response_service.py`

#### Key Capabilities & Methods:
1. **Real Host Firewall IP Blocking (`block_ip` / `unblock_ip`)**:
   - Validation & Safety: Validate IP syntax with `ipaddress.ip_address`. Disallow blocking protected IPs (`127.0.0.1`, `::1`, loopback networks `127.0.0.0/8`, broadcast `255.255.255.255`, default gateway, backend server host IP).
   - Linux Execution:
     - `iptables -I INPUT -s <ip> -j DROP -m comment --comment "ARKA_ActiveResponse"`
     - Unblock: `iptables -D INPUT -s <ip> -j DROP -m comment --comment "ARKA_ActiveResponse"`
   - Windows Execution:
     - `netsh advfirewall firewall add rule name="ARKA_Block_<ip>" dir=in action=block remoteip=<ip>`
     - Unblock: `netsh advfirewall firewall delete rule name="ARKA_Block_<ip>"`
2. **Safe Process Termination (`kill_process`)**:
   - Safety checks: Prevent terminating protected system PIDs:
     - Linux: PID 0, 1, 2, agent daemon PID, parent PID.
     - Windows: PID 0, 4, `smss.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, agent PID.
   - Two-phase kill:
     - Phase 1: Graceful `proc.terminate()` (`SIGTERM`), wait up to 3.0 seconds.
     - Phase 2: If process is still alive, force `proc.kill()` (`SIGKILL`).
   - Recursive child kill option (`proc.children(recursive=True)`).
3. **Secure File Quarantine Vault (`quarantine_file` / `unquarantine_file`)**:
   - Quarantine storage directory: `/var/lib/arka/quarantine/` (Linux) or `C:\ProgramData\ARKA\Quarantine` (Windows) with restricted root/SYSTEM-only permissions (`0700` / NTFS ACL).
   - Operation:
     - Pre-quarantine: Compute SHA-256 hash, capture original path, permissions, size, and timestamp.
     - Move file into quarantine vault with unique identifier name `<sha256>.quarantine`.
     - Write metadata manifest `<sha256>.manifest.json`.
     - Unquarantine: Read manifest, verify hash, move file back to original location, restore permissions.
4. **Command Dispatcher & Safety Policy (`execute_command`)**:
   - Actions: `block_ip`, `unblock_ip`, `kill_process`, `quarantine_file`, `unquarantine_file`, `custom_command`.
   - Execution timeout (default 15s) using `subprocess.run(..., timeout=timeout)`.
   - Automated rollback timer: Optional `duration_seconds` for temporary IP blocking or process isolation.
   - Comprehensive audit logging dictionary: `response_id`, `action`, `target`, `status` (`SUCCESS`, `FAILED`, `BLOCKED_BY_SAFETY`, `ROLLED_BACK`), `agent_id`, `tenant_id`, `message`, `execution_time_ms`, `timestamp`.

---

## 5. Verification Method

To independently verify the architecture and test suite:

### 5.1 Test Execution Command
Run the test suite using the project virtual environment:
```powershell
$env:PYTHONPATH="d:\ARKA\backend;d:\ARKA\agent"
& "d:\ARKA\backend\.venv\Scripts\python.exe" -m pytest backend/tests agent/tests -v
```

### 5.2 Linter & Quality Commands
Run ruff linting:
```powershell
& "d:\ARKA\backend\.venv\Scripts\ruff.exe" check agent backend
```

Run bandit security scan:
```powershell
& "d:\ARKA\backend\.venv\Scripts\bandit.exe" -r agent/arka_agent backend/app -ll
```

### 5.3 Test Suite Expansion Matrix
When implementing R1, R2, R3, R4, the following test coverage must be maintained:
1. `agent/tests/test_rootcheck_and_syscollector.py`:
   - Verify rootkit file detection via `tmp_path`.
   - Verify hidden process detection logic (mocking `psutil.pids()` vs `/proc`).
   - Verify suspicious port and promiscuous socket detection.
   - Verify system binary check logic.
2. `agent/tests/test_sca_benchmarks.py`:
   - Verify CIS policy loader and rule evaluators (file content, file permissions, registry, command output).
   - Verify Linux and Windows CIS check evaluations with mock filesystem/registry.
   - Verify compliance score math and summary metrics.
3. `agent/tests/test_syscollector.py` / `test_rootcheck_and_syscollector.py`:
   - Verify installed package harvesting across Linux (dpkg, rpm, apk) and Windows registry/python packages.
   - Verify network interfaces, open ports, and detailed process lineage structures.
   - Verify snapshot payload conforms to `InventorySnapshotPayload`.
4. `agent/tests/test_active_response.py`:
   - Verify safe process kill (graceful terminate -> force kill, system PID safety protection).
   - Verify IP block / unblock logic and IP allowlist guardrails.
   - Verify file quarantine and unquarantine rollback cycle using `tmp_path`.
   - Verify active response execution timeouts and audit trail logging.
