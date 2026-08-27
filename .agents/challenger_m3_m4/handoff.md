# Empirical Challenge Report: Milestones M3 & M4 (SCA & Syscollector/Inventory)

## Verdict
**CHALLENGE_FOUND**

---

## 1. Observation

### Observation 1.1: `SCAScanner.eval_file_content` crashes on invalid regex patterns (`re.error`)
- **File**: `agent/arka_agent/collectors/sca.py`, lines 59–75
- **Code**:
  ```python
  try:
      with open(path, encoding="utf-8", errors="replace") as f:
          content = f.read()

      match = re.search(pattern, content, flags)
      if expected_match:
          if match:
              matched_snippet = match.group(0).strip()
              return "PASS", f"Pattern '{pattern}' matched in '{path}' ('{matched_snippet}')."
          return "FAIL", f"Pattern '{pattern}' was not found in '{path}'."
      ...
  except (PermissionError, OSError) as err:
      return "FAIL", f"Error accessing file '{path}': {err}"
  ```
- **Observed Behavior**: When an invalid regex is supplied (e.g. `pattern = r"[a-z("`), `re.search` raises `re.error: unterminated character set at position 0`. Because the exception handler catches only `(PermissionError, OSError)`, `re.error` escapes and crashes the scanner process. In contrast, `eval_command_output` (line 234) catches `except Exception as err:`.
- **Empirical Test Result**: Verified in `test_adversarial_sca.py::TestSCAScannerAdversarial::test_invalid_regex_unhandled_exception`.

---

### Observation 1.2: `SCAScanner.eval_registry_value` crashes on non-numeric registry values under comparison operators
- **File**: `agent/arka_agent/collectors/sca.py`, lines 184–191, 198–201
- **Code**:
  ```python
  elif operator == "gte":
      if int(val) >= int(expected_value):
          return "PASS", f"Registry '{key_path}\\{value_name}' value {val} >= {expected_value}."
      return "FAIL", f"Registry '{key_path}\\{value_name}' value {val} is less than required {expected_value}."
  elif operator == "lte":
      if int(val) <= int(expected_value):
          return "PASS", f"Registry '{key_path}\\{value_name}' value {val} <= {expected_value}."
      return "FAIL", f"Registry '{key_path}\\{value_name}' value {val} exceeds maximum permitted {expected_value}."
  ...
  except FileNotFoundError:
      return "FAIL", f"Registry key or value '{key_path}\\{value_name}' does not exist."
  except (PermissionError, OSError) as err:
      return "FAIL", f"Error accessing registry '{key_path}\\{value_name}': {err}"
  ```
- **Observed Behavior**: If a registry value is string or non-integer data (e.g. `"NotANumberString"`, `None`, `bytes`), `int(val)` raises `ValueError: invalid literal for int() with base 10` or `TypeError`. The exception handler catches only `FileNotFoundError` and `(PermissionError, OSError)`, allowing `ValueError`/`TypeError` to terminate execution.
- **Empirical Test Result**: Verified in `test_adversarial_sca.py::TestSCAScannerAdversarial::test_eval_registry_value_non_numeric_type_error`.

---

### Observation 1.3: `InventoryService.ingest_snapshot` crashes on unhandled `ValueError`/`TypeError` in hardware & process fields
- **File**: `backend/app/services/inventory_service.py`, lines 86–89 and 257–258
- **Code**:
  ```python
  # Hardware parsing (lines 86-89):
  logical_cores = int(hardware_dict.get("cpu_cores_logical", 1))
  physical_cores = int(hardware_dict.get("cpu_cores_physical", 1))
  cpu_arch = str(hardware_dict.get("cpu_architecture", "unknown"))
  ram_gb = float(hardware_dict.get("ram_total_gb", 0.0))

  # Process parsing (lines 257-258):
  proc_record = AgentInventoryProcess(
      ...
      cpu_percent=float(proc.get("cpu_percent", 0.0)),
      memory_percent=float(proc.get("memory_percent", 0.0)),
      updated_at=now,
  )
  ```
- **Observed Behavior**: While port numbers (`local_port`) and process PIDs (`proc_pid_int`) in the same method are guarded by `try...except (ValueError, TypeError)`, the hardware cores, RAM, and process CPU/memory conversions are unguarded. If an agent submits malformed metrics (e.g., `{"ram_total_gb": None}`, `{"ram_total_gb": "invalid"}`, or `{"cpu_percent": "N/A"}`), Python raises `TypeError` or `ValueError`, aborting the database transaction.
- **Empirical Test Result**: Verified in `test_adversarial_syscollector_inventory.py::TestInventoryServiceAdversarial::test_ingest_snapshot_unhandled_type_conversion_exceptions`.

---

### Observation 1.4: Verified Robust Components & Behaviors
- **Corrupted Config Files**: `SCAScanner.eval_file_content` successfully decodes files with invalid UTF-8 and null bytes without raising decoding errors (via `errors="replace"`).
- **Division by Zero on 0 Applicable Checks**: Both `SCAScanner.run_full_scan()` and `SCAEngine.persist_report()` safely return `100.0` compliance score without `ZeroDivisionError` when 0 checks pass and all are `NOT_APPLICABLE`.
- **Package Parsers Resilience**: `parse_dpkg_output`, `parse_dpkg_status_content`, `parse_rpm_output`, `parse_apk_output`, and `parse_winreg_entry` in `SyscollectorHarvester` gracefully handle malformed delimiters, empty lines, missing fields, SQL injection strings, and large payloads.
- **Harvester Fault Tolerance**: `SyscollectorHarvester` cleanly handles zero total memory, swap query errors, locked disk partitions (`PermissionError`), network sockets with `psutil.AccessDenied`, and processes that terminate mid-enumeration (`NoSuchProcess`, `ZombieProcess`, `AccessDenied`).
- **Atomic UPSERT & Replace Consistency**: Sequential and high-volume snapshot submissions cleanly replace old subresources (packages, network, ports, processes) without orphan ghost records.
- **Tenant Isolation**: Both `SCAEngine` and `InventoryService` strictly partition scan reports, policies, summaries, and agent inventory resources by `tenant_id`.

---

## 2. Logic Chain

1. **Step 1 (SCA Agent File Evaluation)**:
   - Rule engines evaluate user/policy-defined regexes across system files.
   - Observation 1.1 establishes that `re.search` is called inside a `try` block that only catches `(PermissionError, OSError)`.
   - An invalid regex generates `re.error` (which inherits from `Exception`, not `OSError`).
   - Therefore, any malformed regex in a custom policy or rule set will crash the agent's SCA scanning routine.

2. **Step 2 (SCA Registry Evaluation)**:
   - Windows Registry keys frequently hold diverse data types (strings, binary blobs, DWORDs).
   - Observation 1.2 establishes that `eval_registry_value` attempts direct `int(val)` casting for `gte`/`lte` comparisons without type guard or exception handling for `ValueError`/`TypeError`.
   - Therefore, encountering a string or binary value when expecting a numeric registry value causes an unhandled crash.

3. **Step 3 (Inventory Backend Payload Ingestion)**:
   - The backend accepts JSON snapshots from distributed agent endpoints.
   - Observation 1.3 shows that `int(...)` and `float(...)` are applied directly to `hardware_dict` and `proc` dictionaries.
   - Observation 1.3 also shows that `ports` and `pid` fields *did* receive `try...except (ValueError, TypeError)` guards, proving the inconsistency was an omission.
   - Therefore, any agent sending `None` or string metrics for RAM, CPU cores, or process CPU/memory percent crashes the ingestion service endpoint.

4. **Step 4 (Mitigation Feasibility)**:
   - For Observation 1.1: Wrap `re.search` with `except (re.error, Exception) as err:` returning `("FAIL", f"Regex evaluation error: {err}")`.
   - For Observation 1.2: Wrap `int(val)` with `try...except (ValueError, TypeError): return ("FAIL", f"Registry value '{val}' is not a valid integer for comparison.")`.
   - For Observation 1.3: Add safe helper conversion `safe_float(val, default=0.0)` and `safe_int(val, default=1)` in `InventoryService.ingest_snapshot`.

---

## 3. Caveats

- Tests were run on a local Windows development environment with SQLite in-memory async engine (`sqlite+aiosqlite:///:memory:`). PostgreSQL production-specific lock contention under multi-node horizontal scaling was not directly tested against a live RDS/PostgreSQL cluster.
- Linux-specific kernel checks (`/proc/sys/net/...`, `ufw`, `iptables`, `dpkg-query`) were evaluated via custom path fixtures, command mocking, and simulated file trees since execution ran on Windows.

---

## 4. Conclusion

While the core architectures of both Milestone 3 (SCA) and Milestone 4 (Syscollector & Inventory) demonstrate high baseline robustness, atomic upsert integrity, and strict multi-tenant isolation, 3 empirical input-handling and exception-safety bugs were discovered under hostile and corrupted conditions:

1. **Bug 1 (High)**: `SCAScanner.eval_file_content` crashes on invalid regex patterns (`re.error`).
2. **Bug 2 (Medium)**: `SCAScanner.eval_registry_value` crashes on non-numeric registry comparisons (`ValueError`/`TypeError`).
3. **Bug 3 (High)**: `InventoryService.ingest_snapshot` crashes on malformed/None numeric values in `hardware` and `running_processes` payloads (`ValueError`/`TypeError`).

**Final Verdict**: **`CHALLENGE_FOUND`**

---

## 5. Verification Method

To independently execute and verify the empirical challenge battery and reproductions:

```powershell
# In PowerShell:
$env:PYTHONPATH = "d:\ARKA\backend;d:\ARKA\agent"
d:\ARKA\backend\.venv\Scripts\python.exe -m pytest `
  d:\ARKA\.agents\challenger_m3_m4\test_adversarial_sca.py `
  d:\ARKA\.agents\challenger_m3_m4\test_adversarial_syscollector_inventory.py `
  d:\ARKA\.agents\challenger_m3_m4\test_concurrency_and_stress.py `
  -v -o asyncio_mode=auto
```

### Invalidation Conditions
- Bug 1 is invalidated if `eval_file_content` catches `re.error` / `Exception` and returns `("FAIL", ...)` without raising.
- Bug 2 is invalidated if `eval_registry_value` safely returns `("FAIL", ...)` when `val` cannot be converted to `int`.
- Bug 3 is invalidated if `ingest_snapshot` falls back to default float/int values when `hardware_dict` or `running_processes` contains strings or `None` without raising `ValueError`/`TypeError`.
