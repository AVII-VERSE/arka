# ARKA Detection & Correlation Engine Specification

## Overview

The ARKA Detection Engine provides real-time analysis of incoming normalized events against rule sets. Rules are defined deterministically in structured YAML files and mapped to MITRE ATT&CK tactics and techniques.

---

## Detection Mechanism

```
[Normalized Event Stream] ──> [Rule Evaluator] ──> [Redis Window Counter]
                                                         │
                                               Threshold Exceeded?
                                                         │
                                        ┌────────────────┴────────────────┐
                                        ▼                                 ▼
                                     [NO]                              [YES]
                               (Continue Stream)                 [Generate Alert]
                                                                          │
                                                                          ▼
                                                                [Incident Correlation]
```

---

## Rule Structure Definition (YAML)

```yaml
id: rule-brute-force-login
name: Multiple Failed Authentication Attempts (Brute Force)
description: Detects more than 5 failed logon attempts from the same source IP within 5 minutes.
severity: HIGH
enabled: true
tenant_id: default
mitre_attack:
  tactic: Credential Access
  technique_id: T1110
  technique_name: Brute Force
conditions:
  event_type: authentication
  action: logon_failed
threshold:
  count: 5
  time_window_seconds: 300
  group_by:
    - source_ip
    - user
```

---

## Initial Detection Rule Catalog

1. `rule-brute-force-login`: 5+ failed logons from the same IP within 300s (T1110).
2. `rule-suspicious-powershell`: PowerShell command containing `-EncodedCommand` or `DownloadString` (T1059.001).
3. `rule-privilege-escalation`: User added to Local Administrators or `sudoers` (T1078).
4. `rule-service-creation`: New system service installed (Windows ID 7045 or Linux systemd unit) (T1543).
5. `rule-account-lockout`: Multiple account lockout events triggered (T1110.001).
