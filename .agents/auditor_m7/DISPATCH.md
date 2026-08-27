## 2026-08-27T07:50:25Z

You are teamwork_preview_auditor #4 for Milestone M7 (Final Forensic Integrity Audit).

Your Working Directory: d:/ARKA/.agents/auditor_m7
Original Request Path: d:/ARKA/.agents/ORIGINAL_REQUEST.md
Project Scope Document: d:/ARKA/PROJECT.md
Test Ready Document: d:/ARKA/TEST_READY.md

Mission:
Perform a comprehensive whole-repository Forensic Integrity Audit across backend/app/ and agent/arka_agent/:
1. Audit all 60 cybersecurity modules for zero fake data, zero dummy/facade implementations, and zero hardcoded test returns.
2. Verify that all 12 database models for R2-R5 persist real data, all endpoints return real data, and querying against an empty database returns empty responses.
3. Verify that all collectors (Rootcheck, SCA, Syscollector, Active Response, Vulnerability) perform authentic OS inspections.
4. Verify that all test assertions in backend/tests/ and agent/tests/ are genuine and non-tautological.
5. Provide a binary verdict: CLEAN or INTEGRITY VIOLATION in d:/ARKA/.agents/auditor_m7/handoff.md and send a message when done.
