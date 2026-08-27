## 2026-08-27T04:25:30Z

You are teamwork_preview_challenger #2 for Milestones M3 and M4.

Your Working Directory: d:/ARKA/.agents/challenger_m3_m4
Original Request Path: d:/ARKA/.agents/ORIGINAL_REQUEST.md
Project Scope Document: d:/ARKA/PROJECT.md

Mission:
Adversarially challenge and stress-test:
1. `SCAScanner` (`agent/arka_agent/collectors/sca.py`) and `SCAEngine` (`backend/app/services/sca_engine.py`): Test with corrupted config files, invalid regex, edge-case permission bits, division by zero when all checks not applicable, empty policy lists, and tenant isolation bypass attempts.
2. `SyscollectorHarvester` (`agent/arka_agent/collectors/syscollector.py`) and `InventoryService` (`backend/app/services/inventory_service.py`): Test package parser resilience on malformed outputs, zero memory division handling, inaccessible disks/processes, port enumeration with `AccessDenied`, atomic UPSERT/replace consistency during rapid snapshot submissions, and non-existent agent queries.
3. Write empirical test scripts in your working directory, execute them, and report findings in `d:/ARKA/.agents/challenger_m3_m4/handoff.md`.
4. Send a message with your verdict (APPROVE or CHALLENGE_FOUND).
