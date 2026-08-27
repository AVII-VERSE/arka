"""
Empirical Adversarial Test Suite for SCA (Milestone 3).
Validates SCAScanner (agent) and SCAEngine (backend) behaviors under hostile, corrupted, and boundary conditions.
"""

import os
import platform
import re
import stat
import tempfile
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.models import SCAPolicy, SCAScanReport, Tenant
from app.schemas.schemas import SCAPolicyCreate
from app.services.sca_engine import SCAEngine
from arka_agent.collectors.sca import SCAScanner

# =============================================================================
# Agent-Side Tests: SCAScanner
# =============================================================================


class TestSCAScannerAdversarial:
    """Stress tests and boundary condition evaluations for SCAScanner."""

    def test_corrupted_config_files(self, tmp_path):
        """Test eval_file_content with invalid UTF-8, null bytes, binary data, and empty files."""
        scanner = SCAScanner(agent_id="test-agent", tenant_id="test-tenant")

        # 1. File with null bytes and binary garbage
        bin_file = tmp_path / "corrupted_bin.conf"
        bin_file.write_bytes(b"\x00\xff\xfe\x00\x01\x02\x03PermitRootLogin no\x00\x00\xff")
        status, rationale = scanner.eval_file_content(str(bin_file), r"PermitRootLogin\s+no")
        assert status == "PASS"

        # 2. File with invalid UTF-8 sequences
        bad_utf8_file = tmp_path / "bad_utf8.conf"
        bad_utf8_file.write_bytes(b"PermitRootLogin \x80\x81\x82 no\n")
        status, rationale = scanner.eval_file_content(str(bad_utf8_file), r"PermitRootLogin\s+no")
        assert status == "FAIL"

        # 3. Completely empty file
        empty_file = tmp_path / "empty.conf"
        empty_file.write_text("")
        status, rationale = scanner.eval_file_content(str(empty_file), r"PermitRootLogin\s+no")
        assert status == "FAIL"
        assert "not found in" in rationale

        # 4. Non-existent file
        status, rationale = scanner.eval_file_content(str(tmp_path / "does_not_exist.conf"), r"some_pattern")
        assert status == "FAIL"
        assert "not found" in rationale

    def test_invalid_regex_unhandled_exception(self, tmp_path):
        """
        EMPIRICAL BUG VERIFICATION: eval_file_content fails to catch re.error.
        When an invalid regex pattern is supplied, re.search raises re.error which is
        NOT caught by `except (PermissionError, OSError)`.
        """
        scanner = SCAScanner()
        sample_file = tmp_path / "sample.conf"
        sample_file.write_text("PermitRootLogin no\n")

        invalid_pattern = r"[a-z("  # Unterminated character set
        with pytest.raises(re.error) as exc_info:
            scanner.eval_file_content(str(sample_file), invalid_pattern)
        assert "unterminated character set" in str(exc_info.value)

    def test_invalid_regex_in_command_output_caught(self):
        """
        eval_command_output DOES catch general Exception (including re.error)
        and returns FAIL gracefully.
        """
        import sys

        scanner = SCAScanner()
        status, rationale = scanner.eval_command_output([sys.executable, "-c", "print('hello')"], r"[a-z(")
        assert status == "FAIL"
        assert "Execution error" in rationale

    def test_edge_case_file_permissions(self, tmp_path):
        """Test eval_file_permissions with boundary permission masks."""
        scanner = SCAScanner()
        test_file = tmp_path / "perm_test.txt"
        test_file.write_text("secure content")

        # 1. max_mode = 0o000 (no permissions allowed)
        status, rationale = scanner.eval_file_permissions(str(test_file), max_mode=0o000)
        assert status == "FAIL"

        # 2. max_mode = 0o777 (all permissions allowed)
        status, rationale = scanner.eval_file_permissions(str(test_file), max_mode=0o777)
        assert status == "PASS"

        # 3. Non-existent file
        status, rationale = scanner.eval_file_permissions(str(tmp_path / "no_file"), max_mode=0o644)
        assert status == "FAIL"
        assert "not found" in rationale

    def test_all_checks_not_applicable_division_by_zero(self):
        """
        Verify that when ALL checks return NOT_APPLICABLE,
        compliance_score evaluates to 100.0 without ZeroDivisionError.
        """
        scanner = SCAScanner()

        mock_na_result = {
            "id": "MOCK-NA",
            "check_id": "MOCK-NA",
            "title": "Mock N/A Check",
            "status": "NOT_APPLICABLE",
            "result": "NOT_APPLICABLE",
            "description": "Mock N/A",
            "rationale": "Not applicable on this platform",
            "remediation": "N/A",
            "compliance": [],
            "extra": {},
        }

        with patch.object(scanner, "check_windows_firewall", return_value=mock_na_result), \
             patch.object(scanner, "check_windows_uac", return_value=mock_na_result), \
             patch.object(scanner, "check_windows_smbv1", return_value=mock_na_result), \
             patch.object(scanner, "check_windows_account_lockout", return_value=mock_na_result), \
             patch.object(scanner, "check_windows_password_min_len", return_value=mock_na_result), \
             patch.object(scanner, "check_windows_guest_account", return_value=mock_na_result), \
             patch.object(scanner, "check_linux_passwd_permissions", return_value=mock_na_result), \
             patch.object(scanner, "check_linux_shadow_permissions", return_value=mock_na_result), \
             patch.object(scanner, "check_linux_sudoers_permissions", return_value=mock_na_result), \
             patch.object(scanner, "check_ssh_root_login", return_value=mock_na_result), \
             patch.object(scanner, "check_ssh_protocol_and_auth", return_value=mock_na_result), \
             patch.object(scanner, "check_linux_ip_forwarding", return_value=mock_na_result), \
             patch.object(scanner, "check_linux_icmp_redirects", return_value=mock_na_result), \
             patch.object(scanner, "check_linux_host_firewall", return_value=mock_na_result), \
             patch.object(scanner, "check_linux_password_expiration", return_value=mock_na_result), \
             patch.object(scanner, "check_linux_password_min_len", return_value=mock_na_result):

            report = scanner.run_full_scan(profile="all")
            assert report["total_checks"] > 0
            assert report["passed_checks"] == 0
            assert report["failed_checks"] == 0
            assert report["not_applicable_checks"] == report["total_checks"]
            assert report["compliance_score"] == 100.0

            events = scanner.collect()
            assert len(events) == 1
            assert events[0]["metadata"]["compliance_score"] == 100.0

    def test_eval_registry_value_non_numeric_type_error(self):
        """
        EMPIRICAL BUG VERIFICATION: eval_registry_value fails to handle ValueError/TypeError
        when comparing non-numeric registry values with 'gte' or 'lte' operators.
        """
        scanner = SCAScanner()
        if platform.system().lower() != "windows":
            res, rationale = scanner.eval_registry_value("HKLM\\SOFTWARE\\Test", "Val", 1, "gte")
            assert res == "NOT_APPLICABLE"
            return

        with patch("winreg.OpenKey"), patch("winreg.QueryValueEx", return_value=("NotANumberString", 1)):
            with pytest.raises(ValueError) as exc_info:
                scanner.eval_registry_value(
                    r"HKLM\SOFTWARE\Microsoft\Windows", "SomeVal", expected_value=5, operator="gte"
                )
            assert "invalid literal for int()" in str(exc_info.value)


# =============================================================================
# Backend-Side Tests: SCAEngine
# =============================================================================

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def async_db():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
class TestSCAEngineAdversarial:
    """Stress tests and boundary condition evaluations for SCAEngine."""

    async def test_persist_report_zero_division_and_empty_payload(self, async_db: AsyncSession):
        """Persist scan report with 0 passed, 0 failed, 0 applicable, and empty payload."""
        empty_payload = {
            "tenant_id": "tenant-empty",
            "agent_id": "agent-empty",
            "policy_id": "cis-empty",
            "policy_name": "Empty Policy",
            "checks": [],
            "summary": {},
        }

        report = await SCAEngine.persist_report(async_db, empty_payload)
        assert report.id is not None
        assert report.compliance_score == 100.0
        assert report.total_checks == 0
        assert report.passed_checks == 0
        assert report.failed_checks == 0
        assert report.not_applicable_checks == 0

    async def test_persist_report_all_not_applicable_checks(self, async_db: AsyncSession):
        """Persist scan report with 10 checks that are all NOT_APPLICABLE."""
        checks = [
            {
                "id": f"CIS-NA-{i}",
                "status": "NOT_APPLICABLE",
                "result": "NOT_APPLICABLE",
                "title": f"NA Check {i}",
            }
            for i in range(10)
        ]
        payload = {
            "tenant_id": "tenant-na",
            "agent_id": "agent-na",
            "checks": checks,
        }

        report = await SCAEngine.persist_report(async_db, payload)
        assert report.compliance_score == 100.0
        assert report.passed_checks == 0
        assert report.failed_checks == 0
        assert report.not_applicable_checks == 10

    async def test_tenant_summary_empty_database(self, async_db: AsyncSession):
        """Query tenant summary when no reports exist."""
        summary = await SCAEngine.get_tenant_summary(async_db, tenant_id="nonexistent-tenant")
        assert summary["total_scans"] == 0
        assert summary["average_compliance_score"] == 0.0
        assert summary["passed_checks_total"] == 0
        assert summary["failed_checks_total"] == 0
        assert summary["not_applicable_checks_total"] == 0
        assert summary["latest_reports"] == []

    async def test_strict_tenant_isolation(self, async_db: AsyncSession):
        """
        Adversarial test: Verify Tenant A cannot access Tenant B's SCA reports,
        summaries, or custom policies under any condition.
        """
        report_a = await SCAEngine.persist_report(
            async_db,
            {
                "tenant_id": "tenant-A",
                "agent_id": "agent-A-1",
                "policy_id": "cis-v2",
                "passed_checks": 8,
                "failed_checks": 2,
                "compliance_score": 80.0,
            },
        )
        report_b = await SCAEngine.persist_report(
            async_db,
            {
                "tenant_id": "tenant-B",
                "agent_id": "agent-B-1",
                "policy_id": "cis-v2",
                "passed_checks": 10,
                "failed_checks": 0,
                "compliance_score": 100.0,
            },
        )

        policy_a = await SCAEngine.create_policy(
            async_db,
            tenant_id="tenant-A",
            policy_in=SCAPolicyCreate(
                policy_code="POL-A",
                name="Tenant A Policy",
                description="Policy for Tenant A",
                os_type="linux",
            ),
        )
        policy_b = await SCAEngine.create_policy(
            async_db,
            tenant_id="tenant-B",
            policy_in=SCAPolicyCreate(
                policy_code="POL-B",
                name="Tenant B Policy",
                description="Policy for Tenant B",
                os_type="windows",
            ),
        )

        # Query Tenant A reports
        reports_a = await SCAEngine.get_tenant_reports(async_db, tenant_id="tenant-A")
        assert len(reports_a) == 1
        assert reports_a[0].tenant_id == "tenant-A"
        assert reports_a[0].agent_id == "agent-A-1"

        # Attempt cross-tenant agent report query
        reports_cross = await SCAEngine.get_agent_reports(
            async_db, tenant_id="tenant-A", agent_id="agent-B-1"
        )
        assert len(reports_cross) == 0

        # Query summaries
        summary_a = await SCAEngine.get_tenant_summary(async_db, tenant_id="tenant-A")
        assert summary_a["total_scans"] == 1
        assert summary_a["average_compliance_score"] == 80.0

        summary_b = await SCAEngine.get_tenant_summary(async_db, tenant_id="tenant-B")
        assert summary_b["total_scans"] == 1
        assert summary_b["average_compliance_score"] == 100.0

        # Query policies
        policies_a = await SCAEngine.get_policies(async_db, tenant_id="tenant-A")
        assert len(policies_a) == 1
        assert policies_a[0].policy_code == "POL-A"

        pol_cross = await SCAEngine.get_policy_by_code(
            async_db, tenant_id="tenant-A", policy_code="POL-B"
        )
        assert pol_cross is None
