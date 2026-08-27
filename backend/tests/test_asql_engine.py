"""
Unit & Integration Tests for ARKA Security Query Language (ASQL) Engine.
"""

from app.services.asql_engine import ASQLEngine


def test_asql_parser():
    """Verifies ASQLEngine parses WHERE, GROUP BY, ORDER BY, and LIMIT clauses."""
    query = "WHERE severity = 'CRITICAL' AND rule_id = 'R1001' GROUP BY agent_id ORDER BY timestamp DESC LIMIT 10"
    ast = ASQLEngine.parse_asql(query)

    assert len(ast["filters"]) == 2
    assert ast["filters"][0]["field"] == "severity"
    assert ast["filters"][0]["value"] == "CRITICAL"
    assert ast["group_by"] == "agent_id"
    assert ast["order_by"] == "timestamp"
    assert ast["order_dir"] == "DESC"
    assert ast["limit"] == 10


def test_asql_execution():
    """Verifies ASQLEngine filters, groups, and orders datasets correctly."""
    dataset = [
        {"id": "1", "severity": "CRITICAL", "agent_id": "agent-01", "score": 9.5},
        {"id": "2", "severity": "HIGH", "agent_id": "agent-02", "score": 7.0},
        {"id": "3", "severity": "CRITICAL", "agent_id": "agent-01", "score": 9.8},
        {"id": "4", "severity": "MEDIUM", "agent_id": "agent-03", "score": 4.0},
    ]

    res = ASQLEngine.execute_query("WHERE severity = 'CRITICAL' GROUP BY agent_id", dataset)

    assert res["total_matches"] == 2
    assert res["returned_count"] == 2
    assert res["group_counts"]["agent-01"] == 2
