"""
ARKA Security Query Language (ASQL) Parsing & Execution Engine.
Provides domain-specific threat hunting query processing over SIEM telemetry datasets.
"""

import re
from typing import Any


class ASQLEngine:
    """Parses and executes ARKA Security Query Language (ASQL) expressions."""

    @staticmethod
    def parse_asql(query_str: str) -> dict[str, Any]:
        """Parses an ASQL query string into structured query AST."""
        query = query_str.strip()

        limit = 50
        limit_match = re.search(r"LIMIT\s+(\d+)", query, re.IGNORECASE)
        if limit_match:
            limit = int(limit_match.group(1))

        order_by = "timestamp"
        order_dir = "DESC"
        order_match = re.search(r"ORDER\s+BY\s+(\w+)(?:\s+(ASC|DESC))?", query, re.IGNORECASE)
        if order_match:
            order_by = order_match.group(1)
            if order_match.group(2):
                order_dir = order_match.group(2).upper()

        group_by = None
        group_match = re.search(r"GROUP\s+BY\s+(\w+)", query, re.IGNORECASE)
        if group_match:
            group_by = group_match.group(1)

        filters = []
        where_match = re.search(
            r"WHERE\s+(.*?)(?=\s+GROUP|\s+ORDER|\s+LIMIT|$)", query, re.IGNORECASE
        )
        if where_match:
            where_clause = where_match.group(1)
            conditions = re.split(r"\s+AND\s+", where_clause, flags=re.IGNORECASE)
            for cond in conditions:
                m = re.match(r"(\w+)\s*(=|!=|>|<|LIKE)\s*['\"]?(.*?)['\"]?$", cond.strip())
                if m:
                    filters.append({"field": m.group(1), "op": m.group(2), "value": m.group(3)})

        return {
            "raw_query": query_str,
            "filters": filters,
            "group_by": group_by,
            "order_by": order_by,
            "order_dir": order_dir,
            "limit": limit,
        }

    @staticmethod
    def execute_query(query_str: str, dataset: list[dict[str, Any]]) -> dict[str, Any]:  # noqa: PLR0912
        """Executes an ASQL query string against a telemetry dataset."""
        ast = ASQLEngine.parse_asql(query_str)
        filtered = list(dataset)

        # Apply filters
        for f in ast["filters"]:
            field = f["field"]
            op = f["op"]
            val = f["value"].lower()

            res = []
            for item in filtered:
                item_val = str(item.get(field, "")).lower()
                if op == "=" and item_val == val:
                    res.append(item)
                elif op == "!=" and item_val != val:
                    res.append(item)
                elif op == "LIKE" and val in item_val:
                    res.append(item)
                elif op == ">":
                    try:
                        if float(item.get(field, 0)) > float(val):
                            res.append(item)
                    except ValueError:
                        pass
                elif op == "<":
                    try:
                        if float(item.get(field, 0)) < float(val):
                            res.append(item)
                    except ValueError:
                        pass
            filtered = res

        # Apply grouping if requested
        groups = {}
        if ast["group_by"]:
            grp_field = ast["group_by"]
            for item in filtered:
                key = str(item.get(grp_field, "unknown"))
                groups[key] = groups.get(key, 0) + 1

        # Apply ordering
        reverse = ast["order_dir"] == "DESC"
        order_key = ast["order_by"]
        filtered.sort(key=lambda x: str(x.get(order_key, "")), reverse=reverse)

        # Apply limit
        limited_results = filtered[: ast["limit"]]

        return {
            "query": query_str,
            "total_matches": len(filtered),
            "returned_count": len(limited_results),
            "group_counts": groups if ast["group_by"] else None,
            "results": limited_results,
        }
