import json
import time
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text
from module_B.database import get_engine
from module_B.query_analysis import INDEX_MAPPING


REPORT_PATH = Path(__file__).resolve().parent / "reports" / "benchmark_results.json"

# Default test parameters
PARAMS = {
    "OrganizationID": 1,
    "OwnerUserID": 1,
    "UserID": 1,
    "DocID": 1,
    "AccessType": "View",
    "ActionType": "VIEW",
    "RoleID": 1,
    "AccountStatus": "Active"
}


def _measure_query(connection, statement: str, params: dict, iterations: int = 30) -> float:
    # Warmup
    try:
        connection.execute(text(statement), params).fetchall()
    except Exception:
        pass  # Ignore warmup errors

    start = time.perf_counter()
    for _ in range(iterations):
        connection.execute(text(statement), params).fetchall()
    elapsed = time.perf_counter() - start
    return (elapsed / iterations) * 1000.0


def _explain(connection, statement: str, params: dict) -> list[dict]:
    try:
        rows = connection.execute(text(f"EXPLAIN {statement}"), params).mappings().all()
        return [dict(row) for row in rows]
    except Exception as e:
        return [{"error": str(e)}]


def resolve_params(query: str) -> tuple[str, dict]:
    """Resolve parameters for a query string."""
    
    # Handle multi-param queries specifically to ensure correct binding
    # Check most specific/longest patterns first to avoid partial matches
    
    if "Permissions WHERE UserID = ? AND DocID = ? AND AccessType IN (?)" in query:
        p = {"p1": PARAMS["UserID"], "p2": PARAMS["DocID"], "p3": PARAMS["AccessType"]}
        query = query.replace("UserID = ?", "UserID = :p1").replace("DocID = ?", "DocID = :p2").replace("AccessType IN (?)", "AccessType IN (:p3)")
        return query, p
    
    if "Users WHERE OrganizationID = ? AND RoleID = ? AND AccountStatus = ?" in query:
        p = {"p1": PARAMS["OrganizationID"], "p2": PARAMS["RoleID"], "p3": PARAMS["AccountStatus"]}
        query = query.replace("OrganizationID = ?", "OrganizationID = :p1").replace("RoleID = ?", "RoleID = :p2").replace("AccountStatus = ?", "AccountStatus = :p3")
        return query, p

    if "Permissions WHERE UserID = ? AND DocID = ?" in query:
        p = {"p1": PARAMS["UserID"], "p2": PARAMS["DocID"]}
        query = query.replace("UserID = ?", "UserID = :p1").replace("DocID = ?", "DocID = :p2")
        return query, p

    if "Permissions WHERE DocID = ? AND AccessType = ?" in query:
        p = {"p1": PARAMS["DocID"], "p2": PARAMS["AccessType"]}
        query = query.replace("DocID = ?", "DocID = :p1").replace("AccessType = ?", "AccessType = :p2")
        return query, p

    if "Logs WHERE DocID = ? AND ActionType = ?" in query:
        p = {"p1": PARAMS["DocID"], "p2": PARAMS["ActionType"]}
        query = query.replace("DocID = ?", "DocID = :p1").replace("ActionType = ?", "ActionType = :p2")
        return query, p

    if "Logs WHERE UserID = ?" in query:
        p = {"p1": PARAMS["UserID"]}
        query = query.replace("UserID = ?", "UserID = :p1")
        return query, p
    
    # Simple mapping based on placeholders found
    # These must come AFTER specific multi-param queries that might contain these substrings
    p = {}
    if "OrganizationID = ?" in query: 
        p["p1"] = PARAMS["OrganizationID"]
        query = query.replace("OrganizationID = ?", "OrganizationID = :p1")
        return query, p
        
    if "OwnerUserID = ?" in query:
        p["p1"] = PARAMS["OwnerUserID"]
        query = query.replace("OwnerUserID = ?", "OwnerUserID = :p1")
        return query, p
        
    return query, p


def run_benchmark(iterations: int = 50, engine=None) -> dict:
    if engine is None:
        engine = get_engine()
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "iterations": iterations,
        "benchmarks": []
    }
    
    print(f"\nRunning benchmarks ({iterations} iterations per query)...")
    print("-" * 100)
    print(f"{'Index Name':<35} | {'Avg (ms)':<10} | {'Rows':<8} | {'Key Used'}")
    print("-" * 100)

    with engine.connect() as conn:
        for index_name, details in INDEX_MAPPING.items():
            for query_template in details["queries"]:
                stmt, params = resolve_params(query_template)
                
                try:
                    avg_ms = _measure_query(conn, stmt, params, iterations)
                    explain_data = _explain(conn, stmt, params)
                    
                    rows_examined = "N/A"
                    key_used = "N/A"
                    
                    if explain_data and isinstance(explain_data[0], dict):
                        rows_examined = explain_data[0].get('rows', 'N/A')
                        key_used = explain_data[0].get('key', 'NULL')
                        if key_used is None: 
                            key_used = "NULL"

                    results["benchmarks"].append({
                        "index": index_name,
                        "query": query_template,
                        "avg_ms": round(avg_ms, 4),
                        "explain_rows": rows_examined,
                        "explain_key": key_used
                    })
                    
                    print(f"{index_name:<35} | {avg_ms:10.4f} | {str(rows_examined):<8} | {key_used}")
                    
                except Exception as e:
                    print(f"{index_name:<35} | ERROR      | -        | {str(e)}")
                    print(f"FAILED QUERY: {stmt}")
                    print(f"PARAMS: {params}")

    print("-" * 100)
    
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nResults saved to: {REPORT_PATH}")
    return results


if __name__ == "__main__":
    run_benchmark()
