import json
import time
from datetime import datetime
from pathlib import Path

from sqlalchemy import text

from module_B.database import get_engine


REPORT_PATH = Path(__file__).resolve().parent / "reports" / "index_benchmark.json"


def _measure_query(connection, statement: str, params: dict, iterations: int = 30) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        connection.execute(text(statement), params).fetchall()
    elapsed = time.perf_counter() - start
    return (elapsed / iterations) * 1000.0


def _explain(connection, statement: str, params: dict) -> list[dict]:
    rows = connection.execute(text(f"EXPLAIN {statement}"), params).mappings().all()
    return [dict(row) for row in rows]


def run_benchmark(org_id: int = 1, iterations: int = 30) -> dict:
    query = """
    SELECT *
    FROM `Documents`
    WHERE `OrganizationID` = :org_id
    ORDER BY `LastModifiedAt` DESC
    LIMIT 100
    """

    with get_engine().connect() as connection:
        avg_ms = _measure_query(connection, query, {"org_id": org_id}, iterations)
        explain = _explain(connection, query, {"org_id": org_id})

    result = {
        "captured_at": datetime.utcnow().isoformat() + "Z",
        "org_id": org_id,
        "iterations": iterations,
        "average_ms": round(avg_ms, 4),
        "explain": explain,
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    benchmark_result = run_benchmark()
    print(json.dumps(benchmark_result, indent=2))
