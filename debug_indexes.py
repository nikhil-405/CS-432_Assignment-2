#!/usr/bin/env python3
"""
Debug script to inspect index keys using module_B.
"""
import sys
import os

sys.path.append(os.getcwd())

try:
    from module_B.database import get_engine
    from sqlalchemy import text

    engine = get_engine()

    query = text("""
        SELECT INDEX_NAME, TABLE_NAME, COLUMN_NAME
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
        ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
    """)

    with engine.connect() as conn:
        result = conn.execute(query)
        rows = result.fetchall()

    indexes = {}
    for row in rows:
        index_name, table_name, column_name = row
        key = f"{table_name}.{index_name}"
        if key not in indexes:
            indexes[key] = {"table": table_name, "name": index_name, "columns": []}
        indexes[key]["columns"].append(column_name)

    print("Index Keys Found:")
    for key in sorted(indexes.keys()):
        if any(x in key.lower() for x in ['documents', 'permissions', 'logs', 'users']):
            print(f"  {key}: {indexes[key]['columns']}")

except ImportError as e:
    print(f"Error importing module_B: {e}")
except Exception as e:
    print(f"Error: {e}")
