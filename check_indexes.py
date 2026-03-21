#!/usr/bin/env python3
from module_B.database import get_engine
from sqlalchemy import text

engine = get_engine()

with engine.connect() as conn:
    # Get all indexes in the database
    query = text("""
        SELECT INDEX_NAME, TABLE_NAME, COLUMN_NAME, SEQ_IN_INDEX
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME IN ('documents', 'permissions', 'logs', 'users')
        ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
    """)
    
    result = conn.execute(query)
    rows = result.fetchall()
    
    print("Existing Indexes in Database:")
    for row in rows:
        print(f"  {row[0]} ({row[1]}): {row[2]} (pos {row[3]})")
