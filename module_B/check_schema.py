#!/usr/bin/env python3
"""
Schema inspection script using module_B.
"""
import sys
import os

# Ensure we can import module_B from parent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from module_B.database import get_engine
    from sqlalchemy import inspect

    engine = get_engine()
    inspector = inspect(engine)

    tables = ['documents', 'permissions', 'logs', 'users']
    for table in tables:
        print(f'\n{table.upper()}:')
        if not inspector.has_table(table):
            print(f"  (Table not found)")
            continue
            
        cols = inspector.get_columns(table)
        for col in cols:
            print(f'  {col["name"]}: {col["type"]}')

except ImportError as e:
    print(f"Error importing module_B: {e}")
except Exception as e:
    print(f"Error: {e}")
