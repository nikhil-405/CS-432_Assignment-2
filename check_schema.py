#!/usr/bin/env python3
from module_B.database import get_engine
from sqlalchemy import inspect

engine = get_engine()
inspector = inspect(engine)

tables = ['documents', 'permissions', 'logs', 'users']
for table in tables:
    print(f'\n{table.upper()}:')
    cols = inspector.get_columns(table)
    for col in cols:
        print(f'  {col["name"]}: {col["type"]}')
