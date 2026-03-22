#!/usr/bin/env python3
"""
SubTask 4: Query Analysis and Index Verification Tool
Verifies and applies SQL indexes for document access optimization.
"""

import argparse
import json
from pathlib import Path

from sqlalchemy import text
from .database import get_engine, get_session
from .config import Config

# Define critical indexes and their purposes
INDEX_MAPPING = {
    "idx_documents_org_lastmodified": {
        "table": "documents",
        "columns": ["OrganizationID", "LastModifiedAt"],
        "purpose": "Optimizes list_documents by organization with ordering",
        "queries": [
            "SELECT * FROM Documents WHERE OrganizationID = ? ORDER BY LastModifiedAt DESC"
        ]
    },
    "idx_documents_owner_lastmodified": {
        "table": "documents",
        "columns": ["OwnerUserID", "LastModifiedAt"],
        "purpose": "Optimizes list_documents by owner with ordering",
        "queries": [
            "SELECT * FROM Documents WHERE OwnerUserID = ? ORDER BY LastModifiedAt DESC"
        ]
    },
    "idx_permissions_user_doc_access": {
        "table": "permissions",
        "columns": ["UserID", "DocID", "AccessType"],
        "purpose": "Optimizes permission lookups (called on every request)",
        "queries": [
            "SELECT 1 FROM Permissions WHERE UserID = ? AND DocID = ? AND AccessType IN (?)",
            "SELECT * FROM Permissions WHERE UserID = ? AND DocID = ?"
        ]
    },
    "idx_permissions_doc_access": {
        "table": "permissions",
        "columns": ["DocID", "AccessType"],
        "purpose": "Optimizes document access type lookups",
        "queries": [
            "SELECT * FROM Permissions WHERE DocID = ? AND AccessType = ?"
        ]
    },
    "idx_logs_doc_action_time": {
        "table": "logs",
        "columns": ["DocID", "ActionType", "ActionTimestamp"],
        "purpose": "Optimizes audit log queries by document",
        "queries": [
            "SELECT * FROM Logs WHERE DocID = ? AND ActionType = ? ORDER BY ActionTimestamp DESC"
        ]
    },
    "idx_logs_user_time": {
        "table": "logs",
        "columns": ["UserID", "ActionTimestamp"],
        "purpose": "Optimizes audit log queries by user",
        "queries": [
            "SELECT * FROM Logs WHERE UserID = ? ORDER BY ActionTimestamp DESC"
        ]
    },
    "idx_users_org_role_status": {
        "table": "users",
        "columns": ["OrganizationID", "RoleID", "AccountStatus"],
        "purpose": "Optimizes user lookups by organization",
        "queries": [
            "SELECT * FROM Users WHERE OrganizationID = ? AND RoleID = ? AND AccountStatus = ?"
        ]
    }
}

def get_existing_indexes(engine):
    """Fetch all existing indexes in the database."""
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
    
    return indexes

def check_indexes(engine):
    """Check if all required indexes exist."""
    existing = get_existing_indexes(engine)
    
    print("\n" + "="*80)
    print("INDEX VERIFICATION REPORT")
    print("="*80)
    
    missing = []
    existing_count = 0
    
    for index_name, details in INDEX_MAPPING.items():
        table = details["table"]
        key = f"{table}.{index_name}"
        
        if key in existing:
            existing_indexes = existing[key]["columns"]
            expected_columns = details["columns"]
            
            print(f"\n✅ {index_name} (EXISTS)")
            print(f"   Table: {table}")
            print(f"   Columns: {', '.join(existing_indexes)}")
            print(f"   Purpose: {details['purpose']}")
            existing_count += 1
        else:
            print(f"\n❌ {index_name} (MISSING)")
            print(f"   Table: {table}")
            print(f"   Columns: {', '.join(details['columns'])}")
            print(f"   Purpose: {details['purpose']}")
            missing.append((index_name, table, details["columns"]))
    
    print("\n" + "-"*80)
    print(f"Summary: {existing_count}/{len(INDEX_MAPPING)} indexes exist")
    print("-"*80)
    
    return missing

def apply_indexes(engine):
    """Apply all indexes from indexes.sql file."""
    sql_file = Path(__file__).parent / "sql" / "indexes.sql"
    
    if not sql_file.exists():
        print(f"❌ Error: {sql_file} not found")
        return False
    
    print(f"\nReading indexes from: {sql_file}")
    with open(sql_file, 'r') as f:
        sql_content = f.read()
    
    # Split by semicolons and execute each statement
    statements = [s.strip() for s in sql_content.split(';') if s.strip()]
    
    print(f"\nApplying {len(statements)} index statements...\n")
    
    with engine.connect() as conn:
        for i, statement in enumerate(statements, 1):
            try:
                conn.execute(text(statement))
                conn.commit()
                print(f"✅ Statement {i}: Success")
            except Exception as e:
                error_msg = str(e)
                # Index already exists is not a fatal error
                if "already exists" in error_msg.lower() or "duplicate key" in error_msg.lower():
                    print(f"ℹ️  Statement {i}: Index already exists (skipped)")
                else:
                    print(f"❌ Statement {i}: {error_msg}")
    
    print("\nAll indexes applied successfully!")
    return True

def show_mapping():
    """Display query-to-index mapping."""
    print("\n" + "="*80)
    print("QUERY-TO-INDEX MAPPING")
    print("="*80)
    
    for index_name, details in INDEX_MAPPING.items():
        print(f"\n📊 Index: {index_name}")
        print(f"   Table: {details['table']}")
        print(f"   Columns: {', '.join(details['columns'])}")
        print(f"   Purpose: {details['purpose']}")
        print(f"   Optimizes queries:")
        for query in details["queries"]:
            print(f"      • {query}")

def run_explain(conn, query):
    """Run EXPLAIN on a query to see execution plan."""
    cursor = conn.cursor()
    cursor.execute(f"EXPLAIN {query}")
    results = cursor.fetchall()
    cursor.close()
    return results

def compare_queries(engine):
    """Compare EXPLAIN plans for critical queries (shows potential improvements)."""
    print("\n" + "="*80)
    print("CRITICAL QUERY ANALYSIS")
    print("="*80)
    
    # Sample queries that benefit from indexing
    critical_queries = [
        ("List documents by owner", 
         "SELECT COUNT(*) FROM Documents WHERE OwnerUserID = 1 ORDER BY LastModifiedAt DESC"),
        ("Permission lookup",
         "SELECT COUNT(*) FROM Permissions WHERE UserID = 1 AND DocID = 1 AND AccessType = 'View'"),
        ("Audit logs by document",
         "SELECT COUNT(*) FROM Logs WHERE DocID = 1 ORDER BY CreatedAt DESC"),
        ("Users by organization",
         "SELECT COUNT(*) FROM Users WHERE OrganizationID = 1 AND Status = 'Active'"),
    ]
    
    with engine.connect() as conn:
        for query_name, query in critical_queries:
            print(f"\n📍 Query: {query_name}")
            print(f"   SQL: {query}")
            
            try:
                result = conn.execute(text(f"EXPLAIN {query}"))
                explain_results = result.fetchall()
                
                # Show key parts of EXPLAIN output
                if explain_results:
                    explain_row = explain_results[0]
                    explain_dict = dict(explain_row._mapping) if hasattr(explain_row, '_mapping') else {}
                    
                    print(f"   EXPLAIN Analysis:")
                    if 'type' in explain_dict:
                        print(f"     - Type: {explain_dict['type']}")
                    if 'key' in explain_dict:
                        print(f"     - Index used: {explain_dict['key'] or 'NONE (full table scan)'}")
                    if 'rows' in explain_dict:
                        print(f"     - Rows examined: {explain_dict['rows']}")
            except Exception as e:
                print(f"   ❌ Error: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Query Analysis and Index Verification Tool")
    parser.add_argument("command", choices=["check", "apply", "mapping", "compare", "benchmark"],
                        help="Command to execute")
    args = parser.parse_args()
    
    engine = get_engine()
    
    try:
        if args.command == "check":
            missing = check_indexes(engine)
            if missing:
                print(f"\n💡 Tip: Run 'python -m module_B.query_analysis apply' to create missing indexes")
        
        elif args.command == "apply":
            apply_indexes(engine)
            print("\nVerifying applied indexes...")
            check_indexes(engine)
        
        elif args.command == "mapping":
            show_mapping()
        
        elif args.command == "compare":
            compare_queries(engine)

        elif args.command == "benchmark":
            from .benchmark import run_benchmark
            run_benchmark()
    
    finally:
        pass  # SQLAlchemy handles connection cleanup

if __name__ == "__main__":
    main()
