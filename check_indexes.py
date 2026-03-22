#!/usr/bin/env python3
"""
Wrapper script to run index verification from module_B.
"""
import sys
import os

# Ensure we can import module_B
sys.path.append(os.getcwd())

try:
    from module_B.database import get_engine
    from module_B.query_analysis import check_indexes
    
    if __name__ == "__main__":
        print("Running Index Check from module_B...")
        engine = get_engine()
        check_indexes(engine)

except ImportError as e:
    print(f"Error importing module_B: {e}")
    print("Please run this script from the project root.")
except Exception as e:
    print(f"Error: {e}")
