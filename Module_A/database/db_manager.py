from .table import Table

class DatabaseManager:
    def __init__(self):
        self.databases = {}

    def create_database(self, db_name):
        if db_name in self.databases:
            return False
        self.databases[db_name] = {}
        return True

    def delete_database(self, db_name):
        if db_name not in self.databases:
            return False
        del self.databases[db_name]
        return True

    def list_databases(self):
        return sorted(self.databases.keys())

    def create_table(self, db_name, table_name, schema, order=8, search_key=None):
        if db_name not in self.databases:
            raise KeyError(f"database '{db_name}' does not exist")

        if table_name in self.databases[db_name]:
            return False

        self.databases[db_name][table_name] = Table(
            name=table_name,
            schema=schema,
            order=order,
            search_key=search_key,
        )
        return True

    def delete_table(self, db_name, table_name):
        if db_name not in self.databases:
            raise KeyError(f"database '{db_name}' does not exist")

        if table_name not in self.databases[db_name]:
            return False

        del self.databases[db_name][table_name]
        return True

    def list_tables(self, db_name):
        if db_name not in self.databases:
            raise KeyError(f"database '{db_name}' does not exist")
        return sorted(self.databases[db_name].keys())

    def get_table(self, db_name, table_name):
        if db_name not in self.databases:
            raise KeyError(f"database '{db_name}' does not exist")
        return self.databases[db_name].get(table_name)

