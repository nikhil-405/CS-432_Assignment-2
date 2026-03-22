from .bplustree import BPlusTree

class Table:
    def __init__(self, name, schema, order=8, search_key=None):
        self.name = name
        self.schema = schema
        self.order = order

        if not isinstance(schema, dict) or not schema:
            raise ValueError("schema must be a non-empty dictionary")

        if search_key is None:
            search_key = next(iter(schema.keys()))

        if search_key not in schema:
            raise ValueError("search_key must be present in schema")

        self.search_key = search_key
        self.data = BPlusTree(t=max(2, int(order)))

    def validate_record(self, record):
        if not isinstance(record, dict):
            raise TypeError("record must be a dictionary")

        missing = [column for column in self.schema if column not in record]
        if missing:
            raise ValueError(f"missing required columns: {missing}")

        extra = [column for column in record if column not in self.schema]
        if extra:
            raise ValueError(f"unknown columns in record: {extra}")

        for column, expected_type in self.schema.items():
            value = record[column]
            if value is not None and not isinstance(value, expected_type):
                raise TypeError(
                    f"column '{column}' expects {expected_type.__name__}, got {type(value).__name__}"
                )

        return True

    def insert(self, record):
        self.validate_record(record)
        key = record[self.search_key]

        if self.data.search(key) is not None:
            raise ValueError(f"record with key '{key}' already exists")

        self.data.insert(key, record.copy())
        return key

    def get(self, record_id):
        return self.data.search(record_id)

    def get_all(self):
        return [record for _, record in self.data.get_all()]

    def update(self, record_id, new_record):
        existing = self.get(record_id)
        if existing is None:
            return False

        if not isinstance(new_record, dict):
            raise TypeError("new_record must be a dictionary")

        updated = existing.copy()
        updated.update(new_record)
        self.validate_record(updated)

        new_key = updated[self.search_key]
        if new_key != record_id:
            if self.data.search(new_key) is not None:
                raise ValueError(f"record with key '{new_key}' already exists")
            self.data.delete(record_id)
            self.data.insert(new_key, updated)
            return True

        return self.data.update(record_id, updated)

    def delete(self, record_id):
        return self.data.delete(record_id)

    def range_query(self, start_value, end_value):
        return [record for _, record in self.data.range_query(start_value, end_value)]