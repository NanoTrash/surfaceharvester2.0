# db/models.py

MODEL_REGISTRY = {}

class ModelMeta(type):
    def __new__(cls, name, bases, dct):
        if name != 'BaseModel':
            MODEL_REGISTRY[name.lower()] = type.__new__(cls, name, bases, dct)
        return type.__new__(cls, name, bases, dct)

class BaseModel(metaclass=ModelMeta):
    @classmethod
    def create_table(cls, cursor):
        columns = [f"{k} {v}" for k, v in cls.__dict__.items() if not k.startswith("_") and not callable(v)]
        sql = f"CREATE TABLE IF NOT EXISTS {cls.__name__.lower()} ({', '.join(columns)});"
        cursor.execute(sql)

    @classmethod
    def insert(cls, cursor, **kwargs):
        keys = ', '.join(kwargs.keys())
        placeholders = ', '.join(['?'] * len(kwargs))
        values = tuple(kwargs.values())
        sql = f"INSERT INTO {cls.__name__.lower()} ({keys}) VALUES ({placeholders})"
        cursor.execute(sql, values)

    @classmethod
    def select_all(cls, cursor):
        cursor.execute(f"SELECT * FROM {cls.__name__.lower()}")
        return cursor.fetchall()

class Host(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    hostname = "TEXT NOT NULL"
    ip_address = "TEXT"

class Url(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    host_id = "INTEGER"
    url = "TEXT NOT NULL"

class Endpoint(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    url_id = "INTEGER"
    path = "TEXT NOT NULL"
    method = "TEXT"

class CVE(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    cve_id = "TEXT NOT NULL"
    description = "TEXT"
    severity = "TEXT"

class ScanResult(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    url_id = "INTEGER"
    cve_id = "INTEGER"
    status = "TEXT"

class Software(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    host_id = "INTEGER"
    name = "TEXT NOT NULL"

class VersionSoft(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    software_id = "INTEGER"
    version = "TEXT NOT NULL"
    is_latest = "BOOLEAN"
