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
    def update(cls, cursor, id_value, **kwargs):
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys()])
        values = tuple(kwargs.values()) + (id_value,)
        sql = f"UPDATE {cls.__name__.lower()} SET {set_clause} WHERE id = ?"
        cursor.execute(sql, values)

    @classmethod
    def select_all(cls, cursor):
        cursor.execute(f"SELECT * FROM {cls.__name__.lower()}")
        return cursor.fetchall()

    @classmethod
    def select_by_id(cls, cursor, id_value):
        cursor.execute(f"SELECT * FROM {cls.__name__.lower()} WHERE id = ?", (id_value,))
        return cursor.fetchone()

class Vulnerability(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    resource = "TEXT NOT NULL"  # URL, IP, FQDN
    vulnerability_type = "TEXT NOT NULL"  # CVE, LPE, SQLi, LFI, SSRF, Path Traversal, etc.
    description = "TEXT"
    severity = "TEXT"
    scanner = "TEXT"
    timestamp = "DATETIME DEFAULT CURRENT_TIMESTAMP"

class ScanSession(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    target = "TEXT NOT NULL"
    start_time = "DATETIME DEFAULT CURRENT_TIMESTAMP"
    end_time = "DATETIME"
    status = "TEXT DEFAULT 'running'"

class Host(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    hostname = "TEXT"
    ip_address = "TEXT"
    created_at = "DATETIME DEFAULT CURRENT_TIMESTAMP"

class Url(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    host_id = "INTEGER"
    url = "TEXT NOT NULL"
    created_at = "DATETIME DEFAULT CURRENT_TIMESTAMP"

class CVE(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    cve_id = "TEXT UNIQUE"
    description = "TEXT"
    severity = "TEXT"
    created_at = "DATETIME DEFAULT CURRENT_TIMESTAMP"

class ScanResult(BaseModel):
    id = "INTEGER PRIMARY KEY AUTOINCREMENT"
    url_id = "INTEGER"
    cve_id = "INTEGER"
    status = "TEXT DEFAULT 'Found'"
    scanner = "TEXT"
    created_at = "DATETIME DEFAULT CURRENT_TIMESTAMP"
