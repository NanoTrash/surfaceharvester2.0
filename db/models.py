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
        columns = []
        for k, v in cls.__dict__.items():
            if not k.startswith("_") and not callable(v) and isinstance(v, str) and any(sql_type in v.upper() for sql_type in ['TEXT', 'INTEGER', 'DATETIME', 'REAL', 'BLOB']):
                columns.append(f"{k} {v}")
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
    severity = "TEXT DEFAULT 'Medium'"
    scanner = "TEXT NOT NULL"
    timestamp = "DATETIME DEFAULT CURRENT_TIMESTAMP"
    
    # Валидные значения
    VALID_SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown']
    REQUIRED_FIELDS = ['resource', 'vulnerability_type', 'scanner']
    
    @classmethod
    def validate_data(cls, **kwargs):
        """
        Валидирует данные перед вставкой
        """
        errors = []
        
        # Проверка обязательных полей
        for field in cls.REQUIRED_FIELDS:
            if not kwargs.get(field):
                errors.append(f"Обязательное поле '{field}' отсутствует или пустое")
        
        # Проверка severity
        severity = kwargs.get('severity', 'Medium')
        if severity not in cls.VALID_SEVERITIES:
            errors.append(f"Неизвестный уровень критичности: {severity}. Допустимые: {cls.VALID_SEVERITIES}")
        
        # Проверка длины полей
        max_lengths = {
            'resource': 500,
            'vulnerability_type': 200,
            'description': 2000,
            'severity': 20,
            'scanner': 50
        }
        
        for field, max_length in max_lengths.items():
            value = str(kwargs.get(field, ''))
            if len(value) > max_length:
                errors.append(f"Поле '{field}' превышает максимальную длину {max_length}")
        
        return errors
    
    @classmethod
    def insert_validated(cls, cursor, **kwargs):
        """
        Вставка с валидацией
        """
        errors = cls.validate_data(**kwargs)
        if errors:
            raise ValueError(f"Ошибки валидации: {'; '.join(errors)}")
        
        # Устанавливаем значения по умолчанию
        kwargs.setdefault('severity', 'Medium')
        kwargs.setdefault('description', '')
        
        return cls.insert(cursor, **kwargs)
    
    @classmethod
    def find_duplicates(cls, cursor, resource, vulnerability_type, description_prefix=None):
        """
        Поиск потенциальных дубликатов
        """
        base_query = "SELECT * FROM vulnerability WHERE resource = ? AND vulnerability_type = ?"
        params = [resource, vulnerability_type]
        
        if description_prefix:
            base_query += " AND description LIKE ?"
            params.append(f"{description_prefix}%")
        
        cursor.execute(base_query, params)
        return cursor.fetchall()
    
    @classmethod
    def get_stats_by_severity(cls, cursor, target=None):
        """
        Получает статистику по уровням критичности
        """
        base_query = """
            SELECT severity, COUNT(*) as count 
            FROM vulnerability 
        """
        params = []
        
        if target:
            base_query += " WHERE resource LIKE ?"
            params.append(f"%{target}%")
        
        base_query += """
            GROUP BY severity 
            ORDER BY CASE severity 
                WHEN 'Critical' THEN 1 
                WHEN 'High' THEN 2 
                WHEN 'Medium' THEN 3 
                WHEN 'Low' THEN 4 
                WHEN 'Info' THEN 5 
                ELSE 6 
            END
        """
        
        cursor.execute(base_query, params)
        return cursor.fetchall()

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
