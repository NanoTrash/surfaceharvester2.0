# db/schema.py

from db.models import MODEL_REGISTRY


def setup_database(cursor):
    """
    Создает все таблицы в базе данных и добавляет индексы
    """
    # Создаем таблицы
    for model in MODEL_REGISTRY.values():
        model.create_table(cursor)
    
    # Сначала миграции для существующих таблиц
    migrate_schema(cursor)
    # Затем создаем индексы для оптимизации запросов
    create_indexes(cursor)
    
    print("[INFO] База данных инициализирована")


def create_indexes(cursor):
    """
    Создает индексы для оптимизации производительности
    """
    indexes = [
        # Индексы для таблицы vulnerability
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_resource ON vulnerability(resource)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_type ON vulnerability(vulnerability_type)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_severity ON vulnerability(severity)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_scanner ON vulnerability(scanner)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_timestamp ON vulnerability(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_resource_type ON vulnerability(resource, vulnerability_type)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_severity_timestamp ON vulnerability(severity, timestamp)",
        
        # Композитный индекс для поиска дубликатов
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_dedup ON vulnerability(resource, vulnerability_type, substr(description, 1, 100))",
        
        # Индексы для таблицы scansession
        "CREATE INDEX IF NOT EXISTS idx_scansession_target ON scansession(target)",
        "CREATE INDEX IF NOT EXISTS idx_scansession_status ON scansession(status)",
        "CREATE INDEX IF NOT EXISTS idx_scansession_start_time ON scansession(start_time)",
        
        # Индексы для таблицы host
        "CREATE INDEX IF NOT EXISTS idx_host_hostname ON host(hostname)",
        "CREATE INDEX IF NOT EXISTS idx_host_ip ON host(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_host_session_id ON host(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_host_parent_domain ON host(parent_domain)",
        "CREATE INDEX IF NOT EXISTS idx_host_type ON host(type)",
        
        # Индексы для таблицы url
        "CREATE INDEX IF NOT EXISTS idx_url_host_id ON url(host_id)",
        "CREATE INDEX IF NOT EXISTS idx_url_url ON url(url)",

        # Индексы для таблицы subdomain
        "CREATE INDEX IF NOT EXISTS idx_subdomain_name ON subdomain(name)",
        "CREATE INDEX IF NOT EXISTS idx_subdomain_parent ON subdomain(parent_domain)",
        "CREATE INDEX IF NOT EXISTS idx_subdomain_host_id ON subdomain(host_id)",
        "CREATE INDEX IF NOT EXISTS idx_subdomain_last_seen ON subdomain(session_last_seen)",
        
        # Индексы для таблицы cve
        "CREATE INDEX IF NOT EXISTS idx_cve_id ON cve(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve(severity)",
        
        # Индексы для таблицы scanresult
        "CREATE INDEX IF NOT EXISTS idx_scanresult_url_id ON scanresult(url_id)",
        "CREATE INDEX IF NOT EXISTS idx_scanresult_cve_id ON scanresult(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_scanresult_scanner ON scanresult(scanner)",
    ]
    
    for index_sql in indexes:
        try:
            cursor.execute(index_sql)
        except Exception as e:
            print(f"[WARNING] Не удалось создать индекс: {e}")
    
    print("[INFO] Индексы созданы")


def _table_columns(cursor, table_name: str):
    try:
        cursor.execute(f"PRAGMA table_info({table_name})")
        return {row[1] for row in cursor.fetchall()}
    except Exception:
        return set()


def migrate_schema(cursor):
    """
    Добавляет недостающие колонки в существующие таблицы
    """
    try:
        # host: session_id, target, type, source, parent_domain, last_scanned_session_id
        host_cols = _table_columns(cursor, 'host')
        planned_cols = {
            'session_id': "INTEGER",
            'target': "TEXT",
            'type': "TEXT DEFAULT 'domain'",
            'source': "TEXT",
            'parent_domain': "TEXT",
            'last_scanned_session_id': "INTEGER",
        }
        for col, ddl in planned_cols.items():
            if col not in host_cols and host_cols:
                try:
                    cursor.execute(f"ALTER TABLE host ADD COLUMN {col} {ddl}")
                except Exception as e:
                    print(f"[WARNING] Не удалось добавить колонку host.{col}: {e}")

        # scanresult: scanner
        sr_cols = _table_columns(cursor, 'scanresult')
        if 'scanner' not in sr_cols and sr_cols:
            try:
                cursor.execute("ALTER TABLE scanresult ADD COLUMN scanner TEXT")
            except Exception as e:
                print(f"[WARNING] Не удалось добавить колонку scanresult.scanner: {e}")

        # vulnerability: scanner (на случай очень старой схемы)
        vuln_cols = _table_columns(cursor, 'vulnerability')
        if 'scanner' not in vuln_cols and vuln_cols:
            try:
                cursor.execute("ALTER TABLE vulnerability ADD COLUMN scanner TEXT")
            except Exception as e:
                print(f"[WARNING] Не удалось добавить колонку vulnerability.scanner: {e}")
        # subdomain: если таблицы нет — создать
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='subdomain'")
        if cursor.fetchone() is None:
            try:
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS subdomain ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "name TEXT NOT NULL,"
                    "parent_domain TEXT,"
                    "host_id INTEGER,"
                    "session_first_seen INTEGER,"
                    "session_last_seen INTEGER,"
                    "target TEXT,"
                    "source TEXT,"
                    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
                )
            except Exception as e:
                print(f"[WARNING] Не удалось создать таблицу subdomain: {e}")
    except Exception as e:
        print(f"[WARNING] Миграция схемы завершилась с предупреждениями: {e}")

def insert_initial_data(cursor):
    """
    Вставляет тестовые данные (опционально)
    """
    from db.models import Vulnerability, ScanSession
    
    # Примеры уязвимостей для тестирования
    test_vulnerabilities = [
        {
            'resource': 'https://example.com',
            'vulnerability_type': 'SQL Injection',
            'description': 'SQL injection vulnerability in login form',
            'severity': 'High',
            'scanner': 'nuclei'
        },
        {
            'resource': 'https://example.com/admin',
            'vulnerability_type': 'XSS',
            'description': 'Reflected XSS in search parameter',
            'severity': 'Medium',
            'scanner': 'nikto'
        },
        {
            'resource': 'https://example.com/files',
            'vulnerability_type': 'Path Traversal',
            'description': 'Directory traversal vulnerability',
            'severity': 'Critical',
            'scanner': 'nuclei'
        }
    ]
    
    for vuln in test_vulnerabilities:
        Vulnerability.insert(cursor, **vuln)
    
    print("[INFO] Тестовые данные добавлены")
