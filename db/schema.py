# db/schema.py

from db.models import MODEL_REGISTRY


def setup_database(cursor):
    """
    Создает все таблицы в базе данных и добавляет индексы
    """
    # Создаем таблицы
    for model in MODEL_REGISTRY.values():
        model.create_table(cursor)
    
    # Создаем индексы для оптимизации запросов
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
        
        # Индексы для таблицы url
        "CREATE INDEX IF NOT EXISTS idx_url_host_id ON url(host_id)",
        "CREATE INDEX IF NOT EXISTS idx_url_url ON url(url)",
        
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
