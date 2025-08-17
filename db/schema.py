# db/schema.py

from db.models import MODEL_REGISTRY


def setup_database(cursor):
    """
    Создает все таблицы в базе данных
    """
    for model in MODEL_REGISTRY.values():
        model.create_table(cursor)
    
    print("[INFO] База данных инициализирована")


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
