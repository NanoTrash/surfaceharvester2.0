#!/usr/bin/env python3
# test_ai_parser.py

import sqlite3
from scanner.ai_parser import AIVulnerabilityParser
from db.schema import setup_database

def test_ai_parser():
    """
    Тестирует ИИ-парсер на примерах
    """
    print("Тестирование ИИ-парсера...")
    
    # Создаем тестовую БД
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    setup_database(cursor)
    
    # Инициализируем парсер
    parser = AIVulnerabilityParser()
    
    # Тестовые данные
    test_cases = [
        {
            'scanner': 'nuclei',
            'data': [
                {
                    'host': 'https://example.com',
                    'info': {
                        'name': 'SQL Injection vulnerability detected',
                        'severity': 'High',
                        'cve': ['CVE-2024-1234']
                    }
                },
                {
                    'host': 'https://example.com/admin',
                    'info': {
                        'name': 'Cross-site scripting found in search parameter',
                        'severity': 'Medium'
                    }
                }
            ]
        },
        {
            'scanner': 'nikto',
            'data': {
                'vulnerabilities': [
                    {
                        'description': 'Path traversal vulnerability in file parameter',
                        'severity': 'Critical',
                        'osvdb_id': '12345'
                    },
                    {
                        'description': 'Default credentials admin:admin',
                        'severity': 'High'
                    }
                ]
            }
        }
    ]
    
    # Тестируем парсинг
    for test_case in test_cases:
        print(f"\nТестируем {test_case['scanner']}...")
        
        vulnerabilities = parser.parse_scanner_output(
            test_case['data'], 
            test_case['scanner']
        )
        
        print(f"Найдено {len(vulnerabilities)} уязвимостей:")
        for vuln in vulnerabilities:
            print(f"  - {vuln['vulnerability_type']} ({vuln['severity']})")
            print(f"    Ресурс: {vuln['resource']}")
            print(f"    Описание: {vuln['description']}")
        
        # Сохраняем в БД
        parser.save_to_database(vulnerabilities, cursor)
    
    # Проверяем сохранение в БД
    cursor.execute("SELECT COUNT(*) FROM vulnerability")
    count = cursor.fetchone()[0]
    print(f"\nВсего сохранено в БД: {count} уязвимостей")
    
    # Показываем содержимое БД
    cursor.execute("SELECT resource, vulnerability_type, severity FROM vulnerability")
    rows = cursor.fetchall()
    
    print("\nСодержимое БД:")
    for row in rows:
        print(f"  {row[0]} - {row[1]} ({row[2]})")
    
    conn.close()
    print("\nТест завершен!")

if __name__ == "__main__":
    test_ai_parser()
