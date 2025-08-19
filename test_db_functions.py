#!/usr/bin/env python3
"""
Тестовый скрипт для проверки функций записи результатов и извлечения из базы данных
"""

import sqlite3
import tempfile
import os
import sys
from datetime import datetime

# Добавляем путь к проекту
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db.models import Vulnerability, ScanSession, Host, Subdomain, CVE, Exploits
from db.vulnerability_manager import VulnerabilityManager
from db.report import get_vulnerabilities_by_target, get_scan_sessions, list_targets
from scanner.ai_parser import AIVulnerabilityParser

def test_vulnerability_insertion():
    """Тестирует функции записи уязвимостей"""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ ФУНКЦИЙ ЗАПИСИ УЯЗВИМОСТЕЙ")
    print("=" * 60)
    
    # Создаем временную БД
    db_path = tempfile.mktemp(suffix='.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Создаем таблицы
        Vulnerability.create_table(cursor)
        ScanSession.create_table(cursor)
        Host.create_table(cursor)
        Subdomain.create_table(cursor)
        CVE.create_table(cursor)
        Exploits.create_table(cursor)
        conn.commit()
        
        print("✅ Таблицы созданы успешно")
        
        # Тест 1: Прямая вставка через модель
        print("\n1. Тест прямой вставки через модель Vulnerability:")
        try:
            Vulnerability.insert(
                cursor,
                resource="http://example.com",
                vulnerability_type="SQL Injection",
                description="SQL injection vulnerability found in login form",
                severity="High",
                scanner="nuclei"
            )
            conn.commit()
            print("✅ Уязвимость записана успешно")
            
            # Проверяем запись
            cursor.execute("SELECT * FROM vulnerability WHERE resource = ?", ("http://example.com",))
            result = cursor.fetchone()
            if result:
                print(f"✅ Запись найдена: {result}")
            else:
                print("❌ Запись не найдена")
                
        except Exception as e:
            print(f"❌ Ошибка при записи: {e}")
        
        # Тест 2: Вставка с валидацией
        print("\n2. Тест вставки с валидацией:")
        try:
            Vulnerability.insert_validated(
                cursor,
                resource="http://test.com/admin",
                vulnerability_type="XSS",
                description="Cross-site scripting vulnerability",
                severity="Medium",
                scanner="nuclei"
            )
            conn.commit()
            print("✅ Валидированная уязвимость записана успешно")
        except Exception as e:
            print(f"❌ Ошибка валидации: {e}")
        
        # Тест 3: Тест дубликатов
        print("\n3. Тест проверки дубликатов:")
        try:
            # Пытаемся вставить ту же уязвимость
            Vulnerability.insert_validated(
                cursor,
                resource="http://example.com",
                vulnerability_type="SQL Injection",
                description="SQL injection vulnerability found in login form",
                severity="High",
                scanner="nuclei"
            )
            print("❌ Дубликат должен был быть отклонен")
        except Exception as e:
            print(f"✅ Дубликат правильно отклонен: {e}")
        
        # Тест 4: VulnerabilityManager
        print("\n4. Тест VulnerabilityManager:")
        try:
            vuln_manager = VulnerabilityManager()
            
            # Тестовые данные от сканера
            test_data = [
                {
                    "resource": "http://demo.com",
                    "vulnerability_type": "LFI",
                    "description": "Local file inclusion vulnerability",
                    "severity": "Critical",
                    "scanner": "nuclei"
                },
                {
                    "resource": "http://demo.com/api",
                    "vulnerability_type": "SSRF",
                    "description": "Server-side request forgery",
                    "severity": "High",
                    "scanner": "nuclei"
                }
            ]
            
            stats = vuln_manager.process_and_save_vulnerabilities(
                raw_data=test_data,
                scanner_name='nuclei',
                cursor=cursor,
                session_id=1,
                target_resource="http://demo.com"
            )
            
            print(f"✅ VulnerabilityManager обработал {stats.processed} уязвимостей")
            print(f"   Сохранено: {stats.saved_new}")
            print(f"   Пропущено дубликатов: {stats.duplicates_skipped}")
            
        except Exception as e:
            print(f"❌ Ошибка VulnerabilityManager: {e}")
        
        conn.commit()
        
    finally:
        conn.close()
        os.unlink(db_path)
        print(f"\n🗑️ Временная БД удалена: {db_path}")

def test_data_extraction():
    """Тестирует функции извлечения данных"""
    print("\n" + "=" * 60)
    print("ТЕСТИРОВАНИЕ ФУНКЦИЙ ИЗВЛЕЧЕНИЯ ДАННЫХ")
    print("=" * 60)
    
    # Создаем временную БД с тестовыми данными
    db_path = tempfile.mktemp(suffix='.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Создаем таблицы
        Vulnerability.create_table(cursor)
        ScanSession.create_table(cursor)
        Host.create_table(cursor)
        Subdomain.create_table(cursor)
        CVE.create_table(cursor)
        Exploits.create_table(cursor)
        
        # Вставляем тестовые данные
        test_vulnerabilities = [
            ("http://example.com", "SQL Injection", "SQL injection in login", "High", "nuclei"),
            ("http://example.com/admin", "XSS", "Cross-site scripting", "Medium", "nuclei"),
            ("http://test.com", "LFI", "Local file inclusion", "Critical", "nuclei"),
            ("http://demo.com/api", "SSRF", "Server-side request forgery", "High", "nuclei"),
            ("http://demo.com", "Path Traversal", "Directory traversal", "Low", "nuclei")
        ]
        
        for vuln in test_vulnerabilities:
            Vulnerability.insert(cursor, 
                               resource=vuln[0],
                               vulnerability_type=vuln[1],
                               description=vuln[2],
                               severity=vuln[3],
                               scanner=vuln[4])
        
        # Тестовые сессии
        ScanSession.insert(cursor, target="http://example.com", status="completed")
        ScanSession.insert(cursor, target="http://test.com", status="completed")
        
        # Тестовые хосты
        Host.insert(cursor, hostname="example.com", ip_address="93.184.216.34", type="domain")
        Host.insert(cursor, hostname="test.com", ip_address="104.16.124.96", type="domain")
        
        # Тестовые субдомены
        Subdomain.insert(cursor, name="admin.example.com", parent_domain="example.com")
        Subdomain.insert(cursor, name="api.example.com", parent_domain="example.com")
        
        conn.commit()
        print("✅ Тестовые данные загружены")
        
        # Тест 1: Извлечение уязвимостей по цели
        print("\n1. Тест извлечения уязвимостей по цели:")
        try:
            vulns = get_vulnerabilities_by_target(cursor, "example.com")
            print(f"✅ Найдено {len(vulns)} уязвимостей для example.com")
            for i, vuln in enumerate(vulns, 1):
                print(f"   {i}. {vuln[1]} ({vuln[3]}) - {vuln[0]}")
        except Exception as e:
            print(f"❌ Ошибка извлечения уязвимостей: {e}")
        
        # Тест 2: Извлечение сессий сканирования
        print("\n2. Тест извлечения сессий сканирования:")
        try:
            sessions = get_scan_sessions(cursor)
            print(f"✅ Найдено {len(sessions)} сессий сканирования")
            for i, session in enumerate(sessions, 1):
                print(f"   {i}. {session[0]} - {session[3]}")
        except Exception as e:
            print(f"❌ Ошибка извлечения сессий: {e}")
        
        # Тест 3: Извлечение списка целей
        print("\n3. Тест извлечения списка целей:")
        try:
            targets = list_targets(cursor)
            print(f"✅ Найдено {len(targets)} целей")
            for target in targets:
                print(f"   • {target}")
        except Exception as e:
            print(f"❌ Ошибка извлечения целей: {e}")
        
        # Тест 4: Извлечение только субдоменов
        print("\n4. Тест извлечения только субдоменов:")
        try:
            subdomains = list_targets(cursor, only_subdomains=True)
            print(f"✅ Найдено {len(subdomains)} субдоменов")
            for subdomain in subdomains:
                print(f"   • {subdomain}")
        except Exception as e:
            print(f"❌ Ошибка извлечения субдоменов: {e}")
        
        # Тест 5: Статистика по критичности
        print("\n5. Тест статистики по критичности:")
        try:
            stats = Vulnerability.get_stats_by_severity(cursor)
            print("✅ Статистика по критичности:")
            for severity, count in stats:
                print(f"   • {severity}: {count}")
        except Exception as e:
            print(f"❌ Ошибка статистики: {e}")
        
        # Тест 6: VulnerabilityManager summary
        print("\n6. Тест VulnerabilityManager summary:")
        try:
            vuln_manager = VulnerabilityManager()
            summary = vuln_manager.get_vulnerability_summary(cursor)
            print(f"✅ Общая статистика:")
            print(f"   • Всего уязвимостей: {summary['total']}")
            print(f"   • Критических и высоких: {summary['critical_and_high']}")
            print(f"   • По критичности: {summary['by_severity']}")
        except Exception as e:
            print(f"❌ Ошибка summary: {e}")
        
        # Тест 7: Прямые запросы к моделям
        print("\n7. Тест прямых запросов к моделям:")
        try:
            # Получение всех уязвимостей
            all_vulns = Vulnerability.select_all(cursor)
            print(f"✅ Всего уязвимостей в БД: {len(all_vulns)}")
            
            # Получение по ID
            if all_vulns:
                first_vuln = Vulnerability.select_by_id(cursor, all_vulns[0][0])
                print(f"✅ Первая уязвимость по ID: {first_vuln[1]} ({first_vuln[3]})")
        except Exception as e:
            print(f"❌ Ошибка прямых запросов: {e}")
        
    finally:
        conn.close()
        os.unlink(db_path)
        print(f"\n🗑️ Временная БД удалена: {db_path}")

def test_error_handling():
    """Тестирует обработку ошибок"""
    print("\n" + "=" * 60)
    print("ТЕСТИРОВАНИЕ ОБРАБОТКИ ОШИБОК")
    print("=" * 60)
    
    db_path = tempfile.mktemp(suffix='.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Создаем таблицы
        Vulnerability.create_table(cursor)
        conn.commit()
        
        # Тест 1: Невалидные данные
        print("\n1. Тест невалидных данных:")
        try:
            Vulnerability.insert_validated(
                cursor,
                resource="",  # Пустой ресурс
                vulnerability_type="Test",
                severity="Invalid"  # Невалидная критичность
            )
            print("❌ Невалидные данные должны были быть отклонены")
        except Exception as e:
            print(f"✅ Невалидные данные правильно отклонены: {e}")
        
        # Тест 2: Слишком длинные поля
        print("\n2. Тест слишком длинных полей:")
        try:
            Vulnerability.insert_validated(
                cursor,
                resource="x" * 600,  # Слишком длинный ресурс
                vulnerability_type="Test",
                description="x" * 2500  # Слишком длинное описание
            )
            print("❌ Слишком длинные поля должны были быть отклонены")
        except Exception as e:
            print(f"✅ Слишком длинные поля правильно отклонены: {e}")
        
        # Тест 3: Отсутствующие обязательные поля
        print("\n3. Тест отсутствующих обязательных полей:")
        try:
            Vulnerability.insert_validated(
                cursor,
                # Отсутствует resource
                vulnerability_type="Test"
            )
            print("❌ Отсутствующие поля должны были быть отклонены")
        except Exception as e:
            print(f"✅ Отсутствующие поля правильно отклонены: {e}")
        
    finally:
        conn.close()
        os.unlink(db_path)
        print(f"\n🗑️ Временная БД удалена: {db_path}")

def main():
    """Основная функция тестирования"""
    print("🧪 ТЕСТИРОВАНИЕ ФУНКЦИЙ БАЗЫ ДАННЫХ")
    print("=" * 60)
    
    try:
        test_vulnerability_insertion()
        test_data_extraction()
        test_error_handling()
        
        print("\n" + "=" * 60)
        print("✅ ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ КРИТИЧЕСКАЯ ОШИБКА: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
