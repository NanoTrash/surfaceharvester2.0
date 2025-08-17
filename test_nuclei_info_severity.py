#!/usr/bin/env python3
# test_nuclei_info_severity.py

import sqlite3
import tempfile
import os
from db.schema import setup_database
from db.vulnerability_manager import VulnerabilityManager

def test_nuclei_info_severity():
    """
    Тестирует корректность обработки severity 'info' от Nuclei
    """
    print("Тестирование обработки severity 'info' от Nuclei...")
    
    # Создаем временную БД
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_file:
        db_path = tmp_file.name
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Инициализируем БД
        setup_database(cursor)
        conn.commit()
        
        # Создаем менеджер
        vuln_manager = VulnerabilityManager()
        
        # Тестовые данные Nuclei с различными severity уровнями
        nuclei_test_data = [
            {
                'host': 'http://vulnweb.com',
                'info': {
                    'name': 'HTTP Security Headers Missing',
                    'severity': 'info',  # Маленькими буквами как от Nuclei
                    'description': 'Security headers are missing'
                }
            },
            {
                'host': 'http://vulnweb.com',
                'info': {
                    'name': 'SQL Injection Vulnerability',
                    'severity': 'high',  # Маленькими буквами
                    'description': 'SQL injection found'
                }
            },
            {
                'host': 'http://vulnweb.com', 
                'info': {
                    'name': 'Cross-Site Scripting',
                    'severity': 'medium',  # Маленькими буквами
                    'description': 'XSS vulnerability detected'
                }
            },
            {
                'host': 'http://vulnweb.com',
                'info': {
                    'name': 'Directory Listing',
                    'severity': 'low',  # Маленькими буквами
                    'description': 'Directory listing enabled'
                }
            },
            {
                'host': 'http://vulnweb.com',
                'info': {
                    'name': 'Critical Remote Code Execution',
                    'severity': 'critical',  # Маленькими буквами
                    'description': 'RCE vulnerability found'
                }
            }
        ]
        
        # Обрабатываем данные
        stats = vuln_manager.process_and_save_vulnerabilities(
            raw_data=nuclei_test_data,
            scanner_name='nuclei',
            cursor=cursor,
            target_resource='http://vulnweb.com'
        )
        
        conn.commit()
        
        print(f"\n✅ Результаты обработки:")
        print(f"   Обработано: {stats.processed}")
        print(f"   Сохранено: {stats.saved_new}")
        print(f"   Ошибок валидации: {stats.validation_errors}")
        print(f"   Ошибок обработки: {stats.processing_errors}")
        
        # Проверяем сохраненные данные
        cursor.execute("SELECT vulnerability_type, severity FROM vulnerability WHERE scanner = 'nuclei'")
        saved_vulns = cursor.fetchall()
        
        print(f"\n📊 Сохраненные уязвимости:")
        severity_counts = {}
        for vuln_type, severity in saved_vulns:
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            print(f"   • {vuln_type} - Severity: {severity}")
        
        print(f"\n📈 Статистика по severity:")
        for severity, count in severity_counts.items():
            print(f"   {severity}: {count}")
        
        # Проверяем, что все severity корректно нормализованы
        valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown']
        invalid_severities = [s for s in severity_counts.keys() if s not in valid_severities]
        
        if invalid_severities:
            print(f"❌ Найдены некорректные severity: {invalid_severities}")
            return False
        else:
            print("✅ Все severity корректно нормализованы!")
        
        # Проверяем, что info уязвимости сохранились
        if 'Info' not in severity_counts:
            print("❌ Info уязвимости не сохранились!")
            return False
        else:
            print(f"✅ Info уязвимостей сохранено: {severity_counts['Info']}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Ошибка в тесте: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        try:
            os.unlink(db_path)
        except:
            pass

if __name__ == "__main__":
    success = test_nuclei_info_severity()
    if success:
        print("\n🎉 ТЕСТ ПРОЙДЕН УСПЕШНО!")
        print("Система корректно обрабатывает все severity уровни от Nuclei")
    else:
        print("\n❌ ТЕСТ НЕ ПРОЙДЕН!")
