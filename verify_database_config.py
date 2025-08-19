#!/usr/bin/env python3
"""
Скрипт для проверки конфигурации базы данных во всем проекте
"""

import os
import re
import sqlite3
from pathlib import Path

def check_file_for_db_references(file_path, expected_db="scan_results.db"):
    """
    Проверяет файл на наличие ссылок на базы данных
    """
    issues = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Ищем ссылки на базы данных
        db_patterns = [
            r'test_scan\.db',
            r'test_db.*\.db'
        ]
        
        for pattern in db_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                issues.append(f"  ❌ Строка {line_num}: найдено '{match.group()}'")
        
        # Проверяем правильные ссылки
        correct_refs = content.count(expected_db)
        if correct_refs > 0:
            issues.append(f"  ✅ Найдено {correct_refs} правильных ссылок на '{expected_db}'")
            
    except Exception as e:
        issues.append(f"  ❌ Ошибка чтения файла: {e}")
    
    return issues

def check_database_file():
    """
    Проверяет основную базу данных
    """
    print("🔍 ПРОВЕРКА ОСНОВНОЙ БАЗЫ ДАННЫХ")
    print("=" * 60)
    
    db_file = "scan_results.db"
    
    if not os.path.exists(db_file):
        print(f"❌ Основная база данных {db_file} не найдена")
        return False
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Проверяем таблицы
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print(f"✅ База данных найдена: {db_file}")
        print(f"📋 Таблиц: {len(tables)}")
        
        # Проверяем основные таблицы
        main_tables = ['vulnerability', 'scansession', 'host', 'subdomain']
        for table in main_tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                print(f"   📊 {table}: {count} записей")
            except Exception as e:
                print(f"   ❌ Ошибка проверки таблицы {table}: {e}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Ошибка проверки базы данных: {e}")
        return False

def check_project_files():
    """
    Проверяет все файлы проекта на правильность конфигурации БД
    """
    print("\n🔍 ПРОВЕРКА ФАЙЛОВ ПРОЕКТА")
    print("=" * 60)
    
    # Файлы для проверки
    files_to_check = [
        "config.py",
        "cli.py", 
        "main.py",
        "db/schema.py",
        "db/models.py",
        "scanner/full_scanner.py",
        "scanner/cve_monitor.py",
        "scanner/vulnx_processor.py",
        "reports_manager.py",
        "reports.py"
    ]
    
    issues_found = False
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            print(f"\n📄 Проверка {file_path}:")
            issues = check_file_for_db_references(file_path)
            
            if issues:
                for issue in issues:
                    print(issue)
                issues_found = True
            else:
                print("  ✅ Проблем не найдено")
        else:
            print(f"\n📄 {file_path}: ❌ Файл не найден")
    
    return not issues_found

def check_test_files():
    """
    Проверяет тестовые файлы
    """
    print("\n🧪 ПРОВЕРКА ТЕСТОВЫХ ФАЙЛОВ")
    print("=" * 60)
    
    test_files = [
        "simple_db_test.py",
        "debug_scan_results.py", 
        "check_scan_results.py",
        "merge_databases.py"
    ]
    
    issues_found = False
    
    for file_path in test_files:
        if os.path.exists(file_path):
            print(f"\n📄 Проверка {file_path}:")
            issues = check_file_for_db_references(file_path)
            
            if issues:
                for issue in issues:
                    print(issue)
                issues_found = True
            else:
                print("  ✅ Проблем не найдено")
        else:
            print(f"\n📄 {file_path}: ❌ Файл не найден")
    
    return not issues_found

def check_documentation():
    """
    Проверяет документацию
    """
    print("\n📚 ПРОВЕРКА ДОКУМЕНТАЦИИ")
    print("=" * 60)
    
    doc_files = [
        "README.md",
        "REPORTS_README.md",
        "QUICK_START_REPORTS.md",
        "db_functions_report.md"
    ]
    
    issues_found = False
    
    for file_path in doc_files:
        if os.path.exists(file_path):
            print(f"\n📄 Проверка {file_path}:")
            issues = check_file_for_db_references(file_path)
            
            if issues:
                for issue in issues:
                    print(issue)
                issues_found = True
            else:
                print("  ✅ Проблем не найдено")
        else:
            print(f"\n📄 {file_path}: ❌ Файл не найден")
    
    return not issues_found

def main():
    """
    Основная функция проверки
    """
    print("🔍 ПРОВЕРКА КОНФИГУРАЦИИ БАЗЫ ДАННЫХ")
    print("=" * 60)
    
    # Проверяем основную базу данных
    db_ok = check_database_file()
    
    # Проверяем файлы проекта
    project_ok = check_project_files()
    
    # Проверяем тестовые файлы
    tests_ok = check_test_files()
    
    # Проверяем документацию
    docs_ok = check_documentation()
    
    # Итоговый результат
    print("\n" + "=" * 60)
    print("📊 ИТОГОВЫЙ РЕЗУЛЬТАТ")
    print("=" * 60)
    
    if db_ok and project_ok and tests_ok and docs_ok:
        print("✅ ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ УСПЕШНО!")
        print("🎉 Проект полностью настроен на использование scan_results.db")
    else:
        print("❌ НАЙДЕНЫ ПРОБЛЕМЫ:")
        if not db_ok:
            print("   • Проблемы с основной базой данных")
        if not project_ok:
            print("   • Проблемы в файлах проекта")
        if not tests_ok:
            print("   • Проблемы в тестовых файлах")
        if not docs_ok:
            print("   • Проблемы в документации")
    
    print(f"\n💡 РЕКОМЕНДАЦИИ:")
    print("1. Убедитесь, что все компоненты используют scan_results.db")
    print("2. Проверьте, что все компоненты используют scan_results.db")
    print("3. Запустите тесты для проверки функциональности")

if __name__ == "__main__":
    main()
