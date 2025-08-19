#!/usr/bin/env python3
"""
Скрипт для проверки содержимого базы данных после сканирования
"""

import sqlite3
import os
import sys
from datetime import datetime

def check_database_contents(db_file="scan_results.db"):
    """Проверяет содержимое базы данных"""
    
    if not os.path.exists(db_file):
        print(f"❌ База данных {db_file} не найдена")
        return
    
    print(f"🔍 ПРОВЕРКА БАЗЫ ДАННЫХ: {db_file}")
    print("=" * 60)
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Получаем список всех таблиц
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print(f"📋 Найдено таблиц: {len(tables)}")
        for table in tables:
            print(f"   • {table[0]}")
        
        print("\n" + "=" * 60)
        
        # Проверяем каждую таблицу
        for table_name in [table[0] for table in tables]:
            print(f"\n📊 ТАБЛИЦА: {table_name}")
            print("-" * 40)
            
            try:
                # Подсчитываем количество записей
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = cursor.fetchone()[0]
                print(f"📈 Количество записей: {count}")
                
                if count > 0:
                    # Показываем структуру таблицы
                    cursor.execute(f"PRAGMA table_info({table_name})")
                    columns = cursor.fetchall()
                    print(f"📋 Структура таблицы:")
                    for col in columns:
                        print(f"   • {col[1]} ({col[2]})")
                    
                    # Показываем первые несколько записей
                    cursor.execute(f"SELECT * FROM {table_name} LIMIT 5")
                    rows = cursor.fetchall()
                    
                    if rows:
                        print(f"\n📝 Первые {len(rows)} записей:")
                        for i, row in enumerate(rows, 1):
                            print(f"   {i}. {row}")
                    
                    # Специальная обработка для таблицы vulnerability
                    if table_name == 'vulnerability':
                        print(f"\n🔍 ДЕТАЛЬНЫЙ АНАЛИЗ УЯЗВИМОСТЕЙ:")
                        
                        # Статистика по критичности
                        cursor.execute("""
                            SELECT severity, COUNT(*) as count 
                            FROM vulnerability 
                            GROUP BY severity 
                            ORDER BY CASE severity 
                                WHEN 'Critical' THEN 1 
                                WHEN 'High' THEN 2 
                                WHEN 'Medium' THEN 3 
                                WHEN 'Low' THEN 4 
                                ELSE 5 
                            END
                        """)
                        severity_stats = cursor.fetchall()
                        print(f"   📊 По критичности:")
                        for severity, count in severity_stats:
                            print(f"      • {severity}: {count}")
                        
                        # Статистика по типам уязвимостей
                        cursor.execute("""
                            SELECT vulnerability_type, COUNT(*) as count 
                            FROM vulnerability 
                            GROUP BY vulnerability_type 
                            ORDER BY count DESC
                        """)
                        type_stats = cursor.fetchall()
                        print(f"   📊 По типам:")
                        for vuln_type, count in type_stats:
                            print(f"      • {vuln_type}: {count}")
                        
                        # Статистика по сканерам
                        cursor.execute("""
                            SELECT scanner, COUNT(*) as count 
                            FROM vulnerability 
                            GROUP BY scanner 
                            ORDER BY count DESC
                        """)
                        scanner_stats = cursor.fetchall()
                        print(f"   📊 По сканерам:")
                        for scanner, count in scanner_stats:
                            print(f"      • {scanner}: {count}")
                    
                    # Специальная обработка для таблицы scansession
                    elif table_name == 'scansession':
                        print(f"\n🔍 ДЕТАЛЬНЫЙ АНАЛИЗ СЕССИЙ:")
                        cursor.execute("""
                            SELECT target, start_time, end_time, status 
                            FROM scansession 
                            ORDER BY start_time DESC
                        """)
                        sessions = cursor.fetchall()
                        for i, session in enumerate(sessions, 1):
                            target, start_time, end_time, status = session
                            print(f"   {i}. {target}")
                            print(f"      Статус: {status}")
                            print(f"      Начало: {start_time}")
                            if end_time:
                                print(f"      Конец: {end_time}")
                    
                    # Специальная обработка для таблицы host
                    elif table_name == 'host':
                        print(f"\n🔍 ДЕТАЛЬНЫЙ АНАЛИЗ ХОСТОВ:")
                        cursor.execute("""
                            SELECT hostname, ip_address, type, source 
                            FROM host 
                            ORDER BY hostname
                        """)
                        hosts = cursor.fetchall()
                        for i, host in enumerate(hosts, 1):
                            hostname, ip_address, host_type, source = host
                            print(f"   {i}. {hostname}")
                            if ip_address:
                                print(f"      IP: {ip_address}")
                            print(f"      Тип: {host_type}")
                            if source:
                                print(f"      Источник: {source}")
                    
                    # Специальная обработка для таблицы subdomain
                    elif table_name == 'subdomain':
                        print(f"\n🔍 ДЕТАЛЬНЫЙ АНАЛИЗ СУБДОМЕНОВ:")
                        cursor.execute("""
                            SELECT name, parent_domain, source 
                            FROM subdomain 
                            ORDER BY name
                        """)
                        subdomains = cursor.fetchall()
                        for i, subdomain in enumerate(subdomains, 1):
                            name, parent_domain, source = subdomain
                            print(f"   {i}. {name}")
                            if parent_domain:
                                print(f"      Родительский домен: {parent_domain}")
                            if source:
                                print(f"      Источник: {source}")
                
            except Exception as e:
                print(f"   ❌ Ошибка при анализе таблицы {table_name}: {e}")
        
        print("\n" + "=" * 60)
        print("✅ АНАЛИЗ ЗАВЕРШЕН")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Ошибка при работе с базой данных: {e}")

def check_specific_target(db_file="scan_results.db", target=None):
    """Проверяет данные для конкретной цели"""
    
    if not target:
        print("❌ Не указана цель для проверки")
        return
    
    print(f"\n🎯 ПРОВЕРКА ДАННЫХ ДЛЯ ЦЕЛИ: {target}")
    print("=" * 60)
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Уязвимости для цели
        cursor.execute("""
            SELECT vulnerability_type, severity, description, scanner, timestamp
            FROM vulnerability 
            WHERE resource LIKE ? 
            ORDER BY severity DESC, timestamp DESC
        """, (f'%{target}%',))
        
        vulns = cursor.fetchall()
        print(f"🔍 Найдено уязвимостей: {len(vulns)}")
        
        if vulns:
            for i, vuln in enumerate(vulns, 1):
                vuln_type, severity, description, scanner, timestamp = vuln
                print(f"\n   {i}. {vuln_type} ({severity})")
                print(f"      Сканер: {scanner}")
                print(f"      Описание: {description[:100]}...")
                print(f"      Время: {timestamp}")
        
        # Сессии сканирования для цели
        cursor.execute("""
            SELECT start_time, end_time, status
            FROM scansession 
            WHERE target LIKE ?
            ORDER BY start_time DESC
        """, (f'%{target}%',))
        
        sessions = cursor.fetchall()
        print(f"\n📊 Найдено сессий сканирования: {len(sessions)}")
        
        if sessions:
            for i, session in enumerate(sessions, 1):
                start_time, end_time, status = session
                print(f"   {i}. Статус: {status}")
                print(f"      Начало: {start_time}")
                if end_time:
                    print(f"      Конец: {end_time}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Ошибка при проверке цели: {e}")

def main():
    """Основная функция"""
    print("🧪 ПРОВЕРКА РЕЗУЛЬТАТОВ СКАНИРОВАНИЯ")
    print("=" * 60)
    
    # Проверяем основную базу данных
    check_database_contents("scan_results.db")
    
    # Если указана цель в аргументах командной строки
    if len(sys.argv) > 1:
        target = sys.argv[1]
        check_specific_target("scan_results.db", target)
    
    print("\n💡 Для проверки конкретной цели используйте:")
    print("   python check_scan_results.py example.com")

if __name__ == "__main__":
    main()
