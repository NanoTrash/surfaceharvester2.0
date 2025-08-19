#!/usr/bin/env python3
"""
Скрипт для отладки проблем с записью результатов сканирования
"""

import sqlite3
import os
import sys
from datetime import datetime

def debug_scan_session(db_file="scan_results.db", session_id=1):
    """Отлаживает конкретную сессию сканирования"""
    
    print(f"🔍 ОТЛАДКА СЕССИИ СКАНИРОВАНИЯ ID: {session_id}")
    print("=" * 60)
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Получаем информацию о сессии
        cursor.execute("""
            SELECT target, start_time, end_time, status 
            FROM scansession 
            WHERE id = ?
        """, (session_id,))
        
        session = cursor.fetchone()
        if not session:
            print(f"❌ Сессия {session_id} не найдена")
            return
        
        target, start_time, end_time, status = session
        print(f"🎯 Цель: {target}")
        print(f"📅 Начало: {start_time}")
        print(f"📅 Конец: {end_time}")
        print(f"📊 Статус: {status}")
        
        # Проверяем связанные записи
        print(f"\n🔗 СВЯЗАННЫЕ ЗАПИСИ:")
        
        # Хосты для этой сессии
        cursor.execute("""
            SELECT hostname, ip_address, type, source 
            FROM host 
            WHERE session_id = ?
        """, (session_id,))
        
        hosts = cursor.fetchall()
        print(f"📋 Хосты ({len(hosts)}):")
        for host in hosts:
            print(f"   • {host[0]} ({host[2]}) - {host[3]}")
        
        # Уязвимости для этой цели
        cursor.execute("""
            SELECT vulnerability_type, severity, scanner, timestamp 
            FROM vulnerability 
            WHERE resource LIKE ? 
            ORDER BY severity DESC
        """, (f'%{target.replace("https://", "").replace("http://", "")}%',))
        
        vulns = cursor.fetchall()
        print(f"🔍 Уязвимости ({len(vulns)}):")
        for vuln in vulns:
            print(f"   • {vuln[0]} ({vuln[1]}) - {vuln[2]}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Ошибка отладки: {e}")

def check_vulnerability_insertion():
    """Проверяет функции вставки уязвимостей"""
    
    print(f"\n🧪 ТЕСТИРОВАНИЕ ВСТАВКИ УЯЗВИМОСТЕЙ")
    print("=" * 60)
    
    # Создаем временную БД для теста
    test_db = "debug_temp.db"
    
    try:
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        
        # Создаем таблицы
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'Medium',
                scanner TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scansession (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                end_time DATETIME,
                status TEXT DEFAULT 'running'
            )
        """)
        
        conn.commit()
        print("✅ Таблицы созданы")
        
        # Тест 1: Вставка тестовой уязвимости
        print("\n1. Тест вставки уязвимости:")
        try:
            cursor.execute("""
                INSERT INTO vulnerability (resource, vulnerability_type, description, severity, scanner)
                VALUES (?, ?, ?, ?, ?)
            """, (
                "https://demo.owasp-juice.shop/",
                "SQL Injection",
                "Test vulnerability for debugging",
                "High",
                "nuclei"
            ))
            conn.commit()
            print("✅ Уязвимость вставлена успешно")
            
            # Проверяем
            cursor.execute("SELECT COUNT(*) FROM vulnerability")
            count = cursor.fetchone()[0]
            print(f"📊 Всего уязвимостей в БД: {count}")
            
        except Exception as e:
            print(f"❌ Ошибка вставки: {e}")
        
        # Тест 2: Проверяем, что данные читаются
        print("\n2. Тест чтения данных:")
        try:
            cursor.execute("""
                SELECT resource, vulnerability_type, severity, scanner 
                FROM vulnerability 
                WHERE resource LIKE ?
            """, ("%demo.owasp-juice.shop%",))
            
            results = cursor.fetchall()
            print(f"📋 Найдено записей: {len(results)}")
            for result in results:
                print(f"   • {result[1]} ({result[2]}) - {result[3]}")
                
        except Exception as e:
            print(f"❌ Ошибка чтения: {e}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Ошибка тестирования: {e}")
    
    finally:
        # Удаляем тестовую БД
        if os.path.exists(test_db):
            os.unlink(test_db)
            print(f"\n🗑️ Тестовая БД удалена")

def compare_databases():
    """Сравнивает две базы данных"""
    
    print(f"\n🔄 СРАВНЕНИЕ БАЗ ДАННЫХ")
    print("=" * 60)
    
    db1 = "scan_results.db"
    db2 = "scan_results.db.backup_20250819_201518"  # Используем резервную копию для сравнения
    
    if not os.path.exists(db1) or not os.path.exists(db2):
        print("❌ Одна из баз данных не найдена")
        return
    
    try:
        # Подключаемся к обеим БД
        conn1 = sqlite3.connect(db1)
        conn2 = sqlite3.connect(db2)
        cursor1 = conn1.cursor()
        cursor2 = conn2.cursor()
        
        # Сравниваем таблицы
        tables = ['vulnerability', 'scansession', 'host', 'subdomain']
        
        for table in tables:
            print(f"\n📊 ТАБЛИЦА: {table}")
            
            # Количество записей
            cursor1.execute(f"SELECT COUNT(*) FROM {table}")
            count1 = cursor1.fetchone()[0]
            
            cursor2.execute(f"SELECT COUNT(*) FROM {table}")
            count2 = cursor2.fetchone()[0]
            
            print(f"   scan_results.db: {count1} записей")
            print(f"   backup.db: {count2} записей")
            
            if count1 != count2:
                print(f"   ⚠️ Различие в количестве записей!")
            
            # Если есть записи, показываем примеры
            if count1 > 0:
                cursor1.execute(f"SELECT * FROM {table} LIMIT 3")
                rows1 = cursor1.fetchall()
                print(f"   📝 Примеры из scan_results.db:")
                for i, row in enumerate(rows1, 1):
                    print(f"      {i}. {row}")
            
            if count2 > 0:
                cursor2.execute(f"SELECT * FROM {table} LIMIT 3")
                rows2 = cursor2.fetchall()
                print(f"   📝 Примеры из backup.db:")
                for i, row in enumerate(rows2, 1):
                    print(f"      {i}. {row}")
        
        conn1.close()
        conn2.close()
        
    except Exception as e:
        print(f"❌ Ошибка сравнения: {e}")

def main():
    """Основная функция"""
    print("🔧 ОТЛАДКА РЕЗУЛЬТАТОВ СКАНИРОВАНИЯ")
    print("=" * 60)
    
    # Отлаживаем последнюю сессию
    debug_scan_session("scan_results.db", 1)
    
    # Тестируем вставку уязвимостей
    check_vulnerability_insertion()
    
    # Сравниваем базы данных
    compare_databases()
    
    print(f"\n💡 РЕКОМЕНДАЦИИ:")
    print("1. Проверьте логи сканирования на наличие ошибок")
    print("2. Убедитесь, что сканеры (nuclei, nmap, gobuster) работают корректно")
    print("3. Проверьте права доступа к файлам базы данных")
    print("4. Запустите тестовое сканирование с verbose режимом")

if __name__ == "__main__":
    main()
