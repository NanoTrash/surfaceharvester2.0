#!/usr/bin/env python3
# cli.py

import argparse
import sqlite3
import sys
from datetime import datetime
import tempfile
import os
import asyncio

from db.schema import setup_database, insert_initial_data
from db.report import show_report, show_summary, show_summary_report
from scanner.wapiti import run_wapiti, process_wapiti_result
from scanner.nuclei import run_nuclei, process_nuclei_result
from scanner.ai_parser import AIVulnerabilityParser
from scanner.surface_harvester import SurfaceHarvester
from scanner.full_scanner import FullScanner


def validate_target(target):
    """
    Валидирует целевой URL
    """
    if not target:
        raise ValueError("Target URL is required")
    
    if not (target.startswith('http://') or target.startswith('https://')):
        raise ValueError("Target must be a valid HTTP/HTTPS URL")
    
    # Дополнительная проверка на потенциально опасные символы
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']']
    for char in dangerous_chars:
        if char in target:
            raise ValueError(f"Target contains dangerous character: {char}")
    
    return target


def scan_target(target, db_file="scan_results.db", scanners=None):
    """
    Сканирует указанную цель (устаревшая функция - используйте full_scan)
    """
    if scanners is None:
        scanners = ['wapiti', 'nuclei']
    
    # Валидация target
    try:
        target = validate_target(target)
    except ValueError as e:
        print(f"[ERROR] {e}")
        return False
    
    # Создаем временную директорию
    temp_dir = tempfile.mkdtemp(prefix="scanner_")
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Инициализация БД
        setup_database(cursor)
        conn.commit()
        
        # Создаем сессию сканирования
        from db.models import ScanSession
        ScanSession.insert(cursor, target=target, status="running")
        session_id = cursor.lastrowid
        conn.commit()
        
        print(f"[INFO] Начинаем сканирование {target}")
        print(f"[INFO] Сессия ID: {session_id}")
        print(f"[INFO] Сканеры: {', '.join(scanners)}")
        print(f"[INFO] Временная директория: {temp_dir}")
        
        try:
            if 'wapiti' in scanners:
                print("\n[WAPITI] Запуск Wapiti...")
                wapiti_data = run_wapiti(target, temp_dir)
                if wapiti_data:
                    process_wapiti_result(wapiti_data, cursor, session_id, target)
                    conn.commit()
            
            if 'nuclei' in scanners:
                print("\n[NUCLEI] Запуск Nuclei...")
                nuclei_data = run_nuclei(target)
                if nuclei_data:
                    process_nuclei_result(nuclei_data, cursor, session_id, target)
                    conn.commit()
            
            # Завершаем сессию
            ScanSession.update(cursor, session_id, end_time=datetime.now().isoformat(), status="completed")
            conn.commit()
            
            print(f"\n[SUCCESS] Сканирование завершено успешно!")
            
        except Exception as e:
            print(f"[ERROR] Ошибка во время сканирования: {e}")
            ScanSession.update(cursor, session_id, end_time=datetime.now().isoformat(), status="failed")
            conn.commit()
            return False
        
        finally:
            conn.close()
            
    except Exception as e:
        print(f"[ERROR] Критическая ошибка: {e}")
        return False
    
    finally:
        # Очищаем временные файлы
        try:
            import shutil
            shutil.rmtree(temp_dir)
            print(f"[INFO] Временная директория очищена: {temp_dir}")
        except Exception as e:
            print(f"[WARNING] Не удалось очистить временную директорию: {e}")
    
    return True


async def full_scan_target(target, db_file="scan_results.db", dir_wordlist=None, fuzz_wordlist=None):
    """
    Полное сканирование цели всеми доступными инструментами
    """
    try:
        print(f"[INFO] Начинаем ПОЛНОЕ сканирование: {target}")
        print(f"[INFO] Доступные инструменты: nmap, wapiti, nuclei, subfinder, gobuster")
        if dir_wordlist:
            print(f"[INFO] Словарь директорий: {dir_wordlist}")
        if fuzz_wordlist:
            print(f"[INFO] Словарь фаззинга: {fuzz_wordlist}")
        
        scanner = FullScanner()
        scan_data = await scanner.full_scan(target, db_file, dir_wordlist, fuzz_wordlist)
        
        print(f"\n[SUCCESS] Полное сканирование завершено!")
        print(f"[INFO] Сессия ID: {scan_data['session_id']}")
        
        # Выводим краткую сводку
        if not scan_data['is_ip']:
            contacts = scan_data['contacts']
            print(f"\n[КОНТАКТЫ]")
            print(f"Email: {contacts['emails']}")
            print(f"Телефоны: {contacts['phones']}")
        
        print(f"\n[РЕЗУЛЬТАТЫ]")
        for res in scan_data['results']:
            print(f"- {res['target']} ({res['type']})")
            if 'subfinder' in res and res['subfinder']:
                print(f"  Субдомены: {len(res['subfinder'])} найдено")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Ошибка полного сканирования: {e}")
        return False


async def surface_scan(target, dir_wordlist, fuzz_wordlist=None, output_file="scan_results.txt"):
    """
    Запускает полное сканирование поверхности (только сбор информации)
    """
    try:
        print(f"[INFO] Начинаем сканирование поверхности: {target}")
        print(f"[INFO] Словарь директорий: {dir_wordlist}")
        if fuzz_wordlist:
            print(f"[INFO] Словарь фаззинга: {fuzz_wordlist}")
        
        harvester = SurfaceHarvester()
        scan_data = await harvester.scan_target(target, dir_wordlist, fuzz_wordlist)
        
        # Сохраняем отчет
        output_path = harvester.save_report(scan_data, output_file)
        
        print(f"\n[SUCCESS] Сканирование поверхности завершено!")
        print(f"[INFO] Отчет сохранен в: {output_path}")
        
        # Выводим краткую сводку
        if not scan_data['is_ip']:
            contacts = scan_data['contacts']
            print(f"\n[КОНТАКТЫ]")
            print(f"Email: {contacts['emails']}")
            print(f"Телефоны: {contacts['phones']}")
        
        print(f"\n[РЕЗУЛЬТАТЫ]")
        for res in scan_data['results']:
            print(f"- {res['target']} ({res['type']})")
            if 'subfinder' in res and res['subfinder']:
                print(f"  Субдомены: {len(res['subfinder'])} найдено")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Ошибка сканирования поверхности: {e}")
        return False


def show_vulnerabilities(db_file="scan_results.db", target=None, severity=None):
    """
    Показывает уязвимости из базы данных
    """
    if not os.path.exists(db_file):
        print(f"[ERROR] База данных {db_file} не найдена")
        return
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        if target:
            show_report(cursor, target)
        else:
            show_summary(cursor)
        
        conn.close()
    except Exception as e:
        print(f"[ERROR] Ошибка при работе с базой данных: {e}")


def list_sessions(db_file="scan_results.db"):
    """
    Показывает список сессий сканирования
    """
    if not os.path.exists(db_file):
        print(f"[ERROR] База данных {db_file} не найдена")
        return
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        from db.report import get_scan_sessions
        sessions = get_scan_sessions(cursor)
        
        print("\n" + "="*60)
        print("ИСТОРИЯ СКАНИРОВАНИЙ")
        print("="*60)
        
        if not sessions:
            print("История сканирований пуста")
        else:
            for i, (target, start_time, end_time, status) in enumerate(sessions, 1):
                print(f"{i}. Цель: {target}")
                print(f"   Статус: {status}")
                print(f"   Начало: {start_time}")
                if end_time:
                    print(f"   Конец: {end_time}")
                print()
        
        conn.close()
    except Exception as e:
        print(f"[ERROR] Ошибка при работе с базой данных: {e}")


def show_summary(db_file, target=None):
    """
    Показывает краткий отчет
    """
    try:
        show_summary_report(target, db_file)
    except Exception as e:
        print(f"[ERROR] Ошибка при показе краткого отчета: {e}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Инструмент для автоматизированного сканирования уязвимостей и сбора информации о поверхности с использованием AI-парсинга результатов",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s full-scan http://example.com
  %(prog)s full-scan http://example.com --dir-wordlist /path/to/dir.txt --fuzz-wordlist /path/to/fuzz.txt
  %(prog)s scan http://example.com --scanners nikto,nuclei
  %(prog)s surface example.com --dir-wordlist /path/to/dir.txt --fuzz-wordlist /path/to/fuzz.txt
  %(prog)s report --target http://example.com
  %(prog)s sessions
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Доступные команды')
    
    # Полное сканирование
    full_scan_parser = subparsers.add_parser('full-scan', help='Полное сканирование с использованием всех инструментов')
    full_scan_parser.add_argument('target', help='Целевой URL для сканирования')
    full_scan_parser.add_argument('--db', default='scan_results.db', help='Путь к базе данных (по умолчанию: scan_results.db)')
    full_scan_parser.add_argument('--dir-wordlist', required=True, help='Путь к словарю для gobuster dir')
    full_scan_parser.add_argument('--fuzz-wordlist', required=True, help='Путь к словарю для gobuster fuzz')
    
    # Информация о доступных инструментах
    print("[INFO] Доступные инструменты: nmap, wapiti, nuclei, subfinder, gobuster")
    
    # Команда scan (уязвимости - устаревшая)
    scan_parser = subparsers.add_parser('scan', help='Сканировать уязвимости (устаревшая команда)')
    scan_parser.add_argument('target', help='Целевой URL')
    scan_parser.add_argument('--db', default='scan_results.db', help='Файл базы данных')
    scan_parser.add_argument('--scanners', default='nikto,nuclei', 
                           help='Список сканеров (через запятую)')
    
    # Команда surface (сбор информации о поверхности)
    surface_parser = subparsers.add_parser('surface', help='Сканировать поверхность (порты, директории, субдомены)')
    surface_parser.add_argument('target', help='Целевой домен или IP')
    surface_parser.add_argument('--dir-wordlist', required=True, help='Путь к словарю для gobuster dir')
    surface_parser.add_argument('--fuzz-wordlist', help='Путь к словарю для gobuster fuzz')
    surface_parser.add_argument('--output', default='scan_results.txt', help='Файл для сохранения отчета')
    
    # Просмотр отчета
    report_parser = subparsers.add_parser('report', help='Показать отчет по сканированию')
    report_parser.add_argument('--target', help='Целевой URL для отчета')
    report_parser.add_argument('--db', default='scan_results.db', help='Файл базы данных')
    
    # Краткий отчет
    summary_parser = subparsers.add_parser('summary', help='Показать краткий отчет с эмодзи')
    summary_parser.add_argument('--target', help='Целевой URL для отчета')
    summary_parser.add_argument('--db', default='scan_results.db', help='Файл базы данных')
    
    # Команда sessions
    sessions_parser = subparsers.add_parser('sessions', help='Показать историю сканирований')
    sessions_parser.add_argument('--db', default='scan_results.db', help='Файл базы данных')
    
    # Команда init
    init_parser = subparsers.add_parser('init', help='Инициализировать базу данных')
    init_parser.add_argument('--db', default='scan_results.db', help='Файл базы данных')
    init_parser.add_argument('--test-data', action='store_true', help='Добавить тестовые данные')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        if args.command == 'full-scan':
            success = asyncio.run(full_scan_target(
                args.target, 
                args.db, 
                args.dir_wordlist, 
                args.fuzz_wordlist
            ))
            if success:
                print("\nДля просмотра отчета выполните:")
                print(f"  {sys.argv[0]} report --target {args.target}")
            return 0 if success else 1
        
        elif args.command == 'scan':
            scanners = [s.strip() for s in args.scanners.split(',')]
            success = scan_target(args.target, args.db, scanners)
            if success:
                print("\nДля просмотра отчета выполните:")
                print(f"  {sys.argv[0]} report --target {args.target}")
            return 0 if success else 1
        
        elif args.command == 'surface':
            success = asyncio.run(surface_scan(
                args.target, 
                args.dir_wordlist, 
                args.fuzz_wordlist, 
                args.output
            ))
            return 0 if success else 1
        
        elif args.command == 'report':
            show_vulnerabilities(args.db, args.target)
            return 0
        
        elif args.command == 'summary':
            show_summary(args.db, args.target)
            return 0
        
        elif args.command == 'sessions':
            list_sessions(args.db)
            return 0
        
        elif args.command == 'init':
            conn = sqlite3.connect(args.db)
            cursor = conn.cursor()
            setup_database(cursor)
            if args.test_data:
                insert_initial_data(cursor)
            conn.commit()
            conn.close()
            print(f"[SUCCESS] База данных {args.db} инициализирована")
            return 0
            
    except Exception as e:
        print(f"[ERROR] Неожиданная ошибка: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
