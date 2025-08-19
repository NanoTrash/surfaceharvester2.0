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
from db.report import list_targets
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


async def full_scan_target(target, db_file="scan_results.db", dir_wordlist=None, fuzz_wordlist=None, subdomains_all=False, subdomains_select=None):
    """
    Полное сканирование цели всеми доступными инструментами
    """
    try:
        # Если указаны флаги субдоменов, сканируем только субдомены из БД
        if subdomains_all or (subdomains_select and subdomains_select.strip()):
            print(f"[INFO] Режим сканирования ТОЛЬКО СУБДОМЕНОВ для: {target}")
            print(f"[INFO] Загружаем субдомены из базы данных...")
            
            # Загружаем субдомены из БД
            try:
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                parent_domain = target.replace('http://','').replace('https://','').split('/')[0]
                cursor.execute("SELECT DISTINCT name FROM subdomain WHERE parent_domain = ? ORDER BY name", (parent_domain,))
                unique_subdomains = [row[0] for row in cursor.fetchall()]
                conn.close()
                
                if not unique_subdomains:
                    print(f"[ERROR] Не найдено субдоменов для {parent_domain} в базе данных")
                    print("[HINT] Сначала запустите сканирование без флагов субдоменов для поиска субдоменов")
                    return False
                
                print(f"[INFO] Найдено {len(unique_subdomains)} субдоменов в базе данных")
                print("\n[SUBDOMAINS] Доступные субдомены:")
                for idx, sub in enumerate(unique_subdomains, 1):
                    print(f"  {idx}. {sub}")
                
                # Выбираем субдомены согласно флагам
                selected = []
                seen = set(unique_subdomains)
                
                if subdomains_all:
                    selected = unique_subdomains
                    print(f"\n[INFO] Выбраны ВСЕ субдомены: {len(selected)}")
                else:
                    tokens = [t.strip() for t in subdomains_select.split(',') if t.strip()]
                    for token in tokens:
                        if token.isdigit():
                            i = int(token)
                            if 1 <= i <= len(unique_subdomains):
                                selected.append(unique_subdomains[i - 1])
                        else:
                            if token in seen:
                                selected.append(token)
                    selected = list(dict.fromkeys(selected))  # убираем дубликаты
                    print(f"\n[INFO] Выбраны субдомены: {selected}")
                
                if not selected:
                    print("[ERROR] Не удалось выбрать субдомены")
                    return False
                
                # Сканируем только выбранные субдомены
                scanner = FullScanner()
                print(f"\n[SUBDOMAIN SCAN] Запускаю сканирование {len(selected)} субдоменов...")
                
                for sub in selected:
                    sub_target = f"http://{sub}"
                    print(f"\n[SUBDOMAIN SCAN] Цель: {sub_target}")
                    try:
                        sub_scan = await scanner.full_scan(sub_target, db_file, dir_wordlist, fuzz_wordlist)
                        print(f"[SUBDOMAIN SCAN] Сессия ID: {sub_scan['session_id']}")
                        print(f"[SUCCESS] Субдомен {sub} просканирован успешно!")
                    except Exception as e:
                        print(f"[SUBDOMAIN SCAN][ERROR] {sub_target}: {e}")
                
                print(f"\n[SUCCESS] Сканирование субдоменов завершено!")
                return True
                
            except Exception as e:
                print(f"[ERROR] Ошибка работы с базой данных: {e}")
                return False
        
        # Обычное сканирование основного домена
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

        # Интерактивный выбор субдоменов для повторного полного сканирования
        # Собираем уникальные субдомены из результатов
        unique_subdomains = []
        seen = set()
        for res in scan_data['results']:
            subs = res.get('subfinder') or []
            for sub in subs:
                if sub not in seen:
                    seen.add(sub)
                    unique_subdomains.append(sub)
        
        # Сохраняем субдомены в базу данных для дальнейшего использования
        if unique_subdomains:
            try:
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                for sub in unique_subdomains:
                    # Проверяем, есть ли уже такой субдомен
                    cursor.execute("SELECT id FROM subdomain WHERE name = ?", (sub,))
                    if not cursor.fetchone():
                        # Создаем новый субдомен
                        from db.models import Subdomain
                        Subdomain.insert(cursor,
                                       name=sub,
                                       parent_domain=target.replace('http://','').replace('https://','').split('/')[0],
                                       session_first_seen=scan_data['session_id'],
                                       session_last_seen=scan_data['session_id'],
                                       target=target,
                                       source='subfinder')
                conn.commit()
                conn.close()
                print(f"[INFO] Сохранено {len(unique_subdomains)} субдоменов в базу данных")
            except Exception as e:
                print(f"[WARNING] Не удалось сохранить субдомены: {e}")

        # Если субдомены не найдены в текущем сканировании, проверим базу данных
        if not unique_subdomains:
            try:
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                parent_domain = target.replace('http://','').replace('https://','').split('/')[0]
                cursor.execute("SELECT DISTINCT name FROM subdomain WHERE parent_domain = ? ORDER BY name", (parent_domain,))
                db_subdomains = [row[0] for row in cursor.fetchall()]
                conn.close()
                if db_subdomains:
                    unique_subdomains = db_subdomains
                    print(f"[INFO] Загружено {len(unique_subdomains)} субдоменов из базы данных для {parent_domain}")
            except Exception as e:
                print(f"[WARNING] Не удалось загрузить субдомены из БД: {e}")

        if unique_subdomains:
            print("\n[SUBDOMAINS] Доступные субдомены:")
            for idx, sub in enumerate(unique_subdomains, 1):
                print(f"  {idx}. {sub}")
            print(f"\n[INFO] Все субдомены сохранены в БД. Используйте 'targets-scan' для повторного сканирования.")

            # Непосредственный выбор через флаги CLI
            if subdomains_all or (subdomains_select and subdomains_select.strip()):
                selected = []
                if subdomains_all:
                    selected = unique_subdomains
                else:
                    tokens = [t.strip() for t in subdomains_select.split(',') if t.strip()]
                    for token in tokens:
                        if token.isdigit():
                            i = int(token)
                            if 1 <= i <= len(unique_subdomains):
                                selected.append(unique_subdomains[i - 1])
                        else:
                            if token in seen:
                                selected.append(token)
                selected = list(dict.fromkeys(selected))
                if selected:
                    print(f"\n[CHAIN SCAN] Запускаю повторные полные сканы для {len(selected)} субдоменов...")
                    for sub in selected:
                        sub_target = f"http://{sub}"
                        print(f"\n[CHAIN SCAN] Цель: {sub_target}")
                        try:
                            sub_scan = await scanner.full_scan(sub_target, db_file, dir_wordlist, fuzz_wordlist)
                            print(f"[CHAIN SCAN] Сессия ID: {sub_scan['session_id']}")
                        except Exception as e:
                            print(f"[CHAIN SCAN][ERROR] {sub_target}: {e}")
            else:
                try:
                    choice = input("\nЗапустить полные сканы для субдоменов? (y/N): ").strip().lower()
                except EOFError:
                    choice = 'n'

                if choice == 'y':
                    print("[DEBUG] Пользователь выбрал запуск сканирования субдоменов...")
                    # Цикл выбора до тех пор, пока пользователь не выберет или не отменит
                    input_errors = 0
                    max_input_errors = 3
                    
                    while True:
                        try:
                            print(f"[DEBUG] Доступно {len(unique_subdomains)} субдоменов для выбора")
                            raw_sel = input("Укажите номера через запятую или имена субдоменов (all | q=отмена): ").strip()
                            print(f"[DEBUG] Пользователь ввел: '{raw_sel}'")
                            input_errors = 0  # Сбрасываем счетчик при успешном вводе
                        except EOFError:
                            input_errors += 1
                            print(f"[DEBUG] EOFError при получении ввода пользователя (ошибка {input_errors}/{max_input_errors})")
                            if input_errors >= max_input_errors:
                                print("[WARNING] Превышено количество ошибок ввода. Отмена выбора субдоменов.")
                                break
                            raw_sel = ''
                        except KeyboardInterrupt:
                            print("\n[DEBUG] KeyboardInterrupt - пользователь прервал ввод")
                            break
                        except Exception as e:
                            input_errors += 1
                            print(f"[DEBUG] Неожиданная ошибка при вводе: {e} (ошибка {input_errors}/{max_input_errors})")
                            if input_errors >= max_input_errors:
                                print("[WARNING] Превышено количество ошибок ввода. Отмена выбора субдоменов.")
                                break
                            raw_sel = ''

                        if not raw_sel:
                            if input_errors >= max_input_errors:
                                break
                            print("Ничего не введено. Введите номера (например: 1,3,5), 'all' или 'q' для отмены.")
                            continue

                        if raw_sel.lower() in ('q', 'quit', 'exit'):
                            print("Отмена выбора субдоменов.")
                            break

                        selected = []
                        if raw_sel.lower() == 'all':
                            selected = unique_subdomains
                        else:
                            tokens = [t.strip() for t in raw_sel.split(',') if t.strip()]
                            for token in tokens:
                                if token.isdigit():
                                    i = int(token)
                                    if 1 <= i <= len(unique_subdomains):
                                        selected.append(unique_subdomains[i - 1])
                                else:
                                    if token in seen:
                                        selected.append(token)

                        # Убираем дубликаты, если пользователь указал и номер, и имя
                        selected = list(dict.fromkeys(selected))

                        if not selected:
                            print("Не распознал цели. Повторите ввод (или 'q' для отмены).")
                            continue

                        print(f"\n[CHAIN SCAN] Запускаю повторные полные сканы для {len(selected)} субдоменов...")
                        for sub in selected:
                            sub_target = f"http://{sub}"
                            print(f"\n[CHAIN SCAN] Цель: {sub_target}")
                            try:
                                sub_scan = await scanner.full_scan(sub_target, db_file, dir_wordlist, fuzz_wordlist)
                                print(f"[CHAIN SCAN] Сессия ID: {sub_scan['session_id']}")
                            except Exception as e:
                                print(f"[CHAIN SCAN][ERROR] {sub_target}: {e}")
                        break
                else:
                    print("[DEBUG] Пользователь выбрал НЕ запускать сканирование субдоменов")
                    print("[HINT] Для автоматического сканирования субдоменов используйте:")
                    print("  --subdomains-all                   # сканировать все субдомены")
                    print("  --subdomains-select '1,3,5'        # сканировать выбранные номера")
                    print("  --subdomains-select 'test.site.com' # сканировать конкретные домены")

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


def handle_exploits_command(args):
    """Обработчик команд exploits"""
    try:
        # Динамический импорт для избежания ошибок если модули не установлены
        from scanner.cve_monitor import CVEProcessor
        import asyncio
        import json
        import time
        
        processor = CVEProcessor(args.db)
        
        if args.exploits_command == 'search':
            # Поиск эксплойтов для pending уязвимостей
            print("[INFO] Поиск эксплойтов для уязвимостей...")
            
            if args.target:
                print(f"[INFO] Фильтр по цели: {args.target}")
            
            async def run_search():
                result = await processor.process_all_pending(args.limit)
                print(f"\n[SUCCESS] Обработано уязвимостей: {result['processed']}")
                print(f"[SUCCESS] Найдено эксплойтов: {result['exploits_found']}")
                return result
            
            result = asyncio.run(run_search())
            return 0 if result['processed'] > 0 else 1
        
        elif args.exploits_command == 'monitor':
            # Запуск мониторинга
            print(f"[INFO] Запуск мониторинга CVE (интервал: {args.interval}s)")
            
            try:
                processor.start_monitoring(args.interval)
                
                if args.daemon:
                    print("[INFO] Мониторинг запущен в фоне. Для остановки используйте Ctrl+C")
                    try:
                        while True:
                            time.sleep(60)
                            status = processor.monitor.get_status()
                            processed = sum(status.get('processing_stats', {}).values())
                            exploits = status.get('exploit_stats', {}).get('total_exploits', 0)
                            print(f"[STATUS] Обработано CVE: {processed}, Найдено эксплойтов: {exploits}")
                    except KeyboardInterrupt:
                        print("\n[INFO] Получен сигнал остановки")
                else:
                    print("[INFO] Мониторинг запущен. Нажмите Ctrl+C для остановки")
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        print("\n[INFO] Остановка мониторинга...")
            finally:
                processor.stop_monitoring()
            
            return 0
        
        elif args.exploits_command == 'status':
            # Статус обработки
            status = processor.monitor.get_status()
            
            print("=== Статус CVE обработки ===")
            print(f"Мониторинг активен: {'✅' if status['running'] else '❌'}")
            print(f"Последняя проверка: {status.get('last_check', 'Никогда')}")
            print(f"Интервал: {status.get('check_interval', 'N/A')}s")
            
            print(f"\n📊 Статистика обработки:")
            processing_stats = status.get('processing_stats', {})
            for status_name, count in processing_stats.items():
                emoji = {'completed': '✅', 'failed': '❌', 'processing': '⏳', 'pending': '⏸️'}.get(status_name, '📋')
                print(f"  {emoji} {status_name}: {count}")
            
            print(f"\n🎯 Статистика эксплойтов:")
            exploit_stats = status.get('exploit_stats', {})
            print(f"  💥 Всего эксплойтов: {exploit_stats.get('total_exploits', 0)}")
            print(f"  🔍 Уникальных CVE: {exploit_stats.get('unique_cves', 0)}")
            print(f"  🎯 Уязвимых ресурсов: {exploit_stats.get('vulnerable_assets', 0)}")
            
            return 0
        
        elif args.exploits_command == 'report':
            # Отчёт по эксплойтам
            report = processor.get_exploit_report()
            
            if args.format == 'json':
                print(json.dumps(report, ensure_ascii=False, indent=2))
                return 0
            
            print("=== 📋 Отчёт по найденным эксплойтам ===")
            
            stats = report.get('stats', [])
            if stats:
                print(f"\n📊 Статистика по типам эксплойтов:")
                for stat in stats[:10]:  # топ 10
                    total, unique_cves, assets, exploit_type, source, language = stat
                    print(f"  🔸 {exploit_type} ({source}, {language}): {total} эксплойтов")
            
            top_cves = report.get('top_cves', [])
            if top_cves:
                print(f"\n🎯 Топ CVE по количеству эксплойтов:")
                for cve_stat in top_cves[:10]:
                    cve_id, exploit_count, avg_severity = cve_stat
                    severity_emoji = {'10.0': '🔴', '9': '🔴', '8': '🟠', '7': '🟠', '6': '🟡', '5': '🟡'}.get(str(int(avg_severity)), '🟢')
                    print(f"  {severity_emoji} {cve_id}: {exploit_count} эксплойтов (severity: {avg_severity:.1f})")
            
            if not stats and not top_cves:
                print("ℹ️  Эксплойты не найдены. Запустите 'exploits search' для поиска.")
            
            return 0
        
        else:
            print(f"[ERROR] Неизвестная подкоманда exploits: {args.exploits_command}")
            return 1
    
    except ImportError as e:
        print(f"[ERROR] Не удалось импортировать модули vulnx: {e}")
        print("[HINT] Убедитесь, что установлены зависимости: requests")
        return 1
    except Exception as e:
        print(f"[ERROR] Ошибка выполнения команды exploits: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Инструмент для автоматизированного сканирования уязвимостей и сбора информации о поверхности с использованием AI-парсинга результатов",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s full-scan http://example.com
  %(prog)s full-scan http://example.com --dir-wordlist /path/to/dir.txt --fuzz-wordlist /path/to/fuzz.txt
  %(prog)s scan http://example.com --scanners wapiti,nuclei
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
    # Неинтерактивный выбор субдоменов
    full_scan_parser.add_argument('--subdomains-all', action='store_true', help='Сканировать все найденные субдомены')
    full_scan_parser.add_argument('--subdomains-select', help='Сканировать выбранные субдомены (номера через запятую или имена)')
    
    # Информация о доступных инструментах
    print("[INFO] Доступные инструменты: nmap, wapiti, nuclei, subfinder, gobuster")
    
    # Команда scan (уязвимости - устаревшая)
    scan_parser = subparsers.add_parser('scan', help='Сканировать уязвимости (устаревшая команда)')
    scan_parser.add_argument('target', help='Целевой URL')
    scan_parser.add_argument('--db', default='scan_results.db', help='Файл базы данных')
    scan_parser.add_argument('--scanners', default='wapiti,nuclei', 
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

    # Команда targets-list
    targets_list_parser = subparsers.add_parser('targets-list', help='Показать сохраненные цели')
    targets_list_parser.add_argument('--db', default='scan_results.db', help='Файл базы данных')
    targets_list_parser.add_argument('--subdomains', action='store_true', help='Показывать только субдомены')

    # Команда targets-scan
    targets_scan_parser = subparsers.add_parser('targets-scan', help='Выбрать цели из БД и запустить полные сканы')
    targets_scan_parser.add_argument('--db', default='scan_results.db', help='Файл базы данных')
    targets_scan_parser.add_argument('--dir-wordlist', required=True, help='Путь к словарю для gobuster dir')
    targets_scan_parser.add_argument('--fuzz-wordlist', help='Путь к словарю для gobuster fuzz')
    targets_scan_parser.add_argument('--subdomains', action='store_true', help='Выбирать только субдомены')

    # Команда exploits - поиск эксплойтов через vulnx
    exploits_parser = subparsers.add_parser('exploits', help='Поиск эксплойтов для уязвимостей')
    exploits_subparsers = exploits_parser.add_subparsers(dest='exploits_command', help='Команды для работы с эксплойтами')
    
    # Подкоманда search
    exploits_search_parser = exploits_subparsers.add_parser('search', help='Поиск эксплойтов для pending уязвимостей')
    exploits_search_parser.add_argument('--db', default='scan_results.db', help='Путь к базе данных')
    exploits_search_parser.add_argument('--limit', type=int, default=50, help='Лимит обработки уязвимостей')
    exploits_search_parser.add_argument('--target', help='Поиск только для конкретной цели')
    
    # Подкоманда monitor
    exploits_monitor_parser = exploits_subparsers.add_parser('monitor', help='Мониторинг новых CVE')
    exploits_monitor_parser.add_argument('--db', default='scan_results.db', help='Путь к базе данных')
    exploits_monitor_parser.add_argument('--interval', type=int, default=60, help='Интервал проверки (секунды)')
    exploits_monitor_parser.add_argument('--daemon', action='store_true', help='Запуск в фоне')
    
    # Подкоманда status
    exploits_status_parser = exploits_subparsers.add_parser('status', help='Статус обработки CVE')
    exploits_status_parser.add_argument('--db', default='scan_results.db', help='Путь к базе данных')
    
    # Подкоманда report
    exploits_report_parser = exploits_subparsers.add_parser('report', help='Отчёт по найденным эксплойтам')
    exploits_report_parser.add_argument('--db', default='scan_results.db', help='Путь к базе данных')
    exploits_report_parser.add_argument('--target', help='Отчёт только для конкретной цели')
    exploits_report_parser.add_argument('--cve', help='Отчёт только для конкретного CVE')
    exploits_report_parser.add_argument('--format', choices=['table', 'json'], default='table', help='Формат вывода')
    
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
                args.fuzz_wordlist,
                subdomains_all=args.subdomains_all,
                subdomains_select=args.subdomains_select
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
        
        elif args.command == 'targets-list':
            if not os.path.exists(args.db):
                print(f"[ERROR] База данных {args.db} не найдена")
                return 1
            conn = sqlite3.connect(args.db)
            cursor = conn.cursor()
            targets = list_targets(cursor, only_subdomains=args.subdomains)
            conn.close()
            if not targets:
                print("Целей не найдено")
                return 0
            print("\nСохраненные цели:")
            for i, t in enumerate(targets, 1):
                print(f"  {i}. {t}")
            return 0

        elif args.command == 'targets-scan':
            if not os.path.exists(args.db):
                print(f"[ERROR] База данных {args.db} не найдена")
                return 1
            conn = sqlite3.connect(args.db)
            cursor = conn.cursor()
            targets = list_targets(cursor, only_subdomains=args.subdomains)
            conn.close()
            if not targets:
                print("Целей не найдено")
                return 1
            print("\nВыберите цели для сканирования:")
            for i, t in enumerate(targets, 1):
                print(f"  {i}. {t}")
            try:
                raw_sel = input("Укажите номера через запятую или 'all': ").strip()
            except EOFError:
                raw_sel = ''
            selected = []
            if raw_sel.lower() == 'all':
                selected = targets
            else:
                tokens = [t.strip() for t in raw_sel.split(',') if t.strip()]
                for token in tokens:
                    if token.isdigit():
                        i = int(token)
                        if 1 <= i <= len(targets):
                            selected.append(targets[i - 1])
            selected = list(dict.fromkeys(selected))
            if not selected:
                print("Не выбрано ни одной цели")
                return 1
            # Запускаем полные сканы последовательно
            for t in selected:
                sub_target = t if t.startswith('http') else f"http://{t}"
                print(f"\n[CHAIN SCAN] Цель: {sub_target}")
                success = asyncio.run(full_scan_target(
                    sub_target,
                    args.db,
                    args.dir_wordlist,
                    args.fuzz_wordlist
                ))
                if not success:
                    print(f"[ERROR] Ошибка при сканировании {sub_target}")
            return 0

        elif args.command == 'exploits':
            return handle_exploits_command(args)
            
    except Exception as e:
        print(f"[ERROR] Неожиданная ошибка: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
