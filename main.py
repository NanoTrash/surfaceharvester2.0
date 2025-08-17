# main.py

import sqlite3
import argparse
from datetime import datetime
import os
import tempfile

from db.schema import setup_database
from db.report import show_report
from scanner.nikto import run_nikto, process_nikto_result
from scanner.nuclei import run_nuclei, process_nuclei_result


def validate_target(target):
    """
    Валидирует целевой URL
    """
    if not target:
        raise ValueError("Target URL is required")
    
    if not (target.startswith('http://') or target.startswith('https://')):
        raise ValueError("Target must be a valid HTTP/HTTPS URL")
    
    return target


def main():
    parser = argparse.ArgumentParser(description="Автоматизация сбора и анализа уязвимостей")
    parser.add_argument("target", help="Целевой URL (например, https://example.com)")
    parser.add_argument("--db", default="scan_results.db", help="Файл базы данных SQLite")
    parser.add_argument("--report", action="store_true", help="Показать отчёт после сканирования")

    args = parser.parse_args()

    try:
        # Валидация target
        target = validate_target(args.target)
    except ValueError as e:
        print(f"[ERROR] {e}")
        return 1

    # Создаем временную директорию для файлов сканирования
    temp_dir = tempfile.mkdtemp(prefix="scanner_")
    
    try:
        conn = sqlite3.connect(args.db)
        cursor = conn.cursor()

        # Инициализация схемы БД
        setup_database(cursor)
        conn.commit()

        # Создаем сессию сканирования
        from db.models import ScanSession
        ScanSession.insert(cursor, target=target, status="running")
        session_id = cursor.lastrowid
        conn.commit()

        print(f"[INFO] Начинаем сканирование {target}")
        print(f"[INFO] Сессия ID: {session_id}")
        print(f"[INFO] Временная директория: {temp_dir}")

        try:
            # Запуск сканеров
            nikto_data = run_nikto(target, temp_dir)
            if nikto_data:
                process_nikto_result(nikto_data, cursor, session_id, target)
                conn.commit()

            nuclei_data = run_nuclei(target)
            if nuclei_data:
                process_nuclei_result(nuclei_data, cursor, session_id, target)
                conn.commit()

            # Завершаем сессию
            ScanSession.update(cursor, session_id, end_time=datetime.now().isoformat(), status="completed")
            conn.commit()

            # Вывод отчёта
            if args.report:
                show_report(cursor, target)

        except Exception as e:
            print(f"[ERROR] Ошибка во время сканирования: {e}")
            # Помечаем сессию как неудачную
            ScanSession.update(cursor, session_id, end_time=datetime.now().isoformat(), status="failed")
            conn.commit()

    except Exception as e:
        print(f"[ERROR] Критическая ошибка: {e}")
        return 1

    finally:
        if 'conn' in locals():
            conn.close()
        
        # Очищаем временные файлы
        try:
            import shutil
            shutil.rmtree(temp_dir)
            print(f"[INFO] Временная директория очищена: {temp_dir}")
        except Exception as e:
            print(f"[WARNING] Не удалось очистить временную директорию: {e}")

    return 0


if __name__ == "__main__":
    exit(main())
