# main.py

import sqlite3
import argparse

from db.schema import setup_database, insert_initial_data
from db.report import show_report
from scanner.parser import extract_host_and_url
from scanner.nikto import run_nikto, process_nikto_result
from scanner.nuclei import run_nuclei, process_nuclei_result


def main():
    parser = argparse.ArgumentParser(description="Автоматизация сбора и анализа уязвимостей")
    parser.add_argument("target", help="Целевой URL (например, https://example.com)")
    parser.add_argument("--db", default="scanner.db", help="Файл базы данных SQLite")
    parser.add_argument("--report", action="store_true", help="Показать отчёт после сканирования")

    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    cursor = conn.cursor()

    # Инициализация схемы БД
    setup_database(cursor)
    conn.commit()

    # Обработка цели
    host_id, url_id = extract_host_and_url(args.target, cursor)
    conn.commit()

    # Запуск сканеров
    nikto_data = run_nikto(args.target)
    process_nikto_result(nikto_data, cursor, url_id)
    conn.commit()

    nuclei_data = run_nuclei(args.target)
    process_nuclei_result(nuclei_data, cursor, url_id)
    conn.commit()

    # Вывод отчёта
    if args.report:
        show_report(cursor, args.target.replace("https://", "").replace("http://", ""))

    conn.close()


if __name__ == "__main__":
    main()
