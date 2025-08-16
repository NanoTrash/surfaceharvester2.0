import sys
import asyncio
import sqlite3
from scanner.parser import normalize_vuln_result, universal_import_to_db

# Импортируем функции из shvs.py
from shvs import run_nmap_scan, run_gobuster_dir, run_gobuster_fuzz, run_subfinder, extract_contacts
# Импортируем парсеры из scanner/*
from scanner.nikto import run_nikto, parse_and_import_nikto
from scanner.nuclei import run_nuclei, parse_and_import_nuclei

DB_PATH = 'scan_results.db'

def prompt(msg, example=None):
    if example:
        msg = f"{msg}\nПример: {example}\n> "
    else:
        msg = f"{msg}\n> "
    return input(msg)

def select_scanner():
    print("Выберите сканер:")
    print("1. Nmap")
    print("2. Gobuster Dir")
    print("3. Gobuster Fuzz")
    print("4. Subfinder")
    print("5. Nikto")
    print("6. Nuclei")
    print("0. Выход")
    return input("> ")

def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    while True:
        choice = select_scanner()
        if choice == '1':
            target = prompt("Введите цель для Nmap (IP или домен)", "192.168.1.1 или example.com")
            result = run_nmap_scan(target)
            # Простейший парсер: ищем открытые порты и сервисы (stub)
            # TODO: заменить на полноценный XML/grep парсер
            import re
            matches = re.findall(r'(?P<port>\d+)/tcp\s+open\s+(?P<service>\w+)', result)
            norm_vulns = []
            for port, service in matches:
                norm = {
                    'ip': target,
                    'port': int(port),
                    'service': service,
                    'cve': None,
                    'severity': None,
                    'scanner': 'nmap'
                }
                norm_vulns.append(norm)
            if norm_vulns:
                universal_import_to_db(norm_vulns, cursor)
                conn.commit()
                print(f"{len(norm_vulns)} сервисов Nmap сохранено в базу.")
            else:
                print(result)
        elif choice == '2':
            target = prompt("Введите цель для Gobuster Dir (домен или IP)", "example.com")
            wordlist = prompt("Путь к словарю для Gobuster Dir", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
            result = run_gobuster_dir(target, wordlist)
            # Сохраняем найденные директории как url
            norm_vulns = []
            for line in result.splitlines():
                if line.startswith('/'):  # типичный вывод gobuster
                    norm = {
                        'ip': target,
                        'port': None,
                        'service': 'http',
                        'cve': None,
                        'severity': None,
                        'scanner': 'gobuster',
                        'dir': line.strip()
                    }
                    norm_vulns.append(norm)
            if norm_vulns:
                universal_import_to_db(norm_vulns, cursor)
                conn.commit()
                print(f"{len(norm_vulns)} директорий Gobuster сохранено в базу.")
            else:
                print(result)
        elif choice == '3':
            url = prompt("URL для Gobuster Fuzz", "http://example.com/page.php?id=FUZZ")
            wordlist = prompt("Путь к словарю для Gobuster Fuzz", "/usr/share/wordlists/fuzz.txt")
            result = run_gobuster_fuzz(url, wordlist)
            print(result)
        elif choice == '4':
            target = prompt("Введите домен для Subfinder", "example.com")
            result = run_subfinder(target)
            # Сохраняем найденные субдомены как сервисы
            norm_vulns = []
            for sub in result:
                norm = {
                    'ip': sub,
                    'port': 80,
                    'service': 'http',
                    'cve': None,
                    'severity': None,
                    'scanner': 'subfinder'
                }
                norm_vulns.append(norm)
            if norm_vulns:
                universal_import_to_db(norm_vulns, cursor)
                conn.commit()
                print(f"{len(norm_vulns)} субдоменов Subfinder сохранено в базу.")
            else:
                print(result)
        elif choice == '5':
            target = prompt("Введите цель для Nikto (URL)", "http://example.com")
            data = run_nikto(target)
            parse_and_import_nikto(data, cursor)
            conn.commit()
            print("Результаты Nikto сохранены в базу.")
        elif choice == '6':
            target = prompt("Введите цель для Nuclei (URL)", "http://example.com")
            data = run_nuclei(target)
            parse_and_import_nuclei(data, cursor)
            conn.commit()
            print("Результаты Nuclei сохранены в базу.")
        elif choice == '0':
            print("Выход.")
            break
        else:
            print("Некорректный выбор. Попробуйте снова.")
    conn.close()

if __name__ == "__main__":
    main()
