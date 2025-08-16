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
    print("7. Все сканеры")
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
        elif choice == '7':
            print("[Все сканеры] Запуск всех сканеров для одной цели...")
            target = prompt("Введите цель (домен или IP)", "example.com или 192.168.1.1")
            dir_wordlist = prompt("Путь к словарю для Gobuster Dir", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
            fuzz_wordlist = prompt("Путь к словарю для Gobuster Fuzz", "/usr/share/wordlists/fuzz.txt")

            # 1. Nmap
            nmap_result = run_nmap_scan(target)
            import re
            matches = re.findall(r'(?P<port>\d+)/tcp\s+open\s+(?P<service>\w+)', nmap_result)
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
                print(nmap_result)

            # 2. Gobuster Dir
            gobuster_dir_result = run_gobuster_dir(target, dir_wordlist)
            norm_vulns = []
            for line in gobuster_dir_result.splitlines():
                if line.startswith('/'):
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
                print(gobuster_dir_result)

            # 3. Gobuster Fuzz (ищем потенциальные точки для фаззинга)
            fuzz_results = []
            for line in gobuster_dir_result.splitlines():
                if '?' in line and '=' in line:
                    path = line.split()[0] if line.split() else line
                    if '=' in path:
                        param_path = path.split('=')[0] + '=FUZZ'
                        base_url = target if target.startswith('http') else f'http://{target}'
                        fuzz_url = base_url.rstrip('/') + param_path
                        fuzz_output = run_gobuster_fuzz(fuzz_url, fuzz_wordlist)
                        fuzz_results.append({'url': fuzz_url, 'result': fuzz_output, 'wordlist': fuzz_wordlist})
            for fuzz in fuzz_results:
                print(f"[Gobuster Fuzz] {fuzz['url']} (словарь: {fuzz['wordlist']})\n{fuzz['result']}")

            # 4. Subfinder
            subfinder_result = run_subfinder(target)
            norm_vulns = []
            for sub in subfinder_result:
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
                print(subfinder_result)

            # 5. Nikto
            from scanner.nikto import run_nikto, parse_and_import_nikto
            nikto_data = run_nikto(target)
            parse_and_import_nikto(nikto_data, cursor)
            conn.commit()
            print("Результаты Nikto сохранены в базу.")

            # 6. Nuclei
            from scanner.nuclei import run_nuclei, parse_and_import_nuclei
            nuclei_data = run_nuclei(target)
            parse_and_import_nuclei(nuclei_data, cursor)
            conn.commit()
            print("Результаты Nuclei сохранены в базу.")

            # 7. Wappalyzer
            from scanner.wappalyzer import run_wappalyzer, process_wappalyzer_result
            wappalyzer_data = run_wappalyzer(target)
            from scanner.parser import extract_host_and_url
            host_id, url_id = extract_host_and_url(target, cursor)
            process_wappalyzer_result(wappalyzer_data, cursor, host_id)
            conn.commit()
            print("Результаты Wappalyzer сохранены в базу.")

            # Итоговый отчет
            from db.report import show_report
            show_report(cursor, target.replace("https://", "").replace("http://", ""))
        elif choice == '0':
            print("Выход.")
            break
        else:
            print("Некорректный выбор. Попробуйте снова.")
    conn.close()

if __name__ == "__main__":
    main()
