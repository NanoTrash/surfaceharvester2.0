import subprocess
import re
import aiohttp
import asyncio
import logging
from bs4 import BeautifulSoup
import os

logging.basicConfig(filename='surfaceharvester.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

def validate_wordlist(wordlist_path):
    if not os.path.isfile(wordlist_path):
        logging.error(f"Wordlist file not found: {wordlist_path}")
        raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")

def validate_target(target):
    if not target:
        logging.error("Target is empty")
        raise ValueError("Target cannot be empty")

# Функция для запуска скана nmap
def run_nmap_scan(target):
    try:
        result = subprocess.run(['nmap', "-A", "--script", "vulners", "--script-args", "mincvss=3", target], capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        logging.error(f"[Nmap error for {target}]: {e}")
        return f"[Nmap error for {target}]: {e}\n"

# Функция для запуска скана gobuster (директории)
def run_gobuster_dir(target, wordlist):
    url = target if target.startswith('http') else f"http://{target}"
    try:
        result = subprocess.run([
            'gobuster', 'dir',
            '-u', url,
            '-w', wordlist,
            '-t', '50'
        ], capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        logging.error(f"[Gobuster dir error for {target}]: {e}")
        return f"[Gobuster dir error for {target}]: {e}\n"

# Функция для поиска субдоменов с помощью subfinder

def run_subfinder(target):
    try:
        result = subprocess.run(['subfinder', '-d', target, '-silent'], capture_output=True, text=True, check=True)
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return subdomains
    except Exception as e:
        logging.error(f"[Subfinder error for {target}]: {e}")
        return [f"[Subfinder error for {target}]: {e}"]

# Асинхронная функция для извлечения адресов электронной почты и телефонов из веб-страницы
async def extract_contacts(url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', str(soup))
                phones = re.findall(r'\+\d[\d\s()+-]+', str(soup))
                return emails, phones
    except Exception as e:
        logging.error(f"[Extract contacts error for {url}]: {e}")
        return [], []

def run_gobuster_fuzz(target_url, wordlist):
    try:
        result = subprocess.run([
            'gobuster', 'fuzz',
            '-u', target_url,
            '-w', wordlist,
            '-t', '50'
        ], capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        logging.error(f"[Gobuster fuzz error for {target_url}]: {e}")
        return f"[Gobuster fuzz error for {target_url}]: {e}\n"

async def main():
    dir_wordlist = input("Введите путь к словарю для gobuster dir: ")
    fuzz_wordlist = input("Введите путь к словарю для gobuster fuzz: ")
    wordlist = dir_wordlist  # для обратной совместимости с валидацией
    target = input("Введите целевой адрес (домен или IP): ")
    try:
        validate_wordlist(dir_wordlist)
        validate_wordlist(fuzz_wordlist)
        validate_target(target)
    except Exception as e:
        print(f"Ошибка валидации: {e}")
        return

    emails, phones, domains = [], [], set()
    all_results = []

    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))

    # Всегда запускаем nmap для исходного target
    nmap_result = run_nmap_scan(target)

    if is_ip:
        all_results.append({
            'target': target,
            'type': 'ip',
            'nmap': nmap_result
        })
    else:
        target = target.replace("http://", "").replace("https://", "")
        url = f"http://{target}"
        emails, phones = await extract_contacts(url)
        print(f"Найденные телефоны: {phones}")
        print(f"Найденные адреса электронной почты: {emails}")
        domains = set(email.split('@')[1] for email in emails)
        all_domains = list(domains.union({target}))
        for domain in all_domains:
            # Запускаем nmap для каждого домена
            nmap_result = run_nmap_scan(domain)
            print(f"[INFO] Используется словарь для gobuster dir: {dir_wordlist}")
            gobuster_dir_result = run_gobuster_dir(domain, dir_wordlist)
            # Ищем потенциальные точки для фаззинга
            fuzz_results = []
            for line in gobuster_dir_result.splitlines():
                if '?' in line and '=' in line:
                    path = line.split()[0] if line.split() else line
                    if '=' in path:
                        param_path = path.split('=')[0] + '=FUZZ'
                        base_url = domain if domain.startswith('http') else f'http://{domain}'
                        fuzz_url = base_url.rstrip('/') + param_path
                        print(f"[INFO] Используется словарь для gobuster fuzz: {fuzz_wordlist}")
                        fuzz_output = run_gobuster_fuzz(fuzz_url, fuzz_wordlist)
                        fuzz_results.append({'url': fuzz_url, 'result': fuzz_output, 'wordlist': fuzz_wordlist})
            # Запускаем subfinder только один раз для каждой уникальной цели
            subfinder_result = run_subfinder(domain)
            all_results.append({
                'target': domain,
                'type': 'domain',
                'nmap': nmap_result,
                'gobuster_dir': gobuster_dir_result,
                'gobuster_dir_wordlist': dir_wordlist,
                'subfinder': subfinder_result,
                'fuzz': fuzz_results
            })
    try:
        with open('scan_results.txt', 'w', encoding='utf-8') as f:
            f.write("==============================\n")
            f.write(f"SurfaceHarvester Scan Report\n")
            f.write("==============================\n\n")
            f.write(f"Исходная цель: {target}\n\n")
            if not is_ip:
                f.write(f"[Контакты]\nТелефоны: {phones}\nПочта: {emails}\n\n")
            for res in all_results:
                f.write("------------------------------\n")
                f.write(f"Цель: {res['target']}\nТип: {res['type']}\n")
                if 'nmap' in res:
                    f.write("[Nmap]\n")
                    f.write(res['nmap'] + "\n")
                if 'gobuster_dir' in res:
                    f.write(f"[Gobuster Dir] (словарь: {res.get('gobuster_dir_wordlist','')})\n")
                    f.write(res['gobuster_dir'] + "\n")
                if 'subfinder' in res and res['subfinder']:
                    f.write("[Subfinder]\n")
                    for sub in res['subfinder']:
                        f.write(sub + "\n")
                if 'fuzz' in res and res['fuzz']:
                    for fuzz in res['fuzz']:
                        f.write(f"[Gobuster Fuzz] {fuzz['url']} (словарь: {fuzz['wordlist']})\n")
                        f.write(fuzz['result'] + "\n")
                f.write("\n")
            f.write("Конец отчёта\n")
        print("Результаты сохранены в scan_results.txt")
    except Exception as e:
        logging.error(f"Ошибка при сохранении отчёта: {e}")
        print(f"Ошибка при сохранении отчёта: {e}")

if __name__ == "__main__":
    asyncio.run(main())
