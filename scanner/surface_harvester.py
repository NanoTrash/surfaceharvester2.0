# scanner/surface_harvester.py

import subprocess
import re
import aiohttp
import asyncio
import logging
from bs4 import BeautifulSoup
import os
import tempfile
from typing import List, Dict, Tuple, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SurfaceHarvester:
    """
    Класс для сбора информации о поверхности (порты, директории, субдомены, контакты)
    """
    
    def __init__(self, temp_dir=None):
        self.temp_dir = temp_dir or tempfile.gettempdir()
        
    def validate_wordlist(self, wordlist_path: str) -> bool:
        """Валидирует путь к словарю"""
        if not os.path.isfile(wordlist_path):
            logger.error(f"Wordlist file not found: {wordlist_path}")
            raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")
        return True
    
    def validate_target(self, target: str) -> bool:
        """Валидирует целевой адрес"""
        if not target:
            logger.error("Target is empty")
            raise ValueError("Target cannot be empty")
        return True
    
    def check_tool_installed(self, tool_name: str) -> bool:
        """Проверяет, установлен ли инструмент"""
        try:
            result = subprocess.run([tool_name, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def run_nmap_scan(self, target: str) -> str:
        """
        Запускает nmap сканирование с проверкой уязвимостей
        """
        try:
            # Извлекаем домен из URL для Nmap
            domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            cmd = [
                'nmap', "-A", "--script", "vulners", 
                "--script-args", "mincvss=3", domain
            ]
            logger.info(f"Запуск nmap: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=600,  # 10 минут
                                  check=False)
            
            if result.returncode != 0:
                logger.warning(f"Nmap завершился с кодом {result.returncode}")
                if result.stderr:
                    logger.warning(f"Nmap stderr: {result.stderr}")
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap превысил таймаут для {target}")
            return f"[ERROR] Nmap превысил таймаут для {target}"
        except Exception as e:
            logger.error(f"[Nmap error for {target}]: {e}")
            return f"[Nmap error for {target}]: {e}\n"
    
    def run_gobuster_dir(self, target: str, wordlist: str) -> str:
        """
        Запускает gobuster для поиска директорий
        """
        url = target if target.startswith('http') else f"http://{target}"
        
        try:
            cmd = [
                'gobuster', 'dir',
                '-u', url,
                '-w', wordlist,
                '-t', '50'
            ]
            logger.info(f"Запуск gobuster dir: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=300,  # 5 минут
                                  check=False)
            
            if result.returncode != 0:
                logger.warning(f"Gobuster завершился с кодом {result.returncode}")
                if result.stderr:
                    logger.warning(f"Gobuster stderr: {result.stderr}")
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.error(f"Gobuster превысил таймаут для {target}")
            return f"[ERROR] Gobuster превысил таймаут для {target}"
        except Exception as e:
            logger.error(f"[Gobuster dir error for {target}]: {e}")
            return f"[Gobuster dir error for {target}]: {e}\n"
    
    def run_subfinder(self, target: str) -> List[str]:
        """
        Запускает subfinder для поиска субдоменов
        """
        try:
            cmd = ['subfinder', '-d', target, '-silent']
            logger.info(f"Запуск subfinder: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=300,  # 5 минут
                                  check=False)
            
            if result.returncode != 0:
                logger.warning(f"Subfinder завершился с кодом {result.returncode}")
                if result.stderr:
                    logger.warning(f"Subfinder stderr: {result.stderr}")
            
            subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            return subdomains
            
        except subprocess.TimeoutExpired:
            logger.error(f"Subfinder превысил таймаут для {target}")
            return [f"[ERROR] Subfinder превысил таймаут для {target}"]
        except Exception as e:
            logger.error(f"[Subfinder error for {target}]: {e}")
            return [f"[Subfinder error for {target}]: {e}"]
    
    async def extract_contacts(self, url: str) -> Tuple[List[str], List[str]]:
        """
        Асинхронно извлекает адреса электронной почты и телефоны из веб-страницы
        """
        try:
            async with aiohttp.ClientSession() as session:
                # Некоторые тестовые моки возвращают не контекст-менеджер.
                # Пробуем как контекст-менеджер, при ошибке — обычный await.
                response_ctx = session.get(url, timeout=10)
                try:
                    async with response_ctx as response:
                        text = await response.text()
                except TypeError:
                    response = await response_ctx
                    text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                
                # Поиск email адресов
                visible_text = soup.get_text(" ") if soup else text
                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', visible_text)
                emails = list(set(emails))  # Убираем дубликаты
                
                # Поиск телефонов с нормализацией
                def normalize_phones(raw_text: str) -> List[str]:
                    candidates = re.findall(r'(\+?\d[\d\-\s\(\)]{6,}\d)', raw_text)
                    normalized: List[str] = []
                    for cand in candidates:
                        c = cand.replace('\r', ' ').replace('\n', ' ')
                        c = re.sub(r'[^0-9+]', '', c)
                        if '+' in c and not c.startswith('+'):
                            c = c.replace('+', '')
                        if c.count('+') > 1:
                            c = '+' + c.replace('+', '')
                        digits = re.sub(r'\D', '', c)
                        if len(digits) < 7 or len(digits) > 15:
                            continue
                        phone = ('+' + digits) if c.startswith('+') else digits
                        normalized.append(phone)
                    uniq = sorted(set(normalized), key=lambda x: (len(x), x))
                    return uniq
                phones = normalize_phones(visible_text)
                
                logger.info(f"Найдено {len(emails)} email и {len(phones)} телефонов на {url}")
                return emails, phones
                    
        except Exception as e:
            logger.error(f"[Extract contacts error for {url}]: {e}")
            return [], []
    
    def run_gobuster_fuzz(self, target_url: str, wordlist: str) -> str:
        """
        Запускает gobuster fuzz для поиска параметров
        """
        try:
            cmd = [
                'gobuster', 'fuzz',
                '-u', target_url,
                '-w', wordlist,
                '-t', '50'
            ]
            logger.info(f"Запуск gobuster fuzz: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=300,  # 5 минут
                                  check=False)
            
            if result.returncode != 0:
                logger.warning(f"Gobuster fuzz завершился с кодом {result.returncode}")
                if result.stderr:
                    logger.warning(f"Gobuster fuzz stderr: {result.stderr}")
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.error(f"Gobuster fuzz превысил таймаут для {target_url}")
            return f"[ERROR] Gobuster fuzz превысил таймаут для {target_url}"
        except Exception as e:
            logger.error(f"[Gobuster fuzz error for {target_url}]: {e}")
            return f"[Gobuster fuzz error for {target_url}]: {e}\n"
    
    def is_ip_address(self, target: str) -> bool:
        """Проверяет, является ли цель корректным IPv4 адресом"""
        if not target or not re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', target):
            return False
        parts = target.split('.')
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    async def scan_target(self, target: str, dir_wordlist: str, fuzz_wordlist: str = None) -> Dict:
        """
        Полный сканирование цели
        """
        try:
            # Валидация
            self.validate_target(target)
            self.validate_wordlist(dir_wordlist)
            if fuzz_wordlist:
                self.validate_wordlist(fuzz_wordlist)
            
            emails, phones, domains = [], [], set()
            all_results = []
            
            is_ip = self.is_ip_address(target)
            
            # Всегда запускаем nmap для исходного target
            logger.info(f"Запуск nmap для {target}")
            nmap_result = self.run_nmap_scan(target)
            
            if is_ip:
                all_results.append({
                    'target': target,
                    'type': 'ip',
                    'nmap': nmap_result
                })
            else:
                # Очищаем target от протокола
                target = target.replace("http://", "").replace("https://", "")
                url = f"http://{target}"
                
                # Извлекаем контакты
                logger.info(f"Извлечение контактов с {url}")
                emails, phones = await self.extract_contacts(url)
                
                # Извлекаем домены из email
                domains = set(email.split('@')[1] for email in emails if '@' in email)
                all_domains = list(domains.union({target}))
                
                for domain in all_domains:
                    logger.info(f"Сканирование домена: {domain}")
                    
                    # Nmap сканирование
                    nmap_result = self.run_nmap_scan(domain)
                    
                    # Gobuster dir сканирование
                    gobuster_dir_result = self.run_gobuster_dir(domain, dir_wordlist)
                    
                    # Поиск точек для фаззинга
                    fuzz_results = []
                    if fuzz_wordlist:
                        for line in gobuster_dir_result.splitlines():
                            if '?' in line and '=' in line:
                                path = line.split()[0] if line.split() else line
                                if '=' in path:
                                    param_path = path.split('=')[0] + '=FUZZ'
                                    base_url = domain if domain.startswith('http') else f'http://{domain}'
                                    fuzz_url = base_url.rstrip('/') + param_path
                                    logger.info(f"Фаззинг параметра: {fuzz_url}")
                                    fuzz_output = self.run_gobuster_fuzz(fuzz_url, fuzz_wordlist)
                                    fuzz_results.append({
                                        'url': fuzz_url, 
                                        'result': fuzz_output, 
                                        'wordlist': fuzz_wordlist
                                    })
                    
                    # Subfinder сканирование
                    subfinder_result = self.run_subfinder(domain)
                    
                    all_results.append({
                        'target': domain,
                        'type': 'domain',
                        'nmap': nmap_result,
                        'gobuster_dir': gobuster_dir_result,
                        'gobuster_dir_wordlist': dir_wordlist,
                        'subfinder': subfinder_result,
                        'fuzz': fuzz_results,
                        'contacts': {
                            'emails': emails,
                            'phones': phones
                        }
                    })
            
            return {
                'original_target': target,
                'is_ip': is_ip,
                'contacts': {
                    'emails': emails,
                    'phones': phones
                },
                'results': all_results
            }
            
        except Exception as e:
            logger.error(f"Ошибка сканирования {target}: {e}")
            raise
    
    def save_report(self, scan_data: Dict, output_file: str = 'scan_results.txt') -> str:
        """
        Сохраняет отчет в файл
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("==============================\n")
                f.write(f"SurfaceHarvester Scan Report\n")
                f.write("==============================\n\n")
                f.write(f"Исходная цель: {scan_data['original_target']}\n")
                f.write(f"Тип: {'IP' if scan_data['is_ip'] else 'Domain'}\n\n")
                
                if not scan_data['is_ip']:
                    contacts = scan_data['contacts']
                    f.write(f"[Контакты]\n")
                    f.write(f"Телефоны: {contacts['phones']}\n")
                    f.write(f"Почта: {contacts['emails']}\n\n")
                
                for res in scan_data['results']:
                    f.write("------------------------------\n")
                    f.write(f"Цель: {res['target']}\n")
                    f.write(f"Тип: {res['type']}\n")
                    
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
            
            logger.info(f"Отчет сохранен в {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Ошибка при сохранении отчёта: {e}")
            raise
