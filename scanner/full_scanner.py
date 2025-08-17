# scanner/full_scanner.py

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
import sqlite3
from datetime import datetime

from scanner.wapiti import run_wapiti, process_wapiti_result
from scanner.nuclei import run_nuclei, process_nuclei_result
from scanner.ai_parser import AIVulnerabilityParser
from db.schema import setup_database
from db.models import ScanSession, Vulnerability

logger = logging.getLogger(__name__)

class FullScanner:
    """
    Полный сканер, включающий все инструменты: nmap, gobuster, subfinder, nikto, nuclei
    """
    
    def __init__(self, temp_dir=None):
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.ai_parser = AIVulnerabilityParser()
        
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
        
        # Дополнительная проверка на потенциально опасные символы
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']']
        for char in dangerous_chars:
            if char in target:
                raise ValueError(f"Target contains dangerous character: {char}")
        
        return True
    
    def check_tool_installed(self, tool_name: str) -> bool:
        """Проверяет, установлен ли инструмент"""
        try:
            # Разные флаги для разных инструментов
            version_flags = {
                'nmap': ['-V'],
                'wapiti': ['--version'],
                'nuclei': ['-version'],
                'subfinder': ['-version'],
                'gobuster': ['version']
            }
            
            flag = version_flags.get(tool_name, ['--version'])
            result = subprocess.run([tool_name] + flag, 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def run_nmap_scan(self, target):
        """
        Запускает Nmap сканирование
        """
        if not self.check_tool_installed('nmap'):
            logger.error("Nmap не установлен")
            return None
        
        try:
            # Извлекаем домен из URL для Nmap
            domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            cmd = ['nmap', '-A', '--script', 'vulners', '--script-args', 'mincvss=3', domain]
            logger.info(f"Запуск nmap: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=300,  # 5 минут
                                  check=False)
            
            if result.returncode != 0:
                logger.warning(f"Nmap завершился с кодом {result.returncode}")
                if result.stderr:
                    logger.warning(f"Nmap stderr: {result.stderr}")
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap превысил таймаут для {target}")
            return None
        except Exception as e:
            logger.error(f"Ошибка при запуске Nmap: {e}")
            return None
    
    def run_gobuster_dir(self, target: str, wordlist: str) -> str:
        """
        Запускает gobuster для поиска директорий
        """
        if not self.check_tool_installed('gobuster'):
            logger.error("Gobuster не установлен")
            return f"[ERROR] Gobuster не установлен для {target}"
        
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
        if not self.check_tool_installed('subfinder'):
            logger.error("Subfinder не установлен")
            return [f"[ERROR] Subfinder не установлен для {target}"]
        
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
                async with session.get(url, timeout=10) as response:
                    text = await response.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    
                    # Поиск email адресов
                    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', str(soup))
                    emails = list(set(emails))  # Убираем дубликаты
                    
                    # Поиск телефонов
                    phones = re.findall(r'\+\d[\d\s()+-]+', str(soup))
                    phones = list(set(phones))  # Убираем дубликаты
                    
                    logger.info(f"Найдено {len(emails)} email и {len(phones)} телефонов на {url}")
                    return emails, phones
                    
        except Exception as e:
            logger.error(f"[Extract contacts error for {url}]: {e}")
            return [], []
    
    def run_gobuster_fuzz(self, target_url: str, wordlist: str) -> str:
        """
        Запускает gobuster fuzz для поиска параметров
        """
        if not self.check_tool_installed('gobuster'):
            logger.error("Gobuster не установлен")
            return f"[ERROR] Gobuster не установлен для {target_url}"
        
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
        """Проверяет, является ли цель IP адресом"""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))
    
    def save_nmap_vulnerabilities(self, nmap_output: str, cursor, session_id: int, target: str):
        """
        Сохраняет уязвимости из nmap в базу данных
        """
        try:
            # Парсим nmap вывод на предмет уязвимостей
            lines = nmap_output.split('\n')
            cve_count = 0
            
            for line in lines:
                line = line.strip()
                
                # Ищем CVE в различных форматах
                if any(pattern in line for pattern in ['CVE-', 'VULNERABLE', 'EXPLOIT', 'vulners']):
                    # Извлекаем CVE ID
                    cve_match = re.search(r'CVE-\d{4}-\d+', line)
                    if cve_match:
                        cve_id = cve_match.group(0)
                        vulnerability_type = f"Nmap CVE: {cve_id}"
                    else:
                        vulnerability_type = "Nmap Vulnerability"
                    
                    # Извлекаем CVSS score
                    cvss_match = re.search(r'(\d+\.\d+)', line)
                    cvss_score = float(cvss_match.group(1)) if cvss_match else 5.0
                    
                    # Определяем критичность по CVSS
                    if cvss_score >= 9.0:
                        severity = "Critical"
                    elif cvss_score >= 7.0:
                        severity = "High"
                    elif cvss_score >= 4.0:
                        severity = "Medium"
                    else:
                        severity = "Low"
                    
                    # Ограничиваем длину описания
                    description = line[:500] if len(line) > 500 else line
                    
                    # Сохраняем в БД
                    Vulnerability.insert(
                        cursor,
                        resource=target,
                        vulnerability_type=vulnerability_type,
                        description=description,
                        severity=severity,
                        scanner="nmap"
                    )
                    cve_count += 1
            
            logger.info(f"Сохранено {cve_count} уязвимостей Nmap")
                    
        except Exception as e:
            logger.error(f"Ошибка сохранения nmap уязвимостей: {e}")
    
    def save_gobuster_findings(self, gobuster_output: str, cursor, session_id: int, target: str):
        """
        Сохраняет находки gobuster в базу данных
        """
        try:
            lines = gobuster_output.split('\n')
            for line in lines:
                if line.strip() and not line.startswith('Gobuster'):
                    # Извлекаем найденные пути
                    if 'Status: 200' in line or 'Status: 301' in line or 'Status: 302' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            path = parts[0]
                            status = parts[1] if len(parts) > 1 else "Unknown"
                            
                            Vulnerability.insert(
                                cursor,
                                resource=f"{target}{path}",
                                vulnerability_type="Directory/File Found",
                                description=f"Found: {path} (Status: {status})",
                                severity="Low",
                                scanner="gobuster"
                            )
                    
        except Exception as e:
            logger.error(f"Ошибка сохранения gobuster находок: {e}")
    
    async def full_scan(self, target: str, db_file="scan_results.db", 
                       dir_wordlist: str = None, fuzz_wordlist: str = None) -> Dict:
        """
        Полное сканирование цели всеми доступными инструментами
        """
        try:
            # Валидация
            self.validate_target(target)
            
            # Создаем временную директорию
            temp_dir = tempfile.mkdtemp(prefix="full_scanner_")
            
            # Подключение к БД
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Инициализация БД
            setup_database(cursor)
            conn.commit()
            
            # Создаем сессию сканирования
            ScanSession.insert(cursor, target=target, status="running")
            session_id = cursor.lastrowid
            conn.commit()
            
            print(f"[INFO] Начинаем полное сканирование {target}")
            print(f"[INFO] Сессия ID: {session_id}")
            print(f"[INFO] Временная директория: {temp_dir}")
            
            emails, phones, domains = [], [], set()
            all_results = []
            
            is_ip = self.is_ip_address(target)
            
            try:
                # 1. Nmap сканирование (всегда)
                print("\n[NMAP] Запуск Nmap...")
                nmap_result = self.run_nmap_scan(target)
                self.save_nmap_vulnerabilities(nmap_result, cursor, session_id, target)
                conn.commit()
                
                if is_ip:
                    all_results.append({
                        'target': target,
                        'type': 'ip',
                        'nmap': nmap_result
                    })
                else:
                    # Очищаем target от протокола
                    clean_target = target.replace("http://", "").replace("https://", "")
                    url = f"http://{clean_target}"
                    
                    # 2. Извлечение контактов
                    print("\n[CONTACTS] Извлечение контактов...")
                    emails, phones = await self.extract_contacts(url)
                    
                    # 3. Wapiti сканирование
                    print("\n[WAPITI] Запуск Wapiti...")
                    wapiti_data = run_wapiti(target, temp_dir)
                    if wapiti_data:
                        process_wapiti_result(wapiti_data, cursor, session_id)
                        conn.commit()
                    
                    # 4. Nuclei сканирование
                    print("\n[NUCLEI] Запуск Nuclei...")
                    nuclei_data = run_nuclei(target)
                    if nuclei_data:
                        process_nuclei_result(nuclei_data, cursor, session_id)
                        conn.commit()
                    
                    # 5. Subfinder сканирование
                    print("\n[SUBFINDER] Запуск Subfinder...")
                    subfinder_result = self.run_subfinder(clean_target)
                    
                    # 6. Gobuster dir сканирование (если есть словарь)
                    gobuster_dir_result = ""
                    if dir_wordlist:
                        print(f"\n[GOBUSTER DIR] Запуск Gobuster dir с {dir_wordlist}...")
                        gobuster_dir_result = self.run_gobuster_dir(clean_target, dir_wordlist)
                        self.save_gobuster_findings(gobuster_dir_result, cursor, session_id, target)
                        conn.commit()
                    
                    # 7. Gobuster fuzz сканирование (если есть словарь)
                    fuzz_results = []
                    if fuzz_wordlist and gobuster_dir_result:
                        print(f"\n[GOBUSTER FUZZ] Поиск параметров для фаззинга...")
                        for line in gobuster_dir_result.splitlines():
                            if '?' in line and '=' in line:
                                path = line.split()[0] if line.split() else line
                                if '=' in path:
                                    param_path = path.split('=')[0] + '=FUZZ'
                                    fuzz_url = f"http://{clean_target}{param_path}"
                                    print(f"  Фаззинг: {fuzz_url}")
                                    fuzz_output = self.run_gobuster_fuzz(fuzz_url, fuzz_wordlist)
                                    fuzz_results.append({
                                        'url': fuzz_url, 
                                        'result': fuzz_output, 
                                        'wordlist': fuzz_wordlist
                                    })
                    
                    all_results.append({
                        'target': clean_target,
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
                
                # Завершаем сессию
                ScanSession.update(cursor, session_id, end_time=datetime.now().isoformat(), status="completed")
                conn.commit()
                
                print(f"\n[SUCCESS] Полное сканирование завершено успешно!")
                
                return {
                    'original_target': target,
                    'is_ip': is_ip,
                    'contacts': {
                        'emails': emails,
                        'phones': phones
                    },
                    'results': all_results,
                    'session_id': session_id
                }
                
            except Exception as e:
                print(f"[ERROR] Ошибка во время сканирования: {e}")
                ScanSession.update(cursor, session_id, end_time=datetime.now().isoformat(), status="failed")
                conn.commit()
                raise
                
            finally:
                conn.close()
                # Очищаем временные файлы
                try:
                    import shutil
                    shutil.rmtree(temp_dir)
                    print(f"[INFO] Временная директория очищена: {temp_dir}")
                except Exception as e:
                    print(f"[WARNING] Не удалось очистить временную директорию: {e}")
            
        except Exception as e:
            logger.error(f"Ошибка полного сканирования {target}: {e}")
            raise
