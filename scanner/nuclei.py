# scanner/nuclei.py

import subprocess
import json
import shlex
import logging
from scanner.ai_parser import AIVulnerabilityParser
import time
import select
import os

logger = logging.getLogger(__name__)

def validate_target(target):
    """
    Валидирует целевой URL для Nuclei
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

def check_nuclei_installed():
    """
    Проверяет, установлен ли Nuclei
    """
    try:
        result = subprocess.run(['nuclei', '-version'], 
                              capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def run_nuclei(target):
    """
    Запускает Nuclei сканирование
    """
    if not check_nuclei_installed():
        logger.error("Nuclei не установлен")
        return None
    
    try:
        # Используем правильный флаг -jsonl вместо -json
        cmd = ['nuclei', '-u', target, '-jsonl', '-silent']
        logger.info(f"Запуск nuclei: {' '.join(cmd)}")
        
        # Потоковый запуск с мониторингом неактивности
        hard_timeout = int(os.environ.get('SURFH2_NUCLEI_TIMEOUT', '3000'))
        inactivity_limit = int(os.environ.get('SURFH2_NUCLEI_INACTIVITY_SECONDS', '1200'))
        start_time = time.time()
        last_active = time.time()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        lines = []
        try:
            while True:
                if proc.stdout is None:
                    break
                rlist, _, _ = select.select([proc.stdout], [], [], 1.0)
                if rlist:
                    line = proc.stdout.readline()
                    if not line:
                        if proc.poll() is not None:
                            break
                        continue
                    lines.append(line)
                    last_active = time.time()
                else:
                    now = time.time()
                    if now - start_time > hard_timeout:
                        logger.warning(f"Nuclei превысил общий таймаут {hard_timeout}s. Прерываю...")
                        try:
                            proc.kill()
                        except Exception:
                            pass
                        break
                    if now - last_active > inactivity_limit:
                        logger.warning(f"Nuclei не выводит данных более {inactivity_limit}s. Прерываю...")
                        try:
                            proc.kill()
                        except Exception:
                            pass
                        break
                if proc.poll() is not None:
                    try:
                        remaining = proc.stdout.read() if proc.stdout else ''
                        if remaining:
                            lines.append(remaining)
                    except Exception:
                        pass
                    break
        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass

        # Парсим JSONL
        findings = []
        for line in ''.join(lines).strip().split('\n'):
            if line.strip():
                try:
                    finding = json.loads(line)
                    findings.append(finding)
                except json.JSONDecodeError as e:
                    logger.warning(f"Не удалось парсить строку Nuclei: {e}")
                    logger.warning(f"Строка: {line}")
        
        return findings
        
    except subprocess.TimeoutExpired:
        logger.error(f"Nuclei превысил таймаут для {target}")
        return None
    except Exception as e:
        logger.error(f"[Nuclei error for {target}]: {e}")
        return None

def process_nuclei_result(data, cursor, session_id, target_resource=None):
    """
    Обрабатывает результаты Nuclei и сохраняет в базу данных через VulnerabilityManager
    """
    if not data:
        logger.warning("Нет данных Nuclei для обработки")
        return
    
    try:
        from db.vulnerability_manager import VulnerabilityManager
        
        # Создаем менеджер уязвимостей
        vuln_manager = VulnerabilityManager()
        
        # Обрабатываем и сохраняем данные
        stats = vuln_manager.process_and_save_vulnerabilities(
            raw_data=data,
            scanner_name='nuclei',
            cursor=cursor,
            session_id=session_id,
            target_resource=target_resource
        )
        
        logger.info(f"Nuclei: обработано {stats.processed}, сохранено {stats.saved_new}, пропущено дубликатов {stats.duplicates_skipped}")
        return stats
        
    except Exception as e:
        logger.error(f"Ошибка обработки результатов Nuclei: {e}")
        return None

def parse_and_import_nuclei(data, cursor):
    """
    Устаревшая функция - используйте process_nuclei_result
    """
    print("[WARNING] parse_and_import_nuclei устарела, используйте process_nuclei_result")
    return process_nuclei_result(data, cursor, None)
