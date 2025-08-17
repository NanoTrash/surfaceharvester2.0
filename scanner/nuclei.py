# scanner/nuclei.py

import subprocess
import json
import shlex
import logging
from scanner.ai_parser import AIVulnerabilityParser

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
        
        result = subprocess.run(cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=300,  # 5 минут
                              check=False)
        
        if result.returncode != 0:
            logger.warning(f"Nuclei завершился с кодом {result.returncode}")
            if result.stderr:
                logger.warning(f"Nuclei stderr: {result.stderr}")
        
        # Парсим JSONL (каждая строка - отдельный JSON)
        findings = []
        for line in result.stdout.strip().split('\n'):
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

def process_nuclei_result(data, cursor, session_id):
    """
    Обрабатывает результаты Nuclei и сохраняет в базу данных
    """
    if not data:
        logger.warning("Нет данных Nuclei для обработки")
        return
    
    try:
        from scanner.ai_parser import AIVulnerabilityParser
        parser = AIVulnerabilityParser()
        
        # Преобразуем данные Nuclei в стандартный формат
        vulnerabilities = []
        for finding in data:
            if isinstance(finding, dict):
                vuln = {
                    'resource': finding.get('host', 'Unknown'),
                    'vulnerability_type': finding.get('info', {}).get('name', 'Nuclei Finding'),
                    'description': finding.get('info', {}).get('description', ''),
                    'severity': finding.get('info', {}).get('severity', 'Medium'),
                    'scanner': 'nuclei'
                }
                vulnerabilities.append(vuln)
        
        # Сохраняем в базу данных
        from db.models import Vulnerability
        for vuln in vulnerabilities:
            Vulnerability.insert(
                cursor,
                resource=vuln['resource'],
                vulnerability_type=vuln['vulnerability_type'],
                description=vuln['description'],
                severity=vuln['severity'],
                scanner=vuln['scanner']
            )
        
        logger.info(f"Обработано {len(vulnerabilities)} уязвимостей Nuclei")
        
    except Exception as e:
        logger.error(f"Ошибка обработки результатов Nuclei: {e}")

def parse_and_import_nuclei(data, cursor):
    """
    Устаревшая функция - используйте process_nuclei_result
    """
    print("[WARNING] parse_and_import_nuclei устарела, используйте process_nuclei_result")
    return process_nuclei_result(data, cursor, None)
