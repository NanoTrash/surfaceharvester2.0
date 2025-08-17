# scanner/wapiti.py

import subprocess
import json
import os
import shlex
import logging
import re
from scanner.ai_parser import AIVulnerabilityParser

logger = logging.getLogger(__name__)

def validate_target(target):
    """
    Валидирует целевой URL для Wapiti
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

def check_wapiti_installed():
    """
    Проверяет, установлен ли Wapiti
    """
    try:
        result = subprocess.run(['wapiti', '--version'], 
                              capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def parse_wapiti_output(output_text):
    """
    Парсит текстовый вывод Wapiti в структурированный формат
    """
    findings = []
    
    # Паттерны для поиска уязвимостей в выводе Wapiti
    vuln_patterns = [
        r'\[CRITICAL\] (.*?)$',  # [CRITICAL] Vulnerability
        r'\[HIGH\] (.*?)$',      # [HIGH] Vulnerability
        r'\[MEDIUM\] (.*?)$',    # [MEDIUM] Vulnerability
        r'\[LOW\] (.*?)$',       # [LOW] Vulnerability
        r'\[INFO\] (.*?)$',      # [INFO] Vulnerability
    ]
    
    lines = output_text.split('\n')
    for line in lines:
        line = line.strip()
        for pattern in vuln_patterns:
            match = re.match(pattern, line)
            if match:
                vuln_type = match.group(1)
                severity = pattern.split('[')[1].split(']')[0]
                
                findings.append({
                    'vulnerability_type': vuln_type,
                    'description': f"Wapiti {severity} finding: {vuln_type}",
                    'severity': severity,
                    'scanner': 'wapiti'
                })
                break
    
    return findings

def run_wapiti(target, temp_dir=None):
    """
    Запускает Wapiti сканирование
    """
    if not check_wapiti_installed():
        logger.error("Wapiti не установлен")
        return None
    
    try:
        # Валидация target
        target = validate_target(target)
        
        # Создаем временную директорию если не передана
        if not temp_dir:
            import tempfile
            temp_dir = tempfile.mkdtemp(prefix="wapiti_")
        
        # Путь к файлу результатов
        output_file = os.path.join(temp_dir, "wapiti_output.txt")
        
        # Безопасное выполнение команды
        cmd = ['wapiti', '-u', target, '-f', 'txt', '-o', output_file]
        
        logger.info(f"Запуск wapiti: {' '.join(cmd)}")
        
        # Запуск с таймаутом
        result = subprocess.run(cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=600,  # 10 минут таймаут
                              check=False)  # Не вызываем исключение при ненулевом коде
        
        if result.returncode != 0:
            logger.warning(f"Wapiti завершился с кодом {result.returncode}")
            if result.stderr:
                logger.warning(f"Wapiti stderr: {result.stderr}")
        
        # Проверяем, создался ли файл результатов
        if not os.path.exists(output_file):
            logger.warning(f"Файл результатов Wapiti не найден: {output_file}")
            # Парсим stdout как fallback
            return parse_wapiti_output(result.stdout)
        
        # Читаем результаты из файла
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if not content.strip():
            logger.warning("Файл результатов Wapiti пуст")
            return parse_wapiti_output(result.stdout)
        
        # Парсим текстовый вывод
        findings = parse_wapiti_output(content)
        return findings
        
    except subprocess.TimeoutExpired:
        logger.error(f"Wapiti превысил таймаут для {target}")
        return None
    except ValueError as e:
        logger.error(f"Ошибка валидации: {e}")
        return None
    except Exception as e:
        logger.error(f"Ошибка при запуске Wapiti: {e}")
        return None

def process_wapiti_result(data, cursor, session_id):
    """
    Обрабатывает результат Wapiti и сохраняет в базу данных
    """
    if not data:
        logger.warning("Нет данных Wapiti для обработки")
        return
    
    try:
        # Сохраняем в базу данных
        from db.models import Vulnerability
        for finding in data:
            if isinstance(finding, dict):
                Vulnerability.insert(
                    cursor,
                    resource=finding.get('resource', 'Unknown'),
                    vulnerability_type=finding.get('vulnerability_type', 'Wapiti Finding'),
                    description=finding.get('description', ''),
                    severity=finding.get('severity', 'Medium'),
                    scanner=finding.get('scanner', 'wapiti')
                )
        
        logger.info(f"Обработано {len(data)} уязвимостей Wapiti")
        
    except Exception as e:
        logger.error(f"Ошибка обработки результатов Wapiti: {e}")

def parse_and_import_wapiti(data, cursor):
    """
    Устаревшая функция - используйте process_wapiti_result
    """
    print("[WARNING] parse_and_import_wapiti устарела, используйте process_wapiti_result")
    return process_wapiti_result(data, cursor, None)
