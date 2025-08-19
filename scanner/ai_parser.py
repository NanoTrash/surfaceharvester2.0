# scanner/ai_parser.py

import re
import json
from typing import List, Dict, Any
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Опциональные зависимости - импортируем только если доступны
try:
    import spacy
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False
    logger.warning("spaCy не установлен. Установите: pip install spacy && python -m spacy download en_core_web_sm")

try:
    import nltk
    from nltk.tokenize import word_tokenize
    from nltk.corpus import stopwords
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    logger.warning("NLTK не установлен. Установите: pip install nltk")

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn не установлен. Установите: pip install scikit-learn")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    logger.warning("pandas не установлен. Установите: pip install pandas")

# Инициализация spaCy
nlp = None
if SPACY_AVAILABLE:
    try:
        nlp = spacy.load("en_core_web_sm")
    except OSError:
        # Автоматическая установка модели (по умолчанию включена)
        import os
        auto_install = os.environ.get("SURFH2_AUTO_INSTALL_SPACY", "1") != "0"
        
        if auto_install:
            try:
                logger.info("spaCy model en_core_web_sm не найдена. Устанавливаю автоматически...")
                import subprocess
                import sys
                
                # Используем subprocess для установки через spacy download
                result = subprocess.run([
                    sys.executable, '-m', 'spacy', 'download', 'en_core_web_sm'
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    # Пробуем загрузить после установки
                    import importlib
                    importlib.reload(spacy)
                    nlp = spacy.load("en_core_web_sm")
                    logger.info("✅ spaCy model en_core_web_sm успешно установлена и загружена")
                else:
                    logger.error(f"Ошибка установки spaCy модели: {result.stderr}")
                    logger.warning("Модель spaCy en_core_web_sm не найдена. Установите вручную: python -m spacy download en_core_web_sm")
            except Exception as e:
                logger.warning(f"Не удалось автоматически установить spaCy модель: {e}")
                logger.warning("Установите вручную: python -m spacy download en_core_web_sm")
        else:
            logger.warning("Автоустановка отключена. Модель spaCy en_core_web_sm не найдена. Установите: python -m spacy download en_core_web_sm")

# Инициализация NLTK с автоматической установкой
if NLTK_AVAILABLE:
    import os  # для переменных окружения
    missing_nltk_data = []
    
    # Проверяем punkt
    try:
        nltk.data.find('tokenizers/punkt')
    except LookupError:
        missing_nltk_data.append('punkt')
    
    # Проверяем stopwords
    try:
        nltk.data.find('corpora/stopwords')
    except LookupError:
        missing_nltk_data.append('stopwords')
    
    # Устанавливаем недостающие данные
    if missing_nltk_data:
        auto_install = os.environ.get("SURFH2_AUTO_INSTALL_NLTK", "1") != "0"
        
        if auto_install:
            logger.info(f"NLTK данные не найдены: {missing_nltk_data}. Устанавливаю автоматически...")
            try:
                for dataset in missing_nltk_data:
                    nltk.download(dataset, quiet=True)
                logger.info("✅ NLTK данные успешно установлены")
            except Exception as e:
                logger.warning(f"Не удалось загрузить NLTK данные: {e}")
        else:
            logger.warning(f"Автоустановка NLTK отключена. Данные не найдены: {missing_nltk_data}")
            logger.warning("Установите вручную: python -c \"import nltk; nltk.download('punkt'); nltk.download('stopwords')\"")

class AIVulnerabilityParser:
    def __init__(self):
        self.vulnerability_patterns = {
            'SQL Injection': [
                'sql injection', 'sqli', 'sql injection vulnerability',
                'database injection', 'sql error', 'mysql error'
            ],
            'XSS': [
                'cross-site scripting', 'xss', 'reflected xss', 'stored xss',
                'dom xss', 'script injection'
            ],
            'LFI': [
                'local file inclusion', 'lfi', 'file inclusion',
                'path traversal', 'directory traversal'
            ],
            'RFI': [
                'remote file inclusion', 'rfi', 'remote file inclusion vulnerability'
            ],
            'SSRF': [
                'server-side request forgery', 'ssrf', 'server side request forgery'
            ],
            'LPE': [
                'local privilege escalation', 'lpe', 'privilege escalation',
                'elevation of privilege'
            ],
            'RCE': [
                'remote code execution', 'rce', 'code execution',
                'command injection', 'os command injection'
            ],
            'Path Traversal': [
                'path traversal', 'directory traversal', '../', '..\\',
                'dot dot slash', 'directory climbing'
            ],
            'CSRF': [
                'cross-site request forgery', 'csrf', 'request forgery'
            ],
            'Open Redirect': [
                'open redirect', 'redirect vulnerability', 'url redirection'
            ],
            'Information Disclosure': [
                'information disclosure', 'info disclosure', 'sensitive data exposure',
                'error message disclosure', 'stack trace'
            ],
            'Default Credentials': [
                'default credentials', 'default password', 'admin admin',
                'root root', 'default login'
            ],
            'Outdated Software': [
                'outdated', 'old version', 'deprecated', 'end of life',
                'eol', 'unsupported version'
            ]
        }
        
        self.severity_keywords = {
            'Critical': ['critical', 'severe', 'high risk', 'immediate'],
            'High': ['high', 'serious', 'important'],
            'Medium': ['medium', 'moderate', 'average'],
            'Low': ['low', 'minor', 'informational']
        }

    def extract_vulnerability_type(self, text: str) -> str:
        """
        Извлекает тип уязвимости из текста с помощью ИИ
        """
        if not text:
            return "Unknown"
        
        text_lower = text.lower()
        
        # Проверяем паттерны
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                if pattern in text_lower:
                    return vuln_type
        
        # Если паттерны не найдены и доступны ИИ-инструменты, используем их
        if SPACY_AVAILABLE and nlp and SKLEARN_AVAILABLE:
            try:
                # Анализируем текст с помощью spaCy
                doc = nlp(text)
                
                # Извлекаем ключевые слова
                keywords = [token.text.lower() for token in doc if not token.is_stop and token.is_alpha]
                
                # Создаем TF-IDF векторы для сравнения
                all_patterns = []
                pattern_labels = []
                
                for vuln_type, patterns in self.vulnerability_patterns.items():
                    for pattern in patterns:
                        all_patterns.append(pattern)
                        pattern_labels.append(vuln_type)
                
                if all_patterns:
                    vectorizer = TfidfVectorizer()
                    try:
                        # Векторизуем текст и паттерны
                        vectors = vectorizer.fit_transform([text] + all_patterns)
                        
                        # Вычисляем схожесть
                        similarities = cosine_similarity(vectors[0:1], vectors[1:])
                        
                        # Находим наиболее похожий паттерн
                        max_sim_idx = similarities.argmax()
                        max_similarity = similarities[0][max_sim_idx]
                        
                        if max_similarity > 0.3:  # Порог схожести
                            return pattern_labels[max_sim_idx]
                    except Exception as e:
                        logger.debug(f"Ошибка TF-IDF анализа: {e}")
            except Exception as e:
                logger.debug(f"Ошибка spaCy анализа: {e}")
        
        # Если ничего не найдено, возвращаем "Unknown"
        return "Unknown"

    def extract_severity(self, text: str) -> str:
        """
        Извлекает уровень критичности уязвимости
        """
        if not text:
            return "Medium"
        
        text_lower = text.lower()
        
        for severity, keywords in self.severity_keywords.items():
            for keyword in keywords:
                if keyword in text_lower:
                    return severity
        
        return "Medium"  # По умолчанию

    def extract_resource(self, text: str, scanner_output: Dict) -> str:
        """
        Извлекает ресурс (URL, IP, FQDN) из вывода сканера
        """
        # Пытаемся извлечь из структуры сканера
        if isinstance(scanner_output, dict):
            # Nuclei
            if 'host' in scanner_output:
                return scanner_output['host']
            if 'matched-at' in scanner_output:
                return scanner_output['matched-at']
            if 'ip' in scanner_output:
                return scanner_output['ip']
            
            # Nikto
            if 'hostname' in scanner_output:
                return scanner_output['hostname']
            if 'target' in scanner_output:
                return scanner_output['target']
        
        # Если не найдено в структуре, ищем в тексте
        # Паттерны для URL, IP, FQDN
        url_pattern = r'https?://[^\s]+'
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        fqdn_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
        
        urls = re.findall(url_pattern, text)
        if urls:
            return urls[0]
        
        ips = re.findall(ip_pattern, text)
        if ips:
            return ips[0]
        
        fqdns = re.findall(fqdn_pattern, text)
        if fqdns:
            return fqdns[0]
        
        return "Unknown"

    def parse_scanner_output(self, scanner_output: Any, scanner_name: str) -> List[Dict]:
        """
        Парсит вывод сканера и извлекает уязвимости с помощью ИИ
        """
        vulnerabilities = []
        
        try:
            if scanner_name == 'nuclei':
                vulnerabilities = self._parse_nuclei_output(scanner_output)
            elif scanner_name == 'nikto':
                vulnerabilities = self._parse_nikto_output(scanner_output)
            # elif scanner_name == 'wapiti':  # УДАЛЕНО: Wapiti больше не используется
            #     vulnerabilities = self._parse_wapiti_output(scanner_output)
            elif scanner_name == 'nmap':
                vulnerabilities = self._parse_nmap_output(scanner_output)
            elif scanner_name == 'gobuster':
                vulnerabilities = self._parse_gobuster_output(scanner_output)
            elif scanner_name == 'contacts':
                vulnerabilities = self._parse_contacts_output(scanner_output)
            else:
                vulnerabilities = self._parse_generic_output(scanner_output, scanner_name)
        except Exception as e:
            logger.error(f"Ошибка парсинга вывода {scanner_name}: {e}")
            return []
        
        return vulnerabilities

    def _parse_contacts_output(self, output: Dict) -> List[Dict]:
        """
        Парсит результаты извлечения контактов (emails, phones)
        Ожидаемый формат:
        {
            'emails': [...],
            'phones': [...],
            'target': 'http://example.com'
        }
        """
        vulnerabilities: List[Dict] = []
        if not isinstance(output, dict):
            logger.warning("Contacts output не является dict")
            return vulnerabilities
        target = output.get('target', 'Unknown')
        emails = output.get('emails') or []
        phones = output.get('phones') or []
        
        logger.info(f"Contacts парсер: найдено {len(emails)} email и {len(phones)} телефонов для {target}")
        for em in emails:
            try:
                vulnerabilities.append({
                    'resource': target,
                    'vulnerability_type': 'Contact: Email',
                    'description': f"Email found: {em}",
                    'severity': 'Info',
                    'scanner': 'contacts'
                })
            except Exception:
                continue
        for ph in phones:
            try:
                vulnerabilities.append({
                    'resource': target,
                    'vulnerability_type': 'Contact: Phone',
                    'description': f"Phone found: {ph}",
                    'severity': 'Info',
                    'scanner': 'contacts'
                })
            except Exception:
                continue
        return vulnerabilities

    def _parse_nuclei_output(self, output: List[Dict]) -> List[Dict]:
        """
        Парсит вывод Nuclei
        """
        vulnerabilities = []
        
        if not isinstance(output, list):
            logger.warning("Nuclei output is not a list")
            return vulnerabilities
        
        for finding in output:
            if isinstance(finding, dict):
                try:
                    # Извлекаем информацию
                    resource = self.extract_resource(str(finding), finding)
                    description = finding.get('info', {}).get('name', '')
                    severity = finding.get('info', {}).get('severity', 'Medium')
                    
                    # Определяем тип уязвимости
                    vuln_type = self.extract_vulnerability_type(description)
                    
                    # Проверяем CVE
                    cve_list = finding.get('info', {}).get('cve', [])
                    if cve_list:
                        first = str(cve_list[0])
                        vuln_type = first if first.upper().startswith("CVE-") else f"CVE-{first}"
                    
                    vulnerabilities.append({
                        'resource': resource,
                        'vulnerability_type': vuln_type,
                        'description': description,
                        'severity': severity,
                        'scanner': 'nuclei'
                    })
                except Exception as e:
                    logger.warning(f"Ошибка обработки Nuclei finding: {e}")
                    continue
        
        return vulnerabilities

    def _parse_nikto_output(self, output: Dict) -> List[Dict]:
        """
        Парсит вывод Nikto
        """
        vulnerabilities = []
        
        if not isinstance(output, dict):
            logger.warning("Nikto output is not a dict")
            return vulnerabilities
        
        vuln_list = output.get('vulnerabilities', [])
        
        for vuln in vuln_list:
            if isinstance(vuln, dict):
                try:
                    # Извлекаем информацию
                    resource = self.extract_resource(str(vuln), vuln)
                    description = vuln.get('description', '')
                    severity = vuln.get('severity', 'Medium')
                    
                    # Определяем тип уязвимости
                    vuln_type = self.extract_vulnerability_type(description)
                    
                    # Проверяем OSVDB ID
                    osvdb_id = vuln.get('osvdb_id')
                    if osvdb_id:
                        vuln_type = f"OSVDB-{osvdb_id}"
                    
                    vulnerabilities.append({
                        'resource': resource,
                        'vulnerability_type': vuln_type,
                        'description': description,
                        'severity': severity,
                        'scanner': 'nikto'
                    })
                except Exception as e:
                    logger.warning(f"Ошибка обработки Nikto vulnerability: {e}")
                    continue
        
        return vulnerabilities
    
    # УДАЛЕНО: Wapiti больше не используется
    # def _parse_wapiti_output(self, output: Dict) -> List[Dict]:
    #     """
    #     Парсит вывод Wapiti
    #     """
    #     vulnerabilities = []
    #     
    #     try:
    #         # Получаем список уязвимостей из структуры
    #         vuln_list = []
    #         if isinstance(output, dict):
    #             vuln_list = output.get('vulnerabilities', [])
    #             target = output.get('target', 'Unknown')
    #         else:
    #             vuln_list = output if isinstance(output, list) else []
    #             target = 'Unknown'
    #         
    #         for vuln in vuln_list:
    #             if isinstance(vuln, dict):
    #                 # Извлекаем информацию
    #                 resource = vuln.get('resource', target)
    #                 description = vuln.get('description', '')
    #                 severity = vuln.get('severity', 'Medium')
    #                 
    #                 # Определяем тип уязвимости
    #                 vuln_type = self.extract_vulnerability_type(description)
    #                 
    #                 vulnerabilities.append({
    #                     'resource': resource,
    #                     'vulnerability_type': vuln_type,
    #                     'description': description,
    #                     'severity': severity,
    #                     'scanner': 'wapiti'
    #                 })
    #                 
    #     except Exception as e:
    #         logger.error(f"Ошибка парсинга Wapiti: {e}")
    #     
    #     return vulnerabilities
    
    def _parse_nmap_output(self, output: Dict) -> List[Dict]:
        """
        Парсит вывод Nmap
        """
        vulnerabilities = []
        
        try:
            nmap_text = output.get('output', '') if isinstance(output, dict) else str(output)
            target = output.get('target', 'Unknown') if isinstance(output, dict) else 'Unknown'
            
            logger.info(f"Nmap парсер: анализирую {len(nmap_text)} символов вывода для {target}")
            
            lines = nmap_text.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Ищем CVE и уязвимости
                if any(pattern in line.lower() for pattern in ['cve-', 'vulnerable', 'exploit', 'vulners']):
                    # Извлекаем CVE ID
                    cve_match = re.search(r'CVE-\d{4}-\d+', line)
                    if cve_match:
                        cve_id = cve_match.group(0)
                        vuln_type = f"CVE: {cve_id}"
                    else:
                        vuln_type = self.extract_vulnerability_type(line) or "Nmap Vulnerability"
                    
                    # Извлекаем CVSS score для определения критичности
                    cvss_match = re.search(r'(\d+\.\d+)', line)
                    if cvss_match:
                        cvss_score = float(cvss_match.group(1))
                        if cvss_score >= 9.0:
                            severity = "Critical"
                        elif cvss_score >= 7.0:
                            severity = "High"
                        elif cvss_score >= 4.0:
                            severity = "Medium"
                        else:
                            severity = "Low"
                    else:
                        severity = self.extract_severity(line)
                    
                    vulnerabilities.append({
                        'resource': target,
                        'vulnerability_type': vuln_type,
                        'description': line[:500],  # Ограничиваем длину
                        'severity': severity,
                        'scanner': 'nmap'
                    })
                    
        except Exception as e:
            logger.error(f"Ошибка парсинга Nmap: {e}")
        
        logger.info(f"Nmap парсер нашёл {len(vulnerabilities)} уязвимостей для {target}")
        return vulnerabilities
    
    def _parse_gobuster_output(self, output: Dict) -> List[Dict]:
        """
        Парсит вывод Gobuster
        """
        vulnerabilities = []
        
        try:
            gobuster_text = output.get('output', '') if isinstance(output, dict) else str(output)
            target = output.get('target', 'Unknown') if isinstance(output, dict) else 'Unknown'
            
            lines = gobuster_text.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Ищем найденные пути с интересными статусами
                if any(status in line for status in ['Status: 200', 'Status: 301', 'Status: 302', 'Status: 403']):
                    parts = line.split()
                    if len(parts) >= 2:
                        path = parts[0]
                        status_info = ' '.join(parts[1:])
                        
                        # Определяем критичность на основе статуса и пути
                        if 'admin' in path.lower() or 'config' in path.lower() or 'backup' in path.lower():
                            severity = "Medium"
                            vuln_type = "Sensitive Directory Found"
                        elif '403' in status_info:
                            severity = "Low"
                            vuln_type = "Protected Directory Found"
                        else:
                            severity = "Info"
                            vuln_type = "Directory/File Found"
                        
                        vulnerabilities.append({
                            'resource': f"{target.rstrip('/')}/{path.lstrip('/')}",
                            'vulnerability_type': vuln_type,
                            'description': f"Found: {path} ({status_info})",
                            'severity': severity,
                            'scanner': 'gobuster'
                        })
                        
        except Exception as e:
            logger.error(f"Ошибка парсинга Gobuster: {e}")
        
        return vulnerabilities

    def _parse_generic_output(self, output: Any, scanner_name: str) -> List[Dict]:
        """
        Парсит вывод других сканеров
        """
        vulnerabilities = []
        
        try:
            # Преобразуем в строку для анализа
            output_str = str(output)
            
            # Извлекаем ресурс
            resource = self.extract_resource(output_str, {})
            
            # Определяем тип уязвимости
            vuln_type = self.extract_vulnerability_type(output_str)
            
            # Определяем критичность
            severity = self.extract_severity(output_str)
            
            vulnerabilities.append({
                'resource': resource,
                'vulnerability_type': vuln_type,
                'description': output_str[:200],  # Первые 200 символов
                'severity': severity,
                'scanner': scanner_name
            })
        except Exception as e:
            logger.error(f"Ошибка обработки generic output: {e}")
        
        return vulnerabilities

    def save_to_database(self, vulnerabilities: List[Dict], cursor) -> None:
        """
        Сохраняет уязвимости в базу данных
        """
        from db.models import Vulnerability
        
        for vuln in vulnerabilities:
            try:
                Vulnerability.insert(
                    cursor,
                    resource=vuln.get('resource', 'Unknown'),
                    vulnerability_type=vuln.get('vulnerability_type', 'Unknown'),
                    description=vuln.get('description', ''),
                    severity=vuln.get('severity', 'Medium'),
                    scanner=vuln.get('scanner', 'unknown')
                )
            except Exception as e:
                logger.error(f"Ошибка сохранения уязвимости в БД: {e}")
                continue
