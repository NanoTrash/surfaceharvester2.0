#!/usr/bin/env python3
"""
Модуль для интеграции vulnx (cvemap) в пенетрационный фреймворк
Обрабатывает CVE, ищет эксплойты, кэширует результаты
"""

import json
import logging
import re
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import requests
import os

logger = logging.getLogger(__name__)

class VulnXProcessor:
    """Процессор для работы с vulnx и поиска эксплойтов"""
    
    def __init__(self, db_path: str = "scan_results.db", cache_days: int = 7):
        self.db_path = db_path
        self.cache_days = cache_days
        self.exploits_dir = Path("exploits")
        self.exploits_dir.mkdir(exist_ok=True)
        
        # Проверяем установку vulnx
        self._ensure_vulnx_installed()
        self._init_db_schema()
    
    def _ensure_vulnx_installed(self):
        """Проверяет и устанавливает vulnx если нужно"""
        try:
            # Простая проверка что vulnx доступен
            result = subprocess.run(['vulnx', '--help'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 or result.returncode == 1:  # help может возвращать 1
                logger.info(f"vulnx доступен: {result.stdout[:100]}...")
                return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        logger.warning("vulnx не найден или недоступен. Установите вручную:")
        logger.warning("go install -v github.com/projectdiscovery/cvemap/cmd/cvemap@latest")
        logger.warning("ln -s $(which cvemap) ~/go/bin/vulnx")
    
    def _init_db_schema(self):
        """Инициализирует схему БД для vulnx"""
        try:
            # Схема уже создается через models.py, просто проверяем что таблицы существуют
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Проверяем существование таблиц
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('exploits', 'cvecache', 'cveprocessing')")
            existing_tables = [row[0] for row in cursor.fetchall()]
            
            conn.close()
            
            if len(existing_tables) == 3:
                logger.info("Таблицы vulnx уже существуют в БД")
            else:
                logger.warning(f"Не все таблицы vulnx найдены. Найдено: {existing_tables}")
                logger.warning("Запустите: poetry run python cli.py init --db scan_results.db")
            
        except Exception as e:
            logger.error(f"Ошибка проверки схемы БД: {e}")
    
    def extract_cve_ids(self, vulnerability_text: str) -> List[str]:
        """Извлекает CVE идентификаторы из текста уязвимости"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, vulnerability_text.upper())
        return list(set(cves))  # убираем дубликаты
    
    def is_cache_valid(self, cve_id: str) -> Tuple[bool, Optional[Dict]]:
        """Проверяет актуальность кэша для CVE"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT vulnx_response, last_checked, is_stale 
                FROM cvecache 
                WHERE cve_id = ?
            """, (cve_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return False, None
            
            response_json, last_checked_str, is_stale = row
            
            if is_stale:
                return False, None
            
            last_checked = datetime.fromisoformat(last_checked_str)
            cache_age = datetime.now() - last_checked
            
            if cache_age > timedelta(days=self.cache_days):
                return False, None
            
            return True, json.loads(response_json)
            
        except Exception as e:
            logger.error(f"Ошибка проверки кэша для {cve_id}: {e}")
            return False, None
    
    def query_vulnx(self, cve_id: str) -> Optional[Dict]:
        """Запрашивает информацию о CVE через vulnx"""
        try:
            logger.info(f"Запрашиваю vulnx для {cve_id}...")
            
            # Базовый запрос информации о CVE
            cmd = ['vulnx', 'id', '--json', cve_id]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logger.warning(f"vulnx вернул код {result.returncode} для {cve_id}: {result.stderr}")
                return None
            
            if not result.stdout.strip():
                logger.warning(f"vulnx не вернул данных для {cve_id}")
                return None
            
            # Парсим JSON ответ
            try:
                data = json.loads(result.stdout)
                return data
            except json.JSONDecodeError as e:
                logger.error(f"Ошибка парсинга JSON от vulnx для {cve_id}: {e}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error(f"Таймаут запроса vulnx для {cve_id}")
            return None
        except Exception as e:
            logger.error(f"Ошибка запроса vulnx для {cve_id}: {e}")
            return None
    
    def search_exploits(self, cve_id: str) -> List[Dict]:
        """Ищет эксплойты для CVE через vulnx search"""
        try:
            logger.info(f"Ищу эксплойты для {cve_id}...")
            
            # Поиск эксплойтов
            search_queries = [
                f'cve_id:{cve_id} && is_poc:true',
                f'cve_id:{cve_id} && affected_products.vendor:*',
                f'{cve_id}'  # fallback простой поиск
            ]
            
            all_results = []
            
            for query in search_queries:
                try:
                    cmd = ['vulnx', 'search', '--json', '--limit', '50', query]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        search_data = json.loads(result.stdout)
                        
                        # vulnx может возвращать разные форматы
                        if isinstance(search_data, list):
                            all_results.extend(search_data)
                        elif isinstance(search_data, dict):
                            if 'data' in search_data:
                                all_results.extend(search_data['data'])
                            else:
                                all_results.append(search_data)
                
                except Exception as e:
                    logger.debug(f"Ошибка поиска по запросу '{query}': {e}")
                    continue
            
            # Дедупликация по CVE ID
            seen_cves = set()
            unique_results = []
            
            for item in all_results:
                item_cve = item.get('cve_id') or item.get('id')
                if item_cve and item_cve not in seen_cves:
                    seen_cves.add(item_cve)
                    unique_results.append(item)
            
            logger.info(f"Найдено {len(unique_results)} результатов для {cve_id}")
            return unique_results
            
        except Exception as e:
            logger.error(f"Ошибка поиска эксплойтов для {cve_id}: {e}")
            return []
    
    def extract_exploit_info(self, vulnx_data: Dict) -> List[Dict]:
        """Извлекает информацию об эксплойтах из ответа vulnx"""
        exploits = []
        
        # Обрабатываем различные форматы ответов vulnx
        if isinstance(vulnx_data, list):
            for item in vulnx_data:
                exploits.extend(self._parse_exploit_item(item))
        elif isinstance(vulnx_data, dict):
            exploits.extend(self._parse_exploit_item(vulnx_data))
        
        return exploits
    
    def _parse_exploit_item(self, item: Dict) -> List[Dict]:
        """Парсит отдельный элемент с информацией об эксплойте"""
        exploits = []
        
        try:
            cve_id = item.get('cve_id') or item.get('id')
            if not cve_id:
                return exploits
            
            # Основная информация об уязвимости
            base_info = {
                'cve_id': cve_id,
                'title': item.get('summary') or item.get('description', ''),
                'description': item.get('description') or item.get('summary', ''),
                'severity_score': self._calculate_severity_score(item),
                'metadata': item
            }
            
            # GitHub PoCs
            if 'poc_github' in item and item['poc_github']:
                for github_item in item['poc_github']:
                    exploit = base_info.copy()
                    exploit.update({
                        'exploit_type': 'poc',
                        'source': 'github',
                        'url': github_item.get('url') or github_item.get('html_url'),
                        'title': github_item.get('name') or github_item.get('full_name'),
                        'language': github_item.get('language', 'unknown').lower()
                    })
                    exploits.append(exploit)
            
            # ExploitDB
            if 'exploitdb' in item and item['exploitdb']:
                for edb_item in item['exploitdb']:
                    exploit = base_info.copy()
                    exploit.update({
                        'exploit_type': 'exploit',
                        'source': 'exploitdb',
                        'url': edb_item.get('url'),
                        'title': edb_item.get('title'),
                        'language': self._detect_language_from_title(edb_item.get('title', ''))
                    })
                    exploits.append(exploit)
            
            # Nuclei templates
            if 'nuclei_templates' in item and item['nuclei_templates']:
                for nuclei_item in item['nuclei_templates']:
                    exploit = base_info.copy()
                    exploit.update({
                        'exploit_type': 'nuclei_template',
                        'source': 'nuclei',
                        'url': nuclei_item.get('url'),
                        'title': nuclei_item.get('name') or nuclei_item.get('id'),
                        'language': 'yaml'
                    })
                    exploits.append(exploit)
            
            # Если нет конкретных эксплойтов, но есть PoC флаг
            if not exploits and item.get('is_poc'):
                exploit = base_info.copy()
                exploit.update({
                    'exploit_type': 'poc',
                    'source': 'unknown',
                    'language': 'unknown'
                })
                exploits.append(exploit)
                
        except Exception as e:
            logger.error(f"Ошибка парсинга эксплойта: {e}")
        
        return exploits
    
    def _calculate_severity_score(self, item: Dict) -> int:
        """Вычисляет приоритет эксплойта (0-10)"""
        score = 5  # базовый приоритет
        
        # CVSS score влияет на приоритет
        cvss = item.get('cvss_score') or item.get('cvss')
        if cvss:
            try:
                cvss_float = float(cvss)
                score += int(cvss_float / 2)  # 0-5 дополнительных баллов
            except:
                pass
        
        # Наличие работающих PoC повышает приоритет
        if item.get('is_poc'):
            score += 2
        
        # Критичность по severity
        severity = (item.get('severity') or '').lower()
        if severity == 'critical':
            score += 3
        elif severity == 'high':
            score += 2
        elif severity == 'medium':
            score += 1
        
        # KEV (Known Exploited Vulnerabilities) - максимальный приоритет
        if item.get('is_kev'):
            score += 3
        
        # Удаленная эксплуатация
        if item.get('is_remote'):
            score += 1
        
        return min(10, max(0, score))
    
    def _detect_language_from_title(self, title: str) -> str:
        """Определяет язык программирования по названию"""
        title_lower = title.lower()
        
        if any(lang in title_lower for lang in ['python', '.py']):
            return 'python'
        elif any(lang in title_lower for lang in ['bash', 'shell', '.sh']):
            return 'bash'
        elif any(lang in title_lower for lang in ['php', '.php']):
            return 'php'
        elif any(lang in title_lower for lang in ['javascript', 'js', '.js']):
            return 'javascript'
        elif any(lang in title_lower for lang in ['ruby', '.rb']):
            return 'ruby'
        elif any(lang in title_lower for lang in ['perl', '.pl']):
            return 'perl'
        elif any(lang in title_lower for lang in ['java', '.java']):
            return 'java'
        elif any(lang in title_lower for lang in [' c ', '.c']):
            return 'c'
        else:
            return 'unknown'
    
    def save_cache(self, cve_id: str, vulnx_response: Dict, exploits_count: int):
        """Сохраняет результат запроса в кэш"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO cvecache 
                (cve_id, vulnx_response, exploits_found, last_checked, is_stale)
                VALUES (?, ?, ?, ?, 0)
            """, (cve_id, json.dumps(vulnx_response), exploits_count, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Ошибка сохранения кэша для {cve_id}: {e}")
    
    def save_exploits(self, vulnerability_id: int, cve_id: str, exploits: List[Dict]):
        """Сохраняет найденные эксплойты в БД"""
        if not exploits:
            return
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for exploit in exploits:
                cursor.execute("""
                    INSERT OR REPLACE INTO exploits 
                    (vulnerability_id, cve_id, exploit_type, source, title, 
                     description, url, language, severity_score, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    vulnerability_id,
                    cve_id,
                    exploit.get('exploit_type'),
                    exploit.get('source'),
                    exploit.get('title'),
                    exploit.get('description'),
                    exploit.get('url'),
                    exploit.get('language'),
                    exploit.get('severity_score', 5),
                    json.dumps(exploit.get('metadata', {}))
                ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Сохранено {len(exploits)} эксплойтов для {cve_id}")
            
        except Exception as e:
            logger.error(f"Ошибка сохранения эксплойтов для {cve_id}: {e}")
    
    def update_processing_status(self, vulnerability_id: int, cve_id: str, 
                               status: str, vulnx_checked: bool = False, 
                               error_message: str = None):
        """Обновляет статус обработки CVE"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO cveprocessing 
                (vulnerability_id, cve_id, status, vulnx_checked, last_processed, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (vulnerability_id, cve_id, status, vulnx_checked, 
                  datetime.now().isoformat(), error_message))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Ошибка обновления статуса для {cve_id}: {e}")
    
    def process_vulnerability(self, vulnerability_id: int, vulnerability_text: str) -> Dict:
        """Обрабатывает одну уязвимость - основная функция модуля"""
        result = {
            'vulnerability_id': vulnerability_id,
            'processed_cves': [],
            'total_exploits': 0,
            'errors': []
        }
        
        try:
            # Извлекаем CVE ID из текста уязвимости
            cve_ids = self.extract_cve_ids(vulnerability_text)
            
            if not cve_ids:
                logger.debug(f"Не найдено CVE ID в уязвимости {vulnerability_id}")
                return result
            
            logger.info(f"Обрабатываю уязвимость {vulnerability_id} с CVE: {cve_ids}")
            
            for cve_id in cve_ids:
                try:
                    self.update_processing_status(vulnerability_id, cve_id, 'processing')
                    
                    # Проверяем кэш
                    is_cached, cached_data = self.is_cache_valid(cve_id)
                    
                    if is_cached and cached_data:
                        logger.info(f"Используем кэшированные данные для {cve_id}")
                        vulnx_data = cached_data
                    else:
                        # Запрашиваем vulnx
                        vulnx_data = self.query_vulnx(cve_id)
                        
                        if not vulnx_data:
                            # Пробуем поиск эксплойтов
                            search_results = self.search_exploits(cve_id)
                            if search_results:
                                vulnx_data = {'search_results': search_results}
                        
                        if vulnx_data:
                            # Сохраняем в кэш
                            exploits_preview = self.extract_exploit_info(vulnx_data)
                            self.save_cache(cve_id, vulnx_data, len(exploits_preview))
                    
                    if vulnx_data:
                        # Извлекаем информацию об эксплойтах
                        exploits = self.extract_exploit_info(vulnx_data)
                        
                        if exploits:
                            # Сохраняем эксплойты
                            self.save_exploits(vulnerability_id, cve_id, exploits)
                            result['total_exploits'] += len(exploits)
                            
                            logger.info(f"Найдено {len(exploits)} эксплойтов для {cve_id}")
                        else:
                            logger.info(f"Эксплойты для {cve_id} не найдены")
                        
                        self.update_processing_status(vulnerability_id, cve_id, 'completed', True)
                        result['processed_cves'].append({
                            'cve_id': cve_id,
                            'exploits_count': len(exploits),
                            'status': 'success'
                        })
                    else:
                        logger.warning(f"Не удалось получить данные для {cve_id}")
                        self.update_processing_status(vulnerability_id, cve_id, 'completed', True, 
                                                    "No data from vulnx")
                        result['processed_cves'].append({
                            'cve_id': cve_id,
                            'exploits_count': 0,
                            'status': 'no_data'
                        })
                
                except Exception as e:
                    error_msg = f"Ошибка обработки {cve_id}: {e}"
                    logger.error(error_msg)
                    result['errors'].append(error_msg)
                    self.update_processing_status(vulnerability_id, cve_id, 'failed', True, str(e))
                    
                    result['processed_cves'].append({
                        'cve_id': cve_id,
                        'exploits_count': 0,
                        'status': 'error',
                        'error': str(e)
                    })
                
                # Небольшая задержка между запросами
                time.sleep(1)
        
        except Exception as e:
            error_msg = f"Критическая ошибка обработки уязвимости {vulnerability_id}: {e}"
            logger.error(error_msg)
            result['errors'].append(error_msg)
        
        return result
    
    def get_pending_vulnerabilities(self, limit: int = 50) -> List[Tuple[int, str]]:
        """Получает список уязвимостей, которые ещё не обработаны vulnx"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Ищем уязвимости с CVE, которые не обработаны
            cursor.execute("""
                SELECT DISTINCT v.id, v.description
                FROM vulnerability v
                LEFT JOIN cveprocessing cp ON v.id = cp.vulnerability_id
                WHERE (v.description LIKE '%CVE-%' OR v.description LIKE '%cve-%')
                AND (cp.vulnerability_id IS NULL OR cp.status = 'failed')
                ORDER BY v.timestamp DESC
                LIMIT ?
            """, (limit,))
            
            results = cursor.fetchall()
            conn.close()
            
            return results
            
        except Exception as e:
            logger.error(f"Ошибка получения pending уязвимостей: {e}")
            return []
    
    def get_exploit_summary(self, vulnerability_id: int = None) -> Dict:
        """Получает сводку по найденным эксплойтам"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            where_clause = ""
            params = []
            if vulnerability_id:
                where_clause = "WHERE vulnerability_id = ?"
                params = [vulnerability_id]
            
            # Общая статистика
            cursor.execute(f"""
                SELECT 
                    COUNT(*) as total_exploits,
                    COUNT(DISTINCT cve_id) as unique_cves,
                    COUNT(DISTINCT vulnerability_id) as vulnerable_assets,
                    exploit_type,
                    source,
                    language
                FROM exploits 
                {where_clause}
                GROUP BY exploit_type, source, language
                ORDER BY COUNT(*) DESC
            """, params)
            
            stats = cursor.fetchall()
            
            # Топ CVE по количеству эксплойтов
            cursor.execute(f"""
                SELECT cve_id, COUNT(*) as exploit_count, AVG(severity_score) as avg_severity
                FROM exploits 
                {where_clause}
                GROUP BY cve_id
                ORDER BY COUNT(*) DESC, AVG(severity_score) DESC
                LIMIT 10
            """, params)
            
            top_cves = cursor.fetchall()
            
            conn.close()
            
            return {
                'stats': stats,
                'top_cves': top_cves
            }
            
        except Exception as e:
            logger.error(f"Ошибка получения сводки эксплойтов: {e}")
            return {'stats': [], 'top_cves': []}


def main():
    """Пример использования VulnXProcessor"""
    logging.basicConfig(level=logging.INFO)
    
    processor = VulnXProcessor()
    
    # Получаем pending уязвимости
    pending = processor.get_pending_vulnerabilities(10)
    
    print(f"Найдено {len(pending)} уязвимостей для обработки")
    
    for vuln_id, description in pending:
        print(f"\nОбрабатываю уязвимость {vuln_id}...")
        result = processor.process_vulnerability(vuln_id, description)
        
        print(f"  Обработано CVE: {len(result['processed_cves'])}")
        print(f"  Найдено эксплойтов: {result['total_exploits']}")
        
        if result['errors']:
            print(f"  Ошибки: {result['errors']}")


if __name__ == "__main__":
    main()
