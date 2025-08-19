# scanner/wapiti.py

import subprocess
import os
import shlex
import logging
import re
from scanner.ai_parser import AIVulnerabilityParser
import time
import uuid
import select

# Cross-process lock support
try:
    import fcntl  # POSIX locking
    HAS_FCNTL = True
except Exception:
    HAS_FCNTL = False

logger = logging.getLogger(__name__)

import json

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

def parse_wapiti_output(output_text, target_url=None):
    """
    Парсит текстовый вывод Wapiti в структурированный формат
    """
    findings = []
    
    if not output_text or not output_text.strip():
        return findings
    
    # Если нет уязвимостей в выводе, не создаём артефакты
    has_vulnerabilities = any(keyword in output_text.lower() for keyword in [
        'vulnerability', 'vuln', 'alert', 'error', 'warning', 'found', 'detected'
    ])
    
    if not has_vulnerabilities:
        logger.info(f"Текстовый парсер не нашёл индикаторов уязвимостей в выводе для {target_url}")
        return findings
    
    # Паттерны для поиска уязвимостей в выводе Wapiti
    vuln_patterns = [
        r'\[CRITICAL\] (.*?)$',  # [CRITICAL] Vulnerability
        r'\[HIGH\] (.*?)$',      # [HIGH] Vulnerability
        r'\[MEDIUM\] (.*?)$',    # [MEDIUM] Vulnerability
        r'\[LOW\] (.*?)$',       # [LOW] Vulnerability
        r'\[INFO\] (.*?)$',      # [INFO] Vulnerability
        r'Found (.*?) vulnerability',  # Found XSS vulnerability
        r'Possible (.*?) detected',    # Possible SQL injection detected
    ]
    
    lines = output_text.split('\n')
    for line in lines:
        line = line.strip()
        for pattern in vuln_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                vuln_type = match.group(1)
                # Извлекаем уровень критичности из паттерна или устанавливаем по умолчанию
                if '[CRITICAL]' in line.upper():
                    severity = 'Critical'
                elif '[HIGH]' in line.upper():
                    severity = 'High'
                elif '[MEDIUM]' in line.upper():
                    severity = 'Medium'
                elif '[LOW]' in line.upper():
                    severity = 'Low'
                elif '[INFO]' in line.upper():
                    severity = 'Info'
                else:
                    severity = 'Medium'
                
                # Включаем URL цели в описание для уникальности
                description = f"Wapiti {severity} finding for {target_url or 'target'}: {vuln_type} ({line[:100]})"
                
                findings.append({
                    'vulnerability_type': vuln_type or 'Wapiti Finding',
                    'description': description,
                    'severity': severity,
                    'scanner': 'wapiti'
                })
                break
    
    logger.info(f"Текстовый парсер нашёл {len(findings)} уязвимостей для {target_url}")
    return findings

def parse_wapiti_json_report(json_text: str):
    """Парсит JSON отчёт Wapiti в унифицированный список находок"""
    findings = []
    try:
        data = json.loads(json_text)
        logger.info(f"JSON отчёт успешно распарсен. Ключи верхнего уровня: {list(data.keys()) if isinstance(data, dict) else 'не dict'}")
    except Exception as e:
        logger.error(f"Ошибка парсинга JSON отчёта: {e}")
        logger.error(f"JSON текст (первые 500 символов): {json_text[:500]}")
        return findings

    # Попытаемся пройти по стандартным разделам отчёта (структура может отличаться между версиями)
    # Преобразуем в плоский список базовых полей
    def add_finding(vtype: str, severity: str, description: str):
        findings.append({
            'vulnerability_type': vtype or 'Unknown',
            'description': description or '',
            'severity': (severity or 'Medium').upper(),
            'scanner': 'wapiti'
        })

    # Возможные варианты расположения уязвимостей
    candidates = []
    if isinstance(data, dict):
        # Некоторые версии кладут в ключ 'vulnerabilities'
        if 'vulnerabilities' in data:
            vulns = data.get('vulnerabilities') or []
            if isinstance(vulns, dict):
                # Новая структура Wapiti 3.x: vulnerabilities как объект
                total_vulns = 0
                for vuln_type, vuln_list in vulns.items():
                    if isinstance(vuln_list, list) and vuln_list:
                        logger.info(f"Найдено {len(vuln_list)} записей типа '{vuln_type}'")
                        # Добавляем тип уязвимости к каждому элементу
                        for vuln in vuln_list:
                            if isinstance(vuln, dict):
                                vuln['_wapiti_type'] = vuln_type
                                candidates.append(vuln)
                                total_vulns += 1
                logger.info(f"Всего найдено {total_vulns} записей в ключе 'vulnerabilities' (объект)")
            elif isinstance(vulns, list):
                # Старая структура: vulnerabilities как массив
                logger.info(f"Найдено {len(vulns)} записей в ключе 'vulnerabilities' (массив)")
                candidates.extend(vulns)
        # Либо группируют по типам
        for key in ['vulns', 'issues', 'alerts', 'anomalies', 'infos']:
            if key in data and isinstance(data[key], list):
                items = data[key] or []
                logger.info(f"Найдено {len(items)} записей в ключе '{key}'")
                candidates.extend(items)
                
        # Новая структура Wapiti 3.x
        if 'infos' in data and isinstance(data['infos'], dict):
            for category, items in data['infos'].items():
                if isinstance(items, list):
                    logger.info(f"Найдено {len(items)} записей в категории '{category}'")
                    candidates.extend(items)
                    
    logger.info(f"Всего кандидатов для обработки: {len(candidates)}")

    for item in candidates:
        try:
            if not isinstance(item, dict):
                logger.debug(f"Пропускаем не-dict элемент: {type(item)}")
                continue
            
            # Логируем структуру элемента для диагностики (временно INFO для отладки)
            if len(findings) < 3:  # Логируем только первые 3 элемента
                logger.info(f"Обрабатываем элемент JSON #{len(findings)+1}: ключи={list(item.keys())}")
                logger.info(f"Содержимое элемента: {json.dumps(item, ensure_ascii=False, indent=2)[:500]}...")
            
            vtype = item.get('_wapiti_type') or item.get('name') or item.get('type') or item.get('vulnerability') or item.get('wstg_id') or 'Unknown'
            # Обработка severity из level (числовое значение в Wapiti 3.x)
            level = item.get('level') or item.get('severity') or item.get('risk') or 1
            if isinstance(level, (int, float)):
                if level >= 3:
                    severity = 'High'
                elif level >= 2:
                    severity = 'Medium'
                else:
                    severity = 'Low'
            else:
                severity = str(level)
            desc = item.get('description') or item.get('info') or item.get('detail') or json.dumps(item, ensure_ascii=False)[:500]
            
            # Дополнительные попытки извлечения данных
            if vtype == 'Unknown':
                # Пробуем другие поля
                for field in ['title', 'category', 'class', 'method']:
                    if item.get(field):
                        vtype = str(item[field])
                        break
            
            if not desc or desc == '{}':
                # Пробуем собрать описание из других полей
                desc_parts = []
                for field in ['url', 'parameter', 'method', 'payload']:
                    if item.get(field):
                        desc_parts.append(f"{field}: {item[field]}")
                desc = '; '.join(desc_parts) if desc_parts else f"Wapiti finding: {json.dumps(item, ensure_ascii=False)[:200]}"
            
            if len(findings) < 3:  # Логируем только первые 3 элемента
                logger.info(f"Извлечены данные #{len(findings)+1}: type={vtype}, severity={severity}, desc={desc[:100]}...")
            add_finding(vtype, severity, desc)
            
        except Exception as e:
            logger.warning(f"Ошибка обработки элемента JSON: {e}")
            logger.debug(f"Проблемный элемент: {item}")
            continue

    return findings

def parse_wapiti_html_report(html_text: str):
    """Структурный парсинг HTML отчёта Wapiti в список находок"""
    findings = []
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_text, 'html.parser')
    except Exception:
        soup = None

    def normalize_severity(txt: str) -> str:
        if not txt:
            return 'Medium'
        t = txt.strip().lower()
        if 'critical' in t:
            return 'Critical'
        if 'high' in t:
            return 'High'
        if 'medium' in t or 'moderate' in t:
            return 'Medium'
        if 'low' in t:
            return 'Low'
        if 'info' in t:
            return 'Info'
        return txt.strip().title()

    def add_finding(vtype: str, severity: str, description: str):
        v = {
            'vulnerability_type': (vtype or 'Unknown')[:200],
            'description': (description or '')[:500],
            'severity': normalize_severity(severity or 'Medium'),
            'scanner': 'wapiti'
        }
        findings.append(v)

    # 1) Пытаемся разобрать таблицы с колонками (Vulnerability, Severity, Description, etc.)
    if soup is not None:
        try:
            tables = soup.find_all('table')
            for table in tables:
                headers = [th.get_text(strip=True) for th in table.find_all('th')]
                headers_lower = [h.lower() for h in headers]
                if not headers:
                    continue
                if not (any('vulnerab' in h or 'issue' in h or 'name' in h for h in headers_lower) or ('severity' in headers_lower)):
                    continue
                idx_v = None
                idx_s = None
                idx_d = None
                for i, h in enumerate(headers_lower):
                    if idx_v is None and ('vulnerab' in h or 'name' in h or 'issue' in h):
                        idx_v = i
                    if idx_s is None and 'severity' in h:
                        idx_s = i
                    if idx_d is None and ('description' in h or 'detail' in h or 'info' in h):
                        idx_d = i
                for tr in table.find_all('tr'):
                    tds = tr.find_all('td')
                    if not tds:
                        continue
                    cells = [td.get_text(" ", strip=True) for td in tds]
                    vtype = cells[idx_v] if (idx_v is not None and idx_v < len(cells)) else ''
                    severity = cells[idx_s] if (idx_s is not None and idx_s < len(cells)) else ''
                    description = cells[idx_d] if (idx_d is not None and idx_d < len(cells)) else ' '.join(cells)
                    if vtype or severity or description:
                        add_finding(vtype, severity, description)
        except Exception:
            pass

    # 2) Если таблицы не дали результатов — ищем секции "Vulnerabilities" и элементы списков
    if not findings and soup is not None:
        try:
            from bs4 import NavigableString
            # Найдём заголовок раздела уязвимостей
            heads = [h for h in soup.find_all([ 'h1','h2','h3','h4']) if 'vulnerab' in (h.get_text(strip=True).lower())]
            section_root = heads[0].parent if heads else soup
            # Собираем все элементы списков/параграфы под корнем
            items = section_root.find_all(['li', 'p'])
            for it in items:
                text = it.get_text(" ", strip=True)
                if not text:
                    continue
                sev = None
                # Поиск метки тяжести рядом
                sev_span = it.find(lambda tag: tag.name in ['span','strong','em'] and any(s in (tag.get_text(strip=True).upper()) for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']))
                if sev_span:
                    sev = sev_span.get_text(strip=True)
                # Тип уязвимости попытаемся вытащить из текста
                try:
                    _p = AIVulnerabilityParser()
                    vtype = _p.extract_vulnerability_type(text)
                    add_finding(vtype, sev or _p.extract_severity(text), text)
                except Exception:
                    add_finding('Wapiti Finding', sev or 'Medium', text)
        except Exception:
            pass

    # 3) Fallback на старую простую эвристику (если ничего не нашли)
    if not findings:
        try:
            from bs4 import BeautifulSoup
            soup2 = soup or BeautifulSoup(html_text, 'html.parser')
            raw_text = soup2.get_text("\n")
        except Exception:
            raw_text = html_text
        _p2 = AIVulnerabilityParser()
        lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
        for ln in lines:
            vtype = _p2.extract_vulnerability_type(ln)
            sev = _p2.extract_severity(ln)
            if vtype != 'Unknown' or any(k in ln.lower() for k in ['critical','high','medium','low','info']):
                add_finding(vtype if vtype != 'Unknown' else 'Wapiti Finding', sev, ln)

    # Дедупликация по (type, description[:100])
    seen = set()
    unique = []
    for f in findings:
        key = (f['vulnerability_type'], f['description'][:100])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique

# Global lock for Wapiti single-flight
class WapitiGlobalLock:
    def __init__(self, lockfile: str, timeout_seconds: int = 3600):
        self.lockfile = lockfile
        self.timeout_seconds = timeout_seconds
        self._fd = None
        self._acquired = False

    def acquire(self):
        start = time.time()
        if HAS_FCNTL:
            self._fd = open(self.lockfile, 'w')
            while True:
                try:
                    fcntl.flock(self._fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._fd.write(str(os.getpid()))
                    self._fd.flush()
                    self._acquired = True
                    return True
                except BlockingIOError:
                    if time.time() - start > self.timeout_seconds:
                        return False
                    time.sleep(1)
        else:
            # Fallback: create exclusive file
            while True:
                try:
                    fd = os.open(self.lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    os.write(fd, str(os.getpid()).encode('utf-8'))
                    os.close(fd)
                    self._acquired = True
                    return True
                except FileExistsError:
                    if time.time() - start > self.timeout_seconds:
                        return False
                    time.sleep(1)

    def release(self):
        if not self._acquired:
            return
        try:
            if HAS_FCNTL and self._fd is not None:
                try:
                    fcntl.flock(self._fd.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                try:
                    self._fd.close()
                except Exception:
                    pass
            # Remove lockfile
            try:
                os.remove(self.lockfile)
            except Exception:
                pass
        finally:
            self._acquired = False
            self._fd = None

def run_wapiti(target, temp_dir=None):
    """
    Запускает Wapiti сканирование
    """
    # По требованию: всегда использовать Docker-версию с HTML-отчётом
    # Возможность отключить Wapiti через переменную окружения
    if os.environ.get('SURFH2_DISABLE_WAPITI', '0') == '1':
        logger.info("Wapiti отключен переменной окружения SURFH2_DISABLE_WAPITI=1")
        return None
    
    try:
        # Валидация target
        target = validate_target(target)
        
        # Создаем временную директорию если не передана
        if not temp_dir:
            import tempfile
            temp_dir = tempfile.mkdtemp(prefix="wapiti_")
        
        # Гарантируем схему для цели
        if not (str(target).startswith('http://') or str(target).startswith('https://')):
            target = f"http://{target}"

        # Параметры таймаута
        try:
            timeout_s = int(os.environ.get('SURFH2_WAPITI_TIMEOUT', '600'))
        except ValueError:
            timeout_s = 600

        # УБИРАЕМ глобальную блокировку - она вызывает проблемы с переиспользованием отчётов
        # Вместо этого делаем каждый запуск полностью изолированным
        logger.info(f"Запускаем Wapiti БЕЗ глобальной блокировки для полной изоляции")

        # Настраиваем выходную директорию для HTML отчёта, которую примонтируем в контейнер
        host_reports = os.path.join(temp_dir, 'wapiti_reports')
        os.makedirs(host_reports, exist_ok=True)
        # Очищаем директорию отчётов перед запуском, чтобы исключить старые файлы
        try:
            for name in os.listdir(host_reports):
                p = os.path.join(host_reports, name)
                try:
                    if os.path.isfile(p):
                        os.remove(p)
                except Exception:
                    pass
        except Exception:
            pass
        
        # Создаем СУПЕР-уникальное имя с процессом, потоком и случайностью
        import hashlib
        import threading
        target_hash = hashlib.md5(target.encode('utf-8')).hexdigest()[:8]
        timestamp = int(time.time() * 1000)  # миллисекунды для большей точности
        process_id = os.getpid()
        thread_id = threading.get_ident()
        random_uuid = uuid.uuid4().hex
        
        image = os.environ.get('SURFH2_WAPITI_DOCKER_IMAGE', 'cyberwatch/wapiti')
        container_name = f"wapiti_{target_hash}_{timestamp}_{process_id}_{thread_id}_{random_uuid[:8]}"
        # ПОЛНОСТЬЮ уникальная директория 
        host_reports_dir = os.path.join(temp_dir, f"wapiti_reports_{target_hash}_{timestamp}_{process_id}_{thread_id}")
        
        logger.info(f"Создание уникальной среды: target_hash={target_hash}, timestamp={timestamp}, pid={process_id}, tid={thread_id}")
        os.makedirs(host_reports_dir, exist_ok=True)
        # АГРЕССИВНАЯ очистка - удаляем ВСЁ связанное с этой целью
        try:
            import shutil
            import glob
            
            # 1. Удаляем нашу директорию если существует
            if os.path.exists(host_reports_dir):
                logger.info(f"Удаляем директорию: {host_reports_dir}")
                shutil.rmtree(host_reports_dir, ignore_errors=True)
            
            # 2. Удаляем ВСЕ старые отчёты для этой цели во всём temp_dir
            temp_dir_pattern = os.path.join(temp_dir, f"wapiti_reports_{target_hash}_*")
            old_reports = glob.glob(temp_dir_pattern)
            for old_report in old_reports:
                logger.info(f"Удаляем старый отчёт: {old_report}")
                shutil.rmtree(old_report, ignore_errors=True)
            
            # 3. Удаляем все старые контейнеры с таким же target_hash
            try:
                result = subprocess.run(['docker', 'ps', '-a', '--filter', f'name=wapiti_{target_hash}', '--format', '{{.Names}}'], 
                                      capture_output=True, text=True, timeout=10)
                if result.stdout.strip():
                    old_containers = result.stdout.strip().split('\n')
                    for container in old_containers:
                        if container.strip():
                            logger.info(f"Удаляем старый контейнер: {container.strip()}")
                            subprocess.run(['docker', 'rm', '-f', container.strip()], capture_output=True, timeout=10)
            except Exception as e:
                logger.warning(f"Не удалось очистить старые контейнеры: {e}")
                
            # 4. Пересоздаём нашу чистую директорию
            os.makedirs(host_reports_dir, exist_ok=True)
            logger.info(f"Создана чистая директория: {host_reports_dir}")
            
        except Exception as e:
            logger.error(f"КРИТИЧЕСКАЯ ОШИБКА очистки: {e}")
            # В случае ошибки - пытаемся продолжить с новой уникальной директорией
            host_reports_dir = os.path.join(temp_dir, f"wapiti_emergency_{uuid.uuid4().hex}")
            os.makedirs(host_reports_dir, exist_ok=True)
        # В контейнере будем писать сюда с уникальным именем
        reports_in_container_base = '/reports'
        report_filename = f'report_{target_hash}_{timestamp}_{process_id}_{thread_id}.json'
        logger.info(f"Имя файла отчёта: {report_filename}")
        # Запускаем контейнер С монтированием директории отчётов и JSON-выводом
        # ОБЯЗАТЕЛЬНО удаляем старый контейнер если существует
        try:
            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, text=True, timeout=10)
        except Exception:
            pass
            
        cmd = [
            'docker', 'run', '--name', container_name, '--rm',  # --rm для автоудаления
            '-v', f'{host_reports_dir}:{reports_in_container_base}',
            image, '-u', target, '-f', 'json', '-o', f"{reports_in_container_base}/{report_filename}"
        ]

        logger.info(f"Запуск wapiti: {' '.join(cmd)}")

        # Стримим вывод и следим за неактивностью
        inactivity_limit = int(os.environ.get('SURFH2_WAPITI_INACTIVITY_SECONDS', str(3600)))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        last_active = time.time()
        collected_output = []
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
                    collected_output.append(line)
                    last_active = time.time()
                else:
                    if time.time() - last_active > inactivity_limit:
                        logger.warning(f"Wapiti не выводит данных более {inactivity_limit}s. Посылаю SIGINT контейнеру для сохранения отчёта...")
                        try:
                            subprocess.run(['docker', 'kill', '--signal=INT', container_name], capture_output=True, text=True, timeout=10)
                        except Exception as e:
                            logger.warning(f"Не удалось отправить SIGINT контейнеру {container_name}: {e}")
                        try:
                            proc.wait(timeout=30)
                        except Exception:
                            try:
                                subprocess.run(['docker', 'stop', '-t', '5', container_name], capture_output=True, text=True, timeout=10)
                            except Exception:
                                pass
                        break
                if proc.poll() is not None:
                    try:
                        remaining = proc.stdout.read() if proc.stdout else ''
                        if remaining:
                            collected_output.append(remaining)
                    except Exception:
                        pass
                    break
        except Exception as e:
            logger.warning(f"Ошибка во время чтения вывода Wapiti: {e}")
            try:
                proc.kill()
            except Exception:
                pass
        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass

        # Пытаемся снять отчёты (JSON предпочтительно) из смонтированной директории
        try:
            # Дополнительная пауза для завершения записи файлов контейнером
            time.sleep(3)
            
            json_candidates = []
            html_candidates = []
            for root, _, files in os.walk(host_reports_dir):
                for name in files:
                    p = os.path.join(root, name)
                    # Проверяем, что файл не пустой
                    try:
                        if os.path.getsize(p) > 0:
                            if name.lower().endswith('.json'):
                                json_candidates.append(p)
                            elif name.lower().endswith('.html'):
                                html_candidates.append(p)
                        else:
                            logger.warning(f"Найден пустой файл отчёта: {p}")
                    except Exception as e:
                        logger.warning(f"Ошибка проверки файла {p}: {e}")
            
            logger.info(f"Найдено JSON отчётов: {len(json_candidates)}, HTML отчётов: {len(html_candidates)}")
            # Сначала JSON
            if json_candidates:
                # Предпочтём файл с именем нашего отчета (с хешем цели), иначе самый новый
                preferred = [p for p in json_candidates if report_filename in os.path.basename(p)]
                if not preferred:
                    # Ищем файлы с нашим хешем цели
                    preferred = [p for p in json_candidates if target_hash in os.path.basename(p)]
                chosen_json = preferred[0] if preferred else max(json_candidates, key=lambda p: os.path.getmtime(p))
                logger.info(f"Используем JSON отчёт Wapiti: {chosen_json}")
                
                # Добавляем задержку для завершения записи файла
                time.sleep(2)
                
                try:
                    with open(chosen_json, 'r', encoding='utf-8') as f:
                        j = f.read()
                    logger.info(f"Прочитан JSON отчёт Wapiti размером {len(j)} символов")
                    
                    # КРИТИЧЕСКИ ВАЖНО: проверяем что отчёт для правильной цели И свежий
                    if target.lower() not in j.lower():
                        logger.error(f"ОШИБКА: JSON отчёт НЕ содержит цель '{target}'. Возможно используется старый отчёт!")
                        logger.error(f"Первые 500 символов отчёта: {j[:500]}")
                        return []
                    
                    # Проверяем время создания файла - должен быть создан в последние 10 минут
                    file_age = time.time() - os.path.getmtime(chosen_json)
                    if file_age > 600:  # 10 минут
                        logger.error(f"ОШИБКА: JSON отчёт слишком старый ({file_age:.0f}s). Возможно используется кеш!")
                        logger.error(f"Путь к файлу: {chosen_json}")
                        return []
                    else:
                        logger.info(f"✅ Отчёт свежий: создан {file_age:.1f}s назад")
                    
                    if j.strip():  # Проверяем, что файл не пустой
                        findings = parse_wapiti_json_report(j)
                        logger.info(f"JSON парсер нашёл {len(findings)} уязвимостей")
                        
                        # СОХРАНЯЕМ отчёт в папке проекта для анализа пользователем
                        try:
                            project_reports_dir = os.path.join(os.getcwd(), 'wapiti_reports')
                            os.makedirs(project_reports_dir, exist_ok=True)
                            
                            # Создаем уникальное имя файла с информацией о цели и времени
                            import urllib.parse
                            clean_target_name = urllib.parse.quote(target.replace('http://', '').replace('https://', ''), safe='')
                            saved_filename = f"wapiti_{clean_target_name}_{target_hash}_{timestamp}.json"
                            saved_path = os.path.join(project_reports_dir, saved_filename)
                            
                            import shutil
                            shutil.copy2(chosen_json, saved_path)
                            logger.info(f"📄 Отчёт Wapiti сохранён: {saved_path}")
                            
                            # Дополнительно сохраняем краткую информацию
                            info_filename = f"wapiti_{clean_target_name}_{target_hash}_{timestamp}_info.txt"
                            info_path = os.path.join(project_reports_dir, info_filename)
                            with open(info_path, 'w', encoding='utf-8') as info_file:
                                info_file.write(f"Wapiti отчёт для: {target}\n")
                                info_file.write(f"Время сканирования: {timestamp}\n")
                                info_file.write(f"Размер JSON: {len(j)} символов\n")
                                info_file.write(f"Найдено уязвимостей парсером: {len(findings)}\n")
                                info_file.write(f"Исходный файл: {chosen_json}\n")
                                info_file.write(f"Команда: {' '.join(cmd) if 'cmd' in locals() else 'N/A'}\n")
                            logger.info(f"📋 Информация сохранена: {info_path}")
                            
                        except Exception as e:
                            logger.warning(f"Не удалось сохранить отчёт в проект: {e}")
                        
                        try:
                            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, text=True, timeout=10)
                        except Exception:
                            pass
                        return findings  # Всегда возвращаем результат JSON парсинга, даже если пустой
                    else:
                        logger.warning(f"JSON отчёт пустой: {chosen_json}")
                except Exception as e:
                    logger.error(f"Ошибка чтения JSON отчёта: {e}")
                
                try:
                    subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, text=True, timeout=10)
                except Exception:
                    pass
            # Если JSON нет — пробуем HTML
            if html_candidates:
                chosen_html = max(html_candidates, key=lambda p: os.path.getmtime(p))
                logger.info(f"Используем HTML отчёт Wapiti: {chosen_html}")
                with open(chosen_html, 'r', encoding='utf-8') as f:
                    html = f.read()
                findings = parse_wapiti_html_report(html)
                try:
                    subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, text=True, timeout=10)
                except Exception:
                    pass
                if findings:
                    return findings
        except Exception as e:
            logger.warning(f"Не удалось скопировать отчёт из контейнера: {e}")
        finally:
            try:
                subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, text=True, timeout=10)
            except Exception:
                pass

        logger.warning("Не удалось получить JSON/HTML отчёт из контейнера, парсим stdout")
        fallback = ''.join(collected_output)
        logger.info(f"Fallback stdout содержит {len(fallback)} символов для цели {target}")
        
        # Попытки fallback парсинга в порядке приоритета
        fallback_findings = []
        if fallback.strip():
            # Сначала пробуем JSON парсинг stdout
            fallback_findings = parse_wapiti_json_report(fallback)
            if not fallback_findings:
                # Затем HTML парсинг stdout  
                fallback_findings = parse_wapiti_html_report(fallback)
            if not fallback_findings:
                # Наконец простой текстовый парсинг
                fallback_findings = parse_wapiti_output(fallback, target)
        
        logger.info(f"Fallback парсинг нашёл {len(fallback_findings)} уязвимостей для {target}")
        return fallback_findings
        
    except subprocess.TimeoutExpired:
        logger.error(f"Wapiti превысил таймаут для {target}")
        return None
    except ValueError as e:
        logger.error(f"Ошибка валидации: {e}")
        return None
    except Exception as e:
        logger.error(f"Ошибка при запуске Wapiti: {e}")
        return None

def process_wapiti_result(data, cursor, session_id, target_resource=None):
    """
    Обрабатывает результат Wapiti и сохраняет в базу данных через VulnerabilityManager
    """
    if not data:
        logger.warning("Нет данных Wapiti для обработки")
        return
    
    try:
        from db.vulnerability_manager import VulnerabilityManager
        
        # Создаем менеджер уязвимостей
        vuln_manager = VulnerabilityManager()
        
        # Дополняем данные для AI парсера
        enhanced_data = {
            'vulnerabilities': data,
            'scanner': 'wapiti',
            'target': target_resource
        }
        
        # Обрабатываем и сохраняем данные
        stats = vuln_manager.process_and_save_vulnerabilities(
            raw_data=enhanced_data,
            scanner_name='wapiti',
            cursor=cursor,
            session_id=session_id,
            target_resource=target_resource
        )
        
        logger.info(f"Wapiti: обработано {stats.processed}, сохранено {stats.saved_new}, пропущено дубликатов {stats.duplicates_skipped}")
        return stats
        
    except Exception as e:
        logger.error(f"Ошибка обработки результатов Wapiti: {e}")
        return None

def parse_and_import_wapiti(data, cursor):
    """
    Устаревшая функция - используйте process_wapiti_result
    """
    print("[WARNING] parse_and_import_wapiti устарела, используйте process_wapiti_result")
    return process_wapiti_result(data, cursor, None)
