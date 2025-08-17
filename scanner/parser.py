# scanner/parser.py

from urllib.parse import urlparse
from db.models import Host, Url, CVE, ScanResult


def extract_host_and_url(target_url, cursor):
    """
    Извлекает хост и URL из целевого URL
    """
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        url = f"{parsed.scheme}://{parsed.netloc}"

        # Создаем запись хоста
        Host.insert(cursor, hostname=hostname, ip_address="")
        host_id = cursor.lastrowid

        # Создаем запись URL
        Url.insert(cursor, host_id=host_id, url=url)
        url_id = cursor.lastrowid

        return host_id, url_id
    except Exception as e:
        print(f"[ERROR] Ошибка извлечения хоста и URL: {e}")
        return None, None


def normalize_vuln_result(result, scanner_name):
    """
    Приводит результат сканера к единому формату:
    {
      'ip': str,
      'port': int or None,
      'service': str or None,
      'cve': str or None,
      'severity': str or None,
      'scanner': str
    }
    """
    try:
        # Пример для nuclei
        if scanner_name == 'nuclei':
            ip = result.get('ip', None)
            port = result.get('port', None)
            service = result.get('service', None)
            cve = result.get('info', {}).get('cve', [None])[0] if result.get('info', {}).get('cve') else None
            severity = result.get('info', {}).get('severity', None)
            return {
                'ip': ip,
                'port': port,
                'service': service,
                'cve': cve,
                'severity': severity,
                'scanner': 'nuclei'
            }
        # Пример для nikto
        elif scanner_name == 'nikto':
            ip = result.get('ip', None)
            port = result.get('port', None)
            service = result.get('service', None)
            cve = result.get('osvdb_id') or result.get('id', None)
            severity = result.get('severity', None)
            return {
                'ip': ip,
                'port': port,
                'service': service,
                'cve': cve,
                'severity': severity,
                'scanner': 'nikto'
            }
        # Пример для nmap (добавить по формату nmap)
        elif scanner_name == 'nmap':
            ip = result.get('ip', None)
            port = result.get('port', None)
            service = result.get('service', None)
            cve = result.get('cve', None)
            severity = result.get('severity', None)
            return {
                'ip': ip,
                'port': port,
                'service': service,
                'cve': cve,
                'severity': severity,
                'scanner': 'nmap'
            }
        # Пример для других сканеров (обычно нет CVE, но можно добавить как ПО)
        else:
            return {
                'ip': result.get('ip', None),
                'port': result.get('port', None),
                'service': result.get('service', None),
                'cve': result.get('cve', None),
                'severity': result.get('severity', None),
                'scanner': scanner_name
            }
    except Exception as e:
        print(f"[ERROR] Ошибка нормализации результата {scanner_name}: {e}")
        return {
            'ip': None,
            'port': None,
            'service': None,
            'cve': None,
            'severity': 'Unknown',
            'scanner': scanner_name
        }


def universal_import_to_db(vuln_list, cursor):
    """
    Импортирует список нормализованных уязвимостей в базу данных.
    vuln_list: список словарей с ключами ip, port, service, cve, severity, scanner
    """
    if not vuln_list:
        print("[WARNING] Пустой список уязвимостей для импорта")
        return
    
    try:
        for vuln in vuln_list:
            ip = vuln.get('ip')
            port = vuln.get('port')
            service = vuln.get('service')
            cve_id = vuln.get('cve')
            severity = vuln.get('severity')
            scanner = vuln.get('scanner')

            # 1. Host
            Host.insert(cursor, hostname=ip, ip_address=ip)
            host_id = cursor.lastrowid

            # 2. Url (service + port)
            url_str = f"{service or ''}://{ip}:{port}" if port else f"{service or ''}://{ip}"
            Url.insert(cursor, host_id=host_id, url=url_str)
            url_id = cursor.lastrowid

            # 3. CVE
            if cve_id:
                CVE.insert(cursor, cve_id=cve_id, description='', severity=severity or '')
                cve_db_id = cursor.lastrowid
                # 4. ScanResult
                ScanResult.insert(cursor, url_id=url_id, cve_id=cve_db_id, status='Exploitable', scanner=scanner)
            else:
                # Если нет CVE, создаем ScanResult без CVE
                ScanResult.insert(cursor, url_id=url_id, cve_id=None, status='Found', scanner=scanner)
                
    except Exception as e:
        print(f"[ERROR] Ошибка импорта в базу данных: {e}")
        raise
