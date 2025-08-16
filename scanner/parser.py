# scanner/parser.py

from urllib.parse import urlparse
from db.models import Host, Url


def extract_host_and_url(target_url, cursor):
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    url = f"{parsed.scheme}://{parsed.netloc}"

    Host.insert(cursor, hostname=hostname, ip_address="")
    host_id = cursor.lastrowid

    Url.insert(cursor, host_id=host_id, url=url)
    url_id = cursor.lastrowid

    return host_id, url_id


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
    # Пример для wappalyzer (обычно нет CVE, но можно добавить как ПО)
    elif scanner_name == 'wappalyzer':
        ip = result.get('ip', None)
        port = result.get('port', None)
        service = result.get('service', None)
        return {
            'ip': ip,
            'port': port,
            'service': service,
            'cve': None,
            'severity': None,
            'scanner': 'wappalyzer'
        }
    # По умолчанию — просто копируем основные поля
    else:
        return {
            'ip': result.get('ip', None),
            'port': result.get('port', None),
            'service': result.get('service', None),
            'cve': result.get('cve', None),
            'severity': result.get('severity', None),
            'scanner': scanner_name
        }


def universal_import_to_db(vuln_list, cursor):
    """
    Импортирует список нормализованных уязвимостей в базу данных.
    vuln_list: список словарей с ключами ip, port, service, cve, severity, scanner
    """
    from db.models import Host, Url, CVE, ScanResult
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
            ScanResult.insert(cursor, url_id=url_id, cve_id=cve_db_id, status='Exploitable')
