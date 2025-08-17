# db/report.py

import sqlite3
import re

def get_vulnerabilities_by_target(cursor, target):
    """
    Получает все уязвимости для указанной цели
    """
    sql = """
        SELECT resource, vulnerability_type, description, severity, scanner, timestamp
        FROM vulnerability 
        WHERE resource LIKE ? OR resource = ?
        ORDER BY severity DESC, timestamp DESC
    """
    # Безопасная очистка target
    target_clean = target.replace("https://", "").replace("http://", "")
    cursor.execute(sql, (f"%{target_clean}%", target_clean))
    return cursor.fetchall()

def get_vulnerabilities_by_type(cursor):
    """
    Группирует уязвимости по типу
    """
    sql = """
        SELECT vulnerability_type, COUNT(*) as count, 
               GROUP_CONCAT(DISTINCT severity) as severities
        FROM vulnerability 
        GROUP BY vulnerability_type 
        ORDER BY count DESC
    """
    cursor.execute(sql)
    return cursor.fetchall()

def get_vulnerabilities_by_severity(cursor):
    """
    Группирует уязвимости по критичности
    """
    sql = """
        SELECT severity, COUNT(*) as count,
               GROUP_CONCAT(DISTINCT vulnerability_type) as types
        FROM vulnerability 
        GROUP BY severity 
        ORDER BY 
            CASE severity 
                WHEN 'Critical' THEN 1 
                WHEN 'High' THEN 2 
                WHEN 'Medium' THEN 3 
                WHEN 'Low' THEN 4 
                ELSE 5 
            END
    """
    cursor.execute(sql)
    return cursor.fetchall()

def get_scan_sessions(cursor):
    """
    Получает историю сессий сканирования
    """
    sql = """
        SELECT target, start_time, end_time, status
        FROM scansession 
        ORDER BY start_time DESC
    """
    cursor.execute(sql)
    return cursor.fetchall()

def show_report(cursor, target):
    """
    Показывает полный отчет по сканированию
    """
    print("\n" + "="*60)
    print(f"ОТЧЕТ ПО СКАНИРОВАНИЮ: {target}")
    print("="*60)
    
    # Уязвимости по цели
    print("\n[1] НАЙДЕННЫЕ УЯЗВИМОСТИ:")
    print("-" * 60)
    vulns = get_vulnerabilities_by_target(cursor, target)
    
    if not vulns:
        print("Уязвимости не найдены.")
    else:
        for i, vuln in enumerate(vulns, 1):
            resource, vuln_type, description, severity, scanner, timestamp = vuln
            print(f"{i}. {vuln_type} ({severity})")
            print(f"   Ресурс: {resource}")
            print(f"   Сканер: {scanner}")
            print(f"   Описание: {description[:100] if description else 'Нет описания'}...")
            print(f"   Время: {timestamp}")
            print()
    
    # Статистика по типам уязвимостей
    print("\n[2] СТАТИСТИКА ПО ТИПАМ УЯЗВИМОСТЕЙ:")
    print("-" * 60)
    type_stats = get_vulnerabilities_by_type(cursor)
    for vuln_type, count, severities in type_stats:
        print(f"{vuln_type}: {count} (уровни: {severities or 'Не указано'})")
    
    # Статистика по критичности
    print("\n[3] СТАТИСТИКА ПО КРИТИЧНОСТИ:")
    print("-" * 60)
    severity_stats = get_vulnerabilities_by_severity(cursor)
    for severity, count, types in severity_stats:
        print(f"{severity}: {count} уязвимостей")
    
    # История сканирований
    print("\n[4] ИСТОРИЯ СКАНИРОВАНИЙ:")
    print("-" * 60)
    sessions = get_scan_sessions(cursor)
    for target, start_time, end_time, status in sessions:
        print(f"Цель: {target}")
        print(f"Статус: {status}")
        print(f"Начало: {start_time}")
        if end_time:
            print(f"Конец: {end_time}")
        print()

def show_summary(cursor):
    """
    Показывает краткую сводку
    """
    print("\n" + "="*40)
    print("КРАТКАЯ СВОДКА")
    print("="*40)
    
    # Общее количество уязвимостей
    cursor.execute("SELECT COUNT(*) FROM vulnerability")
    total_vulns = cursor.fetchone()[0]
    
    # Критические уязвимости
    cursor.execute("SELECT COUNT(*) FROM vulnerability WHERE severity = 'Critical'")
    critical_vulns = cursor.fetchone()[0]
    
    # Высокие уязвимости
    cursor.execute("SELECT COUNT(*) FROM vulnerability WHERE severity = 'High'")
    high_vulns = cursor.fetchone()[0]
    
    print(f"Всего уязвимостей: {total_vulns}")
    print(f"Критических: {critical_vulns}")
    print(f"Высоких: {high_vulns}")
    
    if critical_vulns > 0 or high_vulns > 0:
        print("\n⚠️  ВНИМАНИЕ: Обнаружены критические уязвимости!")
    else:
        print("\n✅ Критических уязвимостей не обнаружено.")

def generate_summary_report(cursor, target=None):
    """
    Генерирует краткий отчет с эмодзи и статистикой
    """
    try:
        # Получаем все уязвимости
        if target:
            cursor.execute("""
                SELECT vulnerability_type, severity, description 
                FROM vulnerability 
                WHERE resource LIKE ? 
                ORDER BY 
                    CASE severity 
                        WHEN 'Critical' THEN 1 
                        WHEN 'High' THEN 2 
                        WHEN 'Medium' THEN 3 
                        WHEN 'Low' THEN 4 
                        WHEN 'info' THEN 5 
                        ELSE 6 
                    END
            """, (f'%{target}%',))
        else:
            cursor.execute("""
                SELECT vulnerability_type, severity, description 
                FROM vulnerability 
                ORDER BY 
                    CASE severity 
                        WHEN 'Critical' THEN 1 
                        WHEN 'High' THEN 2 
                        WHEN 'Medium' THEN 3 
                        WHEN 'Low' THEN 4 
                        WHEN 'info' THEN 5 
                        ELSE 6 
                    END
            """)
        
        vulnerabilities = cursor.fetchall()
        
        # Подсчитываем статистику
        severity_counts = {}
        type_counts = {}
        cve_list = []
        
        for vuln_type, severity, description in vulnerabilities:
            # Подсчет по критичности
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Подсчет по типам
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            
            # Собираем CVE
            if 'CVE-' in description:
                cve_match = re.search(r'CVE-\d{4}-\d+', description)
                if cve_match:
                    cve_id = cve_match.group(0)
                    cvss_match = re.search(r'(\d+\.\d+)', description)
                    cvss_score = cvss_match.group(1) if cvss_match else "N/A"
                    cve_list.append(f"{cve_id} ({cvss_score})")
        
        # Убираем дубликаты CVE
        cve_list = list(set(cve_list))
        cve_list.sort()
        
        # Формируем отчет
        report = []
        report.append("=" * 60)
        report.append("КРАТКИЙ ОТЧЕТ ПО СКАНИРОВАНИЮ")
        report.append("=" * 60)
        
        # Статистика по критичности
        report.append("\n🔍 НАЙДЕННЫЕ УЯЗВИМОСТИ:")
        report.append("-" * 40)
        
        if 'Critical' in severity_counts:
            report.append(f"🔴 Critical: {severity_counts['Critical']}")
        if 'High' in severity_counts:
            report.append(f"🔴 High: {severity_counts['High']}")
        if 'Medium' in severity_counts:
            report.append(f"🟡 Medium: {severity_counts['Medium']}")
        if 'Low' in severity_counts:
            report.append(f"🟢 Low: {severity_counts['Low']}")
        if 'info' in severity_counts:
            report.append(f"ℹ️ Info: {severity_counts['info']}")
        
        # Ключевые находки
        if cve_list:
            report.append(f"\n🔑 КЛЮЧЕВЫЕ НАХОДКИ:")
            report.append("-" * 40)
            report.append(f"🔴 CVE уязвимости ({len(cve_list)}):")
            for cve in cve_list[:10]:  # Показываем первые 10
                report.append(f"   • {cve}")
            if len(cve_list) > 10:
                report.append(f"   ... и еще {len(cve_list) - 10} CVE")
        
        # Топ типов уязвимостей
        report.append(f"\n📊 ТОП ТИПОВ УЯЗВИМОСТЕЙ:")
        report.append("-" * 40)
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        for vuln_type, count in sorted_types[:5]:
            report.append(f"   • {vuln_type}: {count}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)
        
    except Exception as e:
        return f"Ошибка генерации отчета: {e}"

def show_summary_report(target=None, db_file="scan_results.db"):
    """
    Показывает краткий отчет
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        report = generate_summary_report(cursor, target)
        print(report)
        
        conn.close()
        
    except Exception as e:
        print(f"Ошибка при показе отчета: {e}")
