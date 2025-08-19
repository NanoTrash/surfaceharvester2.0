#!/usr/bin/env python3
"""
Простой скрипт для быстрого вызова отчетов
"""

from reports_manager import ReportsManager
import sys

def main():
    """Быстрый вызов отчетов"""
    
    if len(sys.argv) < 2:
        print("📊 БЫСТРЫЕ ОТЧЕТЫ")
        print("=" * 40)
        print("Использование:")
        print("  python reports.py 1     # Краткая сводка")
        print("  python reports.py 2     # Детальный анализ")
        print("  python reports.py 3     # История сканирований")
        print("  python reports.py 4     # Хосты и субдомены")
        print("  python reports.py 5     # Оценка безопасности")
        print("  python reports.py 6     # Все отчеты")
        print("  python reports.py i     # Интерактивный режим")
        print("  python reports.py all   # Все отчеты (по умолчанию)")
        return
    
    report_type = sys.argv[1].lower()
    
    try:
        manager = ReportsManager()
        
        if report_type == '1':
            manager.quick_summary_report()
        elif report_type == '2':
            manager.detailed_vulnerabilities_report()
        elif report_type == '3':
            manager.scan_sessions_report()
        elif report_type == '4':
            manager.hosts_and_subdomains_report()
        elif report_type == '5':
            manager.security_score_report()
        elif report_type == '6':
            manager.show_all_reports()
        elif report_type == 'i':
            manager.interactive_menu()
        elif report_type == 'all':
            manager.show_all_reports()
        else:
            print(f"❌ Неизвестный тип отчета: {report_type}")
            return 1
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
