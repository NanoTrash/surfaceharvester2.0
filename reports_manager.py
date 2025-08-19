#!/usr/bin/env python3
"""
Модуль для удобного просмотра отчетов и работы с vulnx
"""

import sqlite3
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

class ReportsManager:
    """
    Менеджер отчетов для удобного просмотра результатов сканирования
    """
    
    def __init__(self, db_file: str = "scan_results.db"):
        self.db_file = db_file
        self.emoji_map = {
            'Critical': '🔴',
            'High': '🔴', 
            'Medium': '🟡',
            'Low': '🟢',
            'Info': 'ℹ️',
            'Unknown': '❓'
        }
    
    def _get_connection(self):
        """Получает соединение с базой данных"""
        if not os.path.exists(self.db_file):
            raise FileNotFoundError(f"База данных {self.db_file} не найдена")
        return sqlite3.connect(self.db_file)
    
    def _format_severity(self, severity: str) -> str:
        """Форматирует уровень критичности с эмодзи"""
        emoji = self.emoji_map.get(severity, '❓')
        return f"{emoji} {severity}"
    
    def _print_separator(self, title: str = ""):
        """Печатает разделитель"""
        if title:
            print(f"\n{'='*60}")
            print(f"📊 {title}")
            print(f"{'='*60}")
        else:
            print(f"\n{'-'*60}")
    
    def _print_vulnx_commands(self, target: Optional[str] = None):
        """Печатает команды для работы с vulnx"""
        self._print_separator("🚀 КОМАНДЫ ДЛЯ РАБОТЫ С VULNX")
        
        base_cmd = "poetry run python cli.py"
        target_param = f" --target {target}" if target else ""
        
        commands = [
            f"🔍 {base_cmd} exploits search{target_param} --limit 10",
            f"📊 {base_cmd} exploits status",
            f"📋 {base_cmd} exploits report{target_param}",
            f"🔄 {base_cmd} exploits monitor --interval 60",
            f"📈 {base_cmd} exploits report{target_param} --format json"
        ]
        
        descriptions = [
            "Поиск эксплойтов для найденных CVE",
            "Статус обработки CVE и эксплойтов", 
            "Подробный отчет по эксплойтам",
            "Мониторинг новых CVE",
            "Экспорт отчета в JSON"
        ]
        
        for cmd, desc in zip(commands, descriptions):
            print(f"   {desc}")
            print(f"   {cmd}")
            print()
    
    def quick_summary_report(self, target: Optional[str] = None):
        """
        Отчет 1: Краткая сводка - основные цифры и статус
        """
        self._print_separator("📈 КРАТКАЯ СВОДКА")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Общая статистика
            cursor.execute("SELECT COUNT(*) FROM vulnerability")
            total_vulns = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scansession")
            total_sessions = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM host")
            total_hosts = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM subdomain")
            total_subdomains = cursor.fetchone()[0]
            
            print(f"🎯 Всего уязвимостей: {total_vulns}")
            print(f"📊 Сессий сканирования: {total_sessions}")
            print(f"🌐 Хостов: {total_hosts}")
            print(f"🔗 Субдоменов: {total_subdomains}")
            
            if total_vulns > 0:
                # Статистика по критичности
                cursor.execute("""
                    SELECT severity, COUNT(*) 
                    FROM vulnerability 
                    GROUP BY severity 
                    ORDER BY CASE severity 
                        WHEN 'Critical' THEN 1 
                        WHEN 'High' THEN 2 
                        WHEN 'Medium' THEN 3 
                        WHEN 'Low' THEN 4 
                        ELSE 5 
                    END
                """)
                
                severity_stats = cursor.fetchall()
                print(f"\n🔍 По критичности:")
                for severity, count in severity_stats:
                    formatted_severity = self._format_severity(severity)
                    print(f"   {formatted_severity}: {count}")
                
                # Последние уязвимости
                cursor.execute("""
                    SELECT vulnerability_type, severity, scanner, resource 
                    FROM vulnerability 
                    ORDER BY timestamp DESC 
                    LIMIT 5
                """)
                
                recent_vulns = cursor.fetchall()
                if recent_vulns:
                    print(f"\n🕒 Последние находки:")
                    for vuln_type, severity, scanner, resource in recent_vulns:
                        formatted_severity = self._format_severity(severity)
                        print(f"   {formatted_severity} {vuln_type} ({scanner}) - {resource[:50]}...")
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Ошибка: {e}")
    
    def detailed_vulnerabilities_report(self, target: Optional[str] = None):
        """
        Отчет 2: Детальный анализ уязвимостей
        """
        self._print_separator("🔍 ДЕТАЛЬНЫЙ АНАЛИЗ УЯЗВИМОСТЕЙ")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Базовый запрос
            base_query = "SELECT vulnerability_type, severity, scanner, resource, description, timestamp FROM vulnerability"
            params = []
            
            if target:
                base_query += " WHERE resource LIKE ?"
                params.append(f"%{target}%")
            
            base_query += " ORDER BY severity DESC, timestamp DESC"
            
            cursor.execute(base_query, params)
            vulnerabilities = cursor.fetchall()
            
            if not vulnerabilities:
                print("ℹ️ Уязвимости не найдены")
                return
            
            print(f"📊 Найдено уязвимостей: {len(vulnerabilities)}")
            
            # Группировка по типам
            cursor.execute("""
                SELECT vulnerability_type, COUNT(*) as count 
                FROM vulnerability 
                GROUP BY vulnerability_type 
                ORDER BY count DESC
            """)
            
            type_stats = cursor.fetchall()
            print(f"\n📋 По типам:")
            for vuln_type, count in type_stats:
                print(f"   • {vuln_type}: {count}")
            
            # Группировка по сканерам
            cursor.execute("""
                SELECT scanner, COUNT(*) as count 
                FROM vulnerability 
                GROUP BY scanner 
                ORDER BY count DESC
            """)
            
            scanner_stats = cursor.fetchall()
            print(f"\n🛠️ По сканерам:")
            for scanner, count in scanner_stats:
                print(f"   • {scanner}: {count}")
            
            # Детальный список (первые 10)
            print(f"\n📝 Детальный список (первые 10):")
            for i, (vuln_type, severity, scanner, resource, description, timestamp) in enumerate(vulnerabilities[:10], 1):
                formatted_severity = self._format_severity(severity)
                print(f"\n   {i}. {formatted_severity} {vuln_type}")
                print(f"      Сканер: {scanner}")
                print(f"      Ресурс: {resource}")
                if description:
                    desc_preview = description[:100] + "..." if len(description) > 100 else description
                    print(f"      Описание: {desc_preview}")
                print(f"      Время: {timestamp}")
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Ошибка: {e}")
    
    def scan_sessions_report(self, target: Optional[str] = None):
        """
        Отчет 3: История сканирований
        """
        self._print_separator("📊 ИСТОРИЯ СКАНИРОВАНИЙ")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Получаем сессии
            base_query = "SELECT target, start_time, end_time, status FROM scansession"
            params = []
            
            if target:
                base_query += " WHERE target LIKE ?"
                params.append(f"%{target}%")
            
            base_query += " ORDER BY start_time DESC"
            
            cursor.execute(base_query, params)
            sessions = cursor.fetchall()
            
            if not sessions:
                print("ℹ️ Сессии сканирования не найдены")
                return
            
            print(f"📊 Найдено сессий: {len(sessions)}")
            
            for i, (session_target, start_time, end_time, status) in enumerate(sessions, 1):
                print(f"\n   {i}. 🎯 {session_target}")
                print(f"      📅 Начало: {start_time}")
                if end_time:
                    print(f"      📅 Конец: {end_time}")
                print(f"      📊 Статус: {status}")
                
                # Уязвимости для этой сессии
                cursor.execute("""
                    SELECT COUNT(*) FROM vulnerability 
                    WHERE resource LIKE ?
                """, (f"%{session_target.replace('https://', '').replace('http://', '')}%",))
                
                vuln_count = cursor.fetchone()[0]
                print(f"      🔍 Уязвимостей: {vuln_count}")
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Ошибка: {e}")
    
    def hosts_and_subdomains_report(self, target: Optional[str] = None):
        """
        Отчет 4: Хосты и субдомены
        """
        self._print_separator("🌐 ХОСТЫ И СУБДОМЕНЫ")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Хосты
            print("🏠 ХОСТЫ:")
            cursor.execute("SELECT hostname, ip_address, type, source FROM host ORDER BY hostname")
            hosts = cursor.fetchall()
            
            if hosts:
                for hostname, ip_address, host_type, source in hosts:
                    print(f"   • {hostname}")
                    if ip_address:
                        print(f"     IP: {ip_address}")
                    print(f"     Тип: {host_type}")
                    if source:
                        print(f"     Источник: {source}")
                    print()
            else:
                print("   ℹ️ Хосты не найдены")
            
            # Субдомены
            print("🔗 СУБДОМЕНЫ:")
            cursor.execute("SELECT name, parent_domain, source FROM subdomain ORDER BY name")
            subdomains = cursor.fetchall()
            
            if subdomains:
                for name, parent_domain, source in subdomains:
                    print(f"   • {name}")
                    if parent_domain:
                        print(f"     Родительский домен: {parent_domain}")
                    if source:
                        print(f"     Источник: {source}")
                    print()
            else:
                print("   ℹ️ Субдомены не найдены")
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Ошибка: {e}")
    
    def security_score_report(self, target: Optional[str] = None):
        """
        Отчет 5: Оценка безопасности
        """
        self._print_separator("🛡️ ОЦЕНКА БЕЗОПАСНОСТИ")
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Подсчет уязвимостей по критичности
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM vulnerability 
                GROUP BY severity
            """)
            
            severity_counts = dict(cursor.fetchall())
            
            # Расчет оценки безопасности (0-100, где 100 - отлично)
            score = 100
            deductions = {
                'Critical': 25,
                'High': 15,
                'Medium': 8,
                'Low': 3,
                'Info': 1
            }
            
            total_deduction = 0
            for severity, count in severity_counts.items():
                deduction = deductions.get(severity, 0) * count
                total_deduction += deduction
            
            score = max(0, score - total_deduction)
            
            # Определение уровня безопасности
            if score >= 90:
                level = "🟢 ОТЛИЧНО"
                emoji = "🟢"
            elif score >= 70:
                level = "🟡 ХОРОШО"
                emoji = "🟡"
            elif score >= 50:
                level = "🟠 СРЕДНЕ"
                emoji = "🟠"
            else:
                level = "🔴 КРИТИЧНО"
                emoji = "🔴"
            
            print(f"📊 Общая оценка безопасности: {emoji} {score}/100")
            print(f"🏆 Уровень: {level}")
            
            print(f"\n📈 Детализация:")
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    formatted_severity = self._format_severity(severity)
                    deduction = deductions.get(severity, 0) * count
                    print(f"   {formatted_severity}: {count} (-{deduction} баллов)")
            
            print(f"\n💡 Рекомендации:")
            if severity_counts.get('Critical', 0) > 0:
                print("   🔴 КРИТИЧНО: Немедленно исправьте критические уязвимости!")
            if severity_counts.get('High', 0) > 0:
                print("   🔴 ВЫСОКО: Приоритетно исправьте высокие уязвимости")
            if severity_counts.get('Medium', 0) > 5:
                print("   🟡 СРЕДНЕ: Рассмотрите исправление средних уязвимостей")
            if score >= 90:
                print("   🟢 ОТЛИЧНО: Система в хорошем состоянии безопасности")
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Ошибка: {e}")
    
    def show_all_reports(self, target: Optional[str] = None):
        """
        Показывает все 5 отчетов подряд
        """
        print("📊 ПОЛНЫЙ ОТЧЕТ ПО СКАНИРОВАНИЮ")
        print("=" * 60)
        
        reports = [
            ("Краткая сводка", self.quick_summary_report),
            ("Детальный анализ уязвимостей", self.detailed_vulnerabilities_report),
            ("История сканирований", self.scan_sessions_report),
            ("Хосты и субдомены", self.hosts_and_subdomains_report),
            ("Оценка безопасности", self.security_score_report)
        ]
        
        for title, report_func in reports:
            try:
                report_func(target)
            except Exception as e:
                print(f"❌ Ошибка в отчете '{title}': {e}")
        
        # Команды vulnx в конце
        self._print_vulnx_commands(target)
    
    def interactive_menu(self):
        """
        Интерактивное меню для выбора отчета
        """
        while True:
            print("\n" + "="*60)
            print("📊 МЕНЕДЖЕР ОТЧЕТОВ")
            print("="*60)
            print("1. 📈 Краткая сводка")
            print("2. 🔍 Детальный анализ уязвимостей")
            print("3. 📊 История сканирований")
            print("4. 🌐 Хосты и субдомены")
            print("5. 🛡️ Оценка безопасности")
            print("6. 📋 Все отчеты")
            print("0. 🚪 Выход")
            
            try:
                choice = input("\nВыберите отчет (0-6): ").strip()
                
                if choice == '0':
                    print("👋 До свидания!")
                    break
                elif choice == '1':
                    self.quick_summary_report()
                elif choice == '2':
                    self.detailed_vulnerabilities_report()
                elif choice == '3':
                    self.scan_sessions_report()
                elif choice == '4':
                    self.hosts_and_subdomains_report()
                elif choice == '5':
                    self.security_score_report()
                elif choice == '6':
                    self.show_all_reports()
                else:
                    print("❌ Неверный выбор. Попробуйте снова.")
                    continue
                
                # Показываем команды vulnx после каждого отчета
                self._print_vulnx_commands()
                
            except KeyboardInterrupt:
                print("\n👋 До свидания!")
                break
            except Exception as e:
                print(f"❌ Ошибка: {e}")

def main():
    """Основная функция"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Менеджер отчетов для результатов сканирования")
    parser.add_argument('--db', default='scan_results.db', help='Путь к базе данных')
    parser.add_argument('--target', help='Фильтр по цели')
    parser.add_argument('--report', type=int, choices=[1,2,3,4,5,6], 
                       help='Номер отчета (1-6, 6=все отчеты)')
    parser.add_argument('--interactive', '-i', action='store_true', 
                       help='Интерактивный режим')
    
    args = parser.parse_args()
    
    try:
        manager = ReportsManager(args.db)
        
        if args.interactive:
            manager.interactive_menu()
        elif args.report:
            reports = {
                1: manager.quick_summary_report,
                2: manager.detailed_vulnerabilities_report,
                3: manager.scan_sessions_report,
                4: manager.hosts_and_subdomains_report,
                5: manager.security_score_report,
                6: manager.show_all_reports
            }
            reports[args.report](args.target)
        else:
            # По умолчанию показываем все отчеты
            manager.show_all_reports(args.target)
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
