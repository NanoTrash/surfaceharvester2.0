#!/usr/bin/env python3
"""
Event-driven обработчик CVE для автоматического поиска эксплойтов
Мониторит новые уязвимости и запускает vulnx обработку
"""

import asyncio
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List
import threading
import signal
import sys

from vulnx_processor import VulnXProcessor

logger = logging.getLogger(__name__)

class CVEMonitor:
    """Мониторинг новых CVE и автоматическая обработка через vulnx"""
    
    def __init__(self, db_path: str = "scan_results.db", check_interval: int = 60):
        self.db_path = db_path
        self.check_interval = check_interval  # секунды между проверками
        self.processor = VulnXProcessor(db_path)
        self.running = False
        self.worker_thread = None
        
        # Последняя проверка
        self.last_check = datetime.now() - timedelta(hours=1)
        
        # Настройка graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Обработчик сигналов для graceful shutdown"""
        logger.info(f"Получен сигнал {signum}, завершаю работу...")
        self.stop()
        sys.exit(0)
    
    def get_new_vulnerabilities(self) -> List[Dict]:
        """Получает новые уязвимости с момента последней проверки"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Ищем уязвимости, созданные после последней проверки
            cursor.execute("""
                SELECT v.id, v.description, v.vulnerability_type, v.resource, v.created_at
                FROM vulnerability v
                LEFT JOIN cve_processing cp ON v.id = cp.vulnerability_id
                WHERE v.created_at > ?
                AND (v.description LIKE '%CVE-%' OR v.description LIKE '%cve-%')
                AND (cp.vulnerability_id IS NULL OR cp.status IN ('failed', 'pending'))
                ORDER BY v.created_at DESC
            """, (self.last_check.isoformat(),))
            
            vulnerabilities = []
            for row in cursor.fetchall():
                vuln_id, description, vuln_type, resource, created_at = row
                vulnerabilities.append({
                    'id': vuln_id,
                    'description': description,
                    'type': vuln_type,
                    'resource': resource,
                    'created_at': created_at
                })
            
            conn.close()
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Ошибка получения новых уязвимостей: {e}")
            return []
    
    def process_new_vulnerabilities(self, vulnerabilities: List[Dict]):
        """Обрабатывает список новых уязвимостей"""
        if not vulnerabilities:
            return
        
        logger.info(f"Обрабатываю {len(vulnerabilities)} новых уязвимостей")
        
        for vuln in vulnerabilities:
            try:
                logger.info(f"Обрабатываю уязвимость {vuln['id']} ({vuln['type']})")
                
                result = self.processor.process_vulnerability(
                    vuln['id'], 
                    vuln['description']
                )
                
                if result['total_exploits'] > 0:
                    logger.info(f"✅ Найдено {result['total_exploits']} эксплойтов для уязвимости {vuln['id']}")
                    
                    # Отправляем уведомление о найденных эксплойтах
                    self._notify_exploits_found(vuln, result)
                else:
                    logger.info(f"ℹ️  Эксплойты для уязвимости {vuln['id']} не найдены")
                
            except Exception as e:
                logger.error(f"Ошибка обработки уязвимости {vuln['id']}: {e}")
            
            # Пауза между обработкой уязвимостей
            time.sleep(2)
    
    def _notify_exploits_found(self, vulnerability: Dict, result: Dict):
        """Отправляет уведомление о найденных эксплойтах"""
        # Здесь можно добавить интеграцию с системами уведомлений:
        # - Slack/Discord webhook
        # - Telegram bot
        # - Email
        # - SIEM системы
        
        logger.warning(f"🚨 НАЙДЕНЫ ЭКСПЛОЙТЫ для {vulnerability['resource']}")
        logger.warning(f"   Уязвимость: {vulnerability['type']}")
        logger.warning(f"   Всего эксплойтов: {result['total_exploits']}")
        
        for cve_result in result['processed_cves']:
            if cve_result['exploits_count'] > 0:
                logger.warning(f"   {cve_result['cve_id']}: {cve_result['exploits_count']} эксплойтов")
        
        # Можно добавить webhook для внешних систем
        # self._send_webhook_notification(vulnerability, result)
    
    def check_stale_cache(self):
        """Помечает устаревший кэш для повторной обработки"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Помечаем кэш старше 7 дней как устаревший
            stale_date = (datetime.now() - timedelta(days=7)).isoformat()
            
            cursor.execute("""
                UPDATE cve_cache 
                SET is_stale = 1 
                WHERE last_checked < ? AND is_stale = 0
            """, (stale_date,))
            
            stale_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if stale_count > 0:
                logger.info(f"Помечено {stale_count} записей кэша как устаревшие")
                
        except Exception as e:
            logger.error(f"Ошибка проверки устаревшего кэша: {e}")
    
    def retry_failed_processing(self):
        """Повторяет обработку failed уязвимостей"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Ищем failed обработки старше 1 часа
            retry_date = (datetime.now() - timedelta(hours=1)).isoformat()
            
            cursor.execute("""
                SELECT DISTINCT cp.vulnerability_id, v.description
                FROM cve_processing cp
                JOIN vulnerability v ON cp.vulnerability_id = v.id
                WHERE cp.status = 'failed' 
                AND cp.last_processed < ?
                LIMIT 10
            """, (retry_date,))
            
            failed_vulns = cursor.fetchall()
            conn.close()
            
            if failed_vulns:
                logger.info(f"Повторяю обработку {len(failed_vulns)} failed уязвимостей")
                
                for vuln_id, description in failed_vulns:
                    try:
                        result = self.processor.process_vulnerability(vuln_id, description)
                        logger.info(f"Повтор уязвимости {vuln_id}: {result['total_exploits']} эксплойтов")
                    except Exception as e:
                        logger.error(f"Ошибка повтора уязвимости {vuln_id}: {e}")
                    
                    time.sleep(1)
                    
        except Exception as e:
            logger.error(f"Ошибка повтора failed обработок: {e}")
    
    def _monitor_loop(self):
        """Основной цикл мониторинга"""
        logger.info("Запуск CVE мониторинга...")
        
        while self.running:
            try:
                # Получаем новые уязвимости
                new_vulns = self.get_new_vulnerabilities()
                
                if new_vulns:
                    self.process_new_vulnerabilities(new_vulns)
                
                # Обновляем время последней проверки
                self.last_check = datetime.now()
                
                # Каждые 10 циклов проверяем устаревший кэш и failed обработки
                if hasattr(self, '_cycle_count'):
                    self._cycle_count += 1
                else:
                    self._cycle_count = 1
                
                if self._cycle_count % 10 == 0:
                    self.check_stale_cache()
                    self.retry_failed_processing()
                
                # Ждем до следующей проверки
                for _ in range(self.check_interval):
                    if not self.running:
                        break
                    time.sleep(1)
                
            except Exception as e:
                logger.error(f"Ошибка в цикле мониторинга: {e}")
                time.sleep(30)  # Ждем 30 секунд при ошибке
    
    def start(self):
        """Запуск мониторинга в отдельном потоке"""
        if self.running:
            logger.warning("Мониторинг уже запущен")
            return
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.worker_thread.start()
        
        logger.info(f"CVE мониторинг запущен (интервал: {self.check_interval}s)")
    
    def stop(self):
        """Остановка мониторинга"""
        if not self.running:
            return
        
        logger.info("Остановка CVE мониторинга...")
        self.running = False
        
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=30)
        
        logger.info("CVE мониторинг остановлен")
    
    def get_status(self) -> Dict:
        """Получает статус мониторинга"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Статистика обработки
            cursor.execute("""
                SELECT status, COUNT(*) 
                FROM cve_processing 
                GROUP BY status
            """)
            processing_stats = dict(cursor.fetchall())
            
            # Статистика эксплойтов
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_exploits,
                    COUNT(DISTINCT cve_id) as unique_cves,
                    COUNT(DISTINCT vulnerability_id) as vulnerable_assets
                FROM exploits
            """)
            exploit_stats = cursor.fetchone()
            
            # Последние обработанные
            cursor.execute("""
                SELECT cve_id, status, last_processed 
                FROM cve_processing 
                ORDER BY last_processed DESC 
                LIMIT 5
            """)
            recent_processing = cursor.fetchall()
            
            conn.close()
            
            return {
                'running': self.running,
                'last_check': self.last_check.isoformat(),
                'check_interval': self.check_interval,
                'processing_stats': processing_stats,
                'exploit_stats': {
                    'total_exploits': exploit_stats[0] if exploit_stats else 0,
                    'unique_cves': exploit_stats[1] if exploit_stats else 0,
                    'vulnerable_assets': exploit_stats[2] if exploit_stats else 0
                },
                'recent_processing': recent_processing
            }
            
        except Exception as e:
            logger.error(f"Ошибка получения статуса: {e}")
            return {'running': self.running, 'error': str(e)}


class CVEProcessor:
    """Высокоуровневый интерфейс для обработки CVE"""
    
    def __init__(self, db_path: str = "scan_results.db"):
        self.db_path = db_path
        self.processor = VulnXProcessor(db_path)
        self.monitor = CVEMonitor(db_path)
    
    async def process_all_pending(self, limit: int = 100) -> Dict:
        """Обрабатывает все pending уязвимости"""
        pending = self.processor.get_pending_vulnerabilities(limit)
        
        if not pending:
            return {'processed': 0, 'exploits_found': 0}
        
        logger.info(f"Обрабатываю {len(pending)} pending уязвимостей...")
        
        total_exploits = 0
        processed_count = 0
        
        for vuln_id, description in pending:
            try:
                result = self.processor.process_vulnerability(vuln_id, description)
                total_exploits += result['total_exploits']
                processed_count += 1
                
                if result['total_exploits'] > 0:
                    logger.info(f"✅ Уязвимость {vuln_id}: {result['total_exploits']} эксплойтов")
                
                # Небольшая пауза между запросами
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Ошибка обработки уязвимости {vuln_id}: {e}")
        
        return {'processed': processed_count, 'exploits_found': total_exploits}
    
    def start_monitoring(self, interval: int = 60):
        """Запускает автоматический мониторинг"""
        self.monitor.check_interval = interval
        self.monitor.start()
    
    def stop_monitoring(self):
        """Останавливает мониторинг"""
        self.monitor.stop()
    
    def get_exploit_report(self) -> Dict:
        """Генерирует отчёт по найденным эксплойтам"""
        return self.processor.get_exploit_summary()


def main():
    """CLI интерфейс для CVE обработчика"""
    import argparse
    
    parser = argparse.ArgumentParser(description="CVE Monitor and Processor")
    parser.add_argument('--db', default='scan_results.db', help='Путь к базе данных')
    parser.add_argument('--interval', type=int, default=60, help='Интервал мониторинга (секунды)')
    
    subparsers = parser.add_subparsers(dest='command', help='Команды')
    
    # Команда monitor
    monitor_parser = subparsers.add_parser('monitor', help='Запуск мониторинга')
    monitor_parser.add_argument('--daemon', action='store_true', help='Запуск в фоне')
    
    # Команда process
    process_parser = subparsers.add_parser('process', help='Обработка pending уязвимостей')
    process_parser.add_argument('--limit', type=int, default=50, help='Лимит обработки')
    
    # Команда status
    status_parser = subparsers.add_parser('status', help='Статус обработки')
    
    # Команда report
    report_parser = subparsers.add_parser('report', help='Отчёт по эксплойтам')
    
    args = parser.parse_args()
    
    # Настройка логирования
    level = logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    processor = CVEProcessor(args.db)
    
    if args.command == 'monitor':
        try:
            processor.start_monitoring(args.interval)
            
            if args.daemon:
                logger.info("Мониторинг запущен в фоне. Для остановки используйте Ctrl+C")
                try:
                    while True:
                        time.sleep(60)
                        status = processor.monitor.get_status()
                        logger.info(f"Статус: обработано {sum(status.get('processing_stats', {}).values())} CVE")
                except KeyboardInterrupt:
                    logger.info("Получен сигнал остановки")
            else:
                logger.info("Мониторинг запущен. Нажмите Ctrl+C для остановки")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
        finally:
            processor.stop_monitoring()
    
    elif args.command == 'process':
        async def run_processing():
            result = await processor.process_all_pending(args.limit)
            print(f"Обработано: {result['processed']} уязвимостей")
            print(f"Найдено эксплойтов: {result['exploits_found']}")
        
        asyncio.run(run_processing())
    
    elif args.command == 'status':
        status = processor.monitor.get_status()
        print("=== Статус CVE обработки ===")
        print(f"Мониторинг активен: {status['running']}")
        print(f"Последняя проверка: {status['last_check']}")
        print(f"Интервал: {status['check_interval']}s")
        print(f"\nСтатистика обработки:")
        for status_name, count in status.get('processing_stats', {}).items():
            print(f"  {status_name}: {count}")
        print(f"\nСтатистика эксплойтов:")
        exploit_stats = status.get('exploit_stats', {})
        print(f"  Всего эксплойтов: {exploit_stats.get('total_exploits', 0)}")
        print(f"  Уникальных CVE: {exploit_stats.get('unique_cves', 0)}")
        print(f"  Уязвимых ресурсов: {exploit_stats.get('vulnerable_assets', 0)}")
    
    elif args.command == 'report':
        report = processor.get_exploit_report()
        print("=== Отчёт по эксплойтам ===")
        print(f"Статистика по типам:")
        for stat in report.get('stats', []):
            print(f"  {stat[3]} ({stat[4]}, {stat[5]}): {stat[0]} эксплойтов")
        print(f"\nТоп CVE по количеству эксплойтов:")
        for cve_stat in report.get('top_cves', []):
            print(f"  {cve_stat[0]}: {cve_stat[1]} эксплойтов (severity: {cve_stat[2]:.1f})")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
