# config_logging.py

import logging
import logging.handlers
import os
from datetime import datetime

def setup_logging(log_level=logging.INFO, log_file=None, enable_console=True):
    """
    Настраивает логирование для приложения
    
    Args:
        log_level: Уровень логирования (DEBUG, INFO, WARNING, ERROR)
        log_file: Путь к файлу лога (если None, создается автоматически)
        enable_console: Выводить логи в консоль
    """
    
    # Создаем корневой логгер
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Очищаем существующие обработчики
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Формат логов
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Консольный обработчик
    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(simple_formatter)
        root_logger.addHandler(console_handler)
    
    # Файловый обработчик
    if log_file is None:
        log_file = f"surfaceharvester2.0_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    try:
        # Создаем директорию для логов если не существует
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Ротирующий файловый обработчик
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, 
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(file_handler)
        
        logging.info(f"Логирование настроено. Файл: {log_file}")
        
    except Exception as e:
        logging.warning(f"Не удалось настроить файловое логирование: {e}")
    
    # Специфичные логгеры для разных компонентов
    setup_component_loggers()

def setup_component_loggers():
    """Настраивает логгеры для конкретных компонентов"""
    
    # Логгер для VulnerabilityManager
    vuln_logger = logging.getLogger('db.vulnerability_manager')
    vuln_logger.setLevel(logging.INFO)
    
    # Логгеры для сканеров
    scanner_loggers = [
        'scanner.nuclei',
        # 'scanner.wapiti',  # УДАЛЕНО: Wapiti больше не используется 
        'scanner.nmap',
        'scanner.gobuster',
        'scanner.full_scanner'
    ]
    
    for logger_name in scanner_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
    
    # Логгер для AI парсера
    ai_logger = logging.getLogger('scanner.ai_parser')
    ai_logger.setLevel(logging.INFO)
    
    # Логгер для базы данных
    db_logger = logging.getLogger('db')
    db_logger.setLevel(logging.INFO)

def get_performance_logger():
    """Создает специальный логгер для метрик производительности"""
    perf_logger = logging.getLogger('performance')
    perf_logger.setLevel(logging.INFO)
    
    # Отдельный файл для метрик
    try:
        perf_handler = logging.FileHandler('performance_metrics.log')
        perf_formatter = logging.Formatter(
            '%(asctime)s,%(message)s'  # CSV формат для анализа
        )
        perf_handler.setFormatter(perf_formatter)
        perf_logger.addHandler(perf_handler)
        perf_logger.propagate = False  # Не передавать в родительские логгеры
    except Exception as e:
        logging.warning(f"Не удалось настроить логгер производительности: {e}")
    
    return perf_logger

def log_scan_metrics(scanner_name, target, duration, vulnerabilities_found, errors_count=0):
    """
    Логирует метрики сканирования в структурированном формате
    """
    perf_logger = get_performance_logger()
    
    metrics = {
        'timestamp': datetime.now().isoformat(),
        'scanner': scanner_name,
        'target': target,
        'duration_seconds': round(duration, 2),
        'vulnerabilities_found': vulnerabilities_found,
        'errors_count': errors_count,
        'success_rate': round((vulnerabilities_found / max(vulnerabilities_found + errors_count, 1)) * 100, 2)
    }
    
    # CSV формат для простого анализа
    csv_line = f"{metrics['timestamp']},{metrics['scanner']},{metrics['target']},{metrics['duration_seconds']},{metrics['vulnerabilities_found']},{metrics['errors_count']},{metrics['success_rate']}"
    perf_logger.info(csv_line)
    
    # Также логируем в основной лог
    logging.info(f"Метрики сканирования {scanner_name}: {vulnerabilities_found} уязвимостей за {duration:.2f}с")

# Настройка логирования при импорте модуля
if __name__ != "__main__":
    # Базовая настройка логирования при импорте
    setup_logging(log_level=logging.INFO, log_file="logs/surfaceharvester2.0.log")
