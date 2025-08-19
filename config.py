# config.py
"""
Конфигурационный файл для SurfaceHarvester
"""

import os
import tempfile
from pathlib import Path

# Основные настройки
PROJECT_NAME = "SurfaceHarvester"
VERSION = "0.1.0"

# Настройки безопасности
ALLOWED_PROTOCOLS = ["http", "https"]
DANGEROUS_CHARS = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']']

# Настройки сканирования
MAX_SCAN_TIMEOUT = 300  # 5 минут
MAX_CONCURRENT_SCANS = 3
DEFAULT_SCANNERS = ['nuclei']  # Убран wapiti - был нестабильным

# Настройки файлов
TEMP_DIR = os.getenv('SURFACEHARVESTER_TEMP_DIR', tempfile.gettempdir())
DEFAULT_DB_FILE = "scan_results.db"
LOG_FILE = "surfaceharvester.log"

# Настройки логирования
LOG_LEVEL = os.getenv('SURFACEHARVESTER_LOG_LEVEL', 'INFO')
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Настройки базы данных
DB_TIMEOUT = 30
DB_CHECK_SAME_THREAD = False

# Настройки AI парсера
AI_SIMILARITY_THRESHOLD = 0.3
AI_MAX_DESCRIPTION_LENGTH = 200

# Настройки отчетов
REPORT_MAX_VULNERABILITIES = 1000
REPORT_DESCRIPTION_TRUNCATE = 100

# Настройки валидации
MIN_URL_LENGTH = 10
MAX_URL_LENGTH = 2048

# Настройки безопасности сканеров
SCANNER_TIMEOUT = 300
SCANNER_MAX_RETRIES = 3

# Настройки для разных сканеров
NIKTO_CONFIG = {
    'timeout': 300,
    'format': 'json',
    'output_dir': TEMP_DIR
}

NUCLEI_CONFIG = {
    'timeout': 300,
    'silent': True,
    'json_output': True
}

# Функции для получения настроек
def get_temp_dir():
    """Возвращает временную директорию"""
    return Path(TEMP_DIR)

def get_db_path(db_file=None):
    """Возвращает путь к базе данных"""
    if db_file is None:
        db_file = DEFAULT_DB_FILE
    return Path(db_file)

def get_log_path():
    """Возвращает путь к файлу логов"""
    return Path(LOG_FILE)

def validate_config():
    """Проверяет корректность конфигурации"""
    errors = []
    
    # Проверяем временную директорию
    if not os.path.exists(TEMP_DIR):
        try:
            os.makedirs(TEMP_DIR, exist_ok=True)
        except Exception as e:
            errors.append(f"Не удалось создать временную директорию: {e}")
    
    # Проверяем права на запись
    if not os.access(TEMP_DIR, os.W_OK):
        errors.append(f"Нет прав на запись в временную директорию: {TEMP_DIR}")
    
    # Проверяем настройки таймаутов
    if MAX_SCAN_TIMEOUT <= 0:
        errors.append("MAX_SCAN_TIMEOUT должен быть больше 0")
    
    if SCANNER_TIMEOUT <= 0:
        errors.append("SCANNER_TIMEOUT должен быть больше 0")
    
    return errors
