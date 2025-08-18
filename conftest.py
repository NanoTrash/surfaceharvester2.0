import os
import sys

# Добавляем корень репозитория в PYTHONPATH для импорта локальных пакетов
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


