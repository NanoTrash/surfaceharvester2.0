# SurfaceHarvester

**Автоматизированный сбор и анализ уязвимостей и поверхностной информации о целях.**

---

## Особенности

- Асинхронное извлечение контактов с сайтов (aiohttp)
- Валидация входных данных и логирование ошибок
- Сканирование портов (nmap), директорий (gobuster dir), fuzzing параметров (gobuster fuzz), субдоменов (subfinder)
- Интеграция с Wappalyzer, Nikto, Nuclei, Subfinder, Gobuster, Nmap
- Единая база данных (SQLite) для хранения всех результатов
- Универсальный CLI-интерфейс для запуска сканеров с user-friendly вводом параметров
- Генерация отчётов по уязвимостям, ПО и CVE

---

## Установка зависимостей

### Python-зависимости (Poetry)

```bash
pip install poetry
poetry install
```

### Внешние утилиты (устанавливаются отдельно)

- **Nmap**:  
  `sudo apt install -y nmap`
- **Gobuster**:  
  `GO111MODULE=on go install github.com/OJ/gobuster/v3@latest`
- **Subfinder**:  
  `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- **Nikto**:  
  `sudo apt install nikto`
- **Nuclei**:  
  `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

> Убедитесь, что все утилиты доступны в PATH.

---

## Быстрый старт

1. Установите зависимости (см. выше).
2. Запустите CLI:

```bash
python cli.py
```

3. Следуйте интерактивным подсказкам для выбора сканера и ввода параметров (для каждого сканера показывается пример ввода).

---

## Архитектура процесса

1. **Сканеры** (Nmap, Nuclei, Nikto, Gobuster, Subfinder) — каждый даёт свой отчёт.
2. **Парсер-нормализатор** на Python:
   - конвертирует все результаты в единую структуру;
   - нормализует поля: `ip`, `port`, `service`, `cve`, `severity`, `scanner`.
3. **SQLite база** — единый источник правды:
   - таблица `Host` (IP, hostname)
   - таблица `Url` (host_id, url)
   - таблица `CVE` (cve_id, описание, критичность)
   - таблица `ScanResult` (url_id, cve_id, статус)
   - таблицы для ПО и версий (Software, VersionSoft)
4. **CLI** — единая точка входа, позволяет запускать любой сканер, сохранять результаты в базу и строить отчёты.

---

## Пример использования CLI

```bash
python cli.py
```

- Выберите сканер из меню.
- Введите параметры (будет показан пример).
- Результаты автоматически сохраняются в базу данных.

---

## Пример структуры базы

```sql
CREATE TABLE IF NOT EXISTS Host (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    ip_address TEXT
);

CREATE TABLE IF NOT EXISTS Url (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    url TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS CVE (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    description TEXT,
    severity TEXT
);

CREATE TABLE IF NOT EXISTS ScanResult (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER,
    cve_id INTEGER,
    status TEXT
);
```

---

## Отчёты

- После сканирования можно сгенерировать отчёты по уязвимым версиям ПО, устаревшим версиям и найденным CVE.
- Для этого используйте соответствующие функции в CLI или main.py.

---

## Best practices

- Используйте только актуальные версии инструментов.
- Не храните чувствительные данные в коде.
- Все результаты сохраняются в базе данных и могут быть экспортированы.
- Обрабатывайте ошибки всех внешних вызовов.

---

## Контакты и поддержка

- Вопросы и предложения — через Issues на GitHub.

## Настройка базы данных

- Используется SQLite, файл базы по умолчанию: scan_results.db (или scanner.db для main.py).
- Все необходимые таблицы создаются автоматически при первом запуске CLI или main.py — ручная настройка не требуется.
- Если база была удалена, просто перезапустите CLI, таблицы создадутся заново.
- Для ручной инициализации (например, если хотите убедиться, что структура создана):

```python
from db.schema import setup_database
import sqlite3
conn = sqlite3.connect('scan_results.db')
cursor = conn.cursor()
setup_database(cursor)
conn.commit()
conn.close()
```

**Важно:**
- Не перемещайте и не удаляйте файл базы данных без необходимости.
- Для резервного копирования достаточно скопировать файл scan_results.db.
