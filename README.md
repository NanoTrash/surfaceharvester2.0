# SurfaceHarvester 2 — Инструмент для поверхностного анализа безопасности

Инструмент для комплексного сканирования веб-приложений и сетевых сервисов с использованием нескольких сканеров безопасности и AI-парсинга, с сохранением результатов в SQLite.

## Команды CLI (основное)

- **Инициализация БД**:
  ```bash
  poetry install --no-root
  poetry run python cli.py init --db scan_results.db
  ```

- **Полный скан** (nmap, wapiti, nuclei, subfinder, gobuster; с интерактивным выбором субдоменов для повторных сканов):
  ```bash
  poetry run python cli.py full-scan http://example.com \
    --db scan_results.db \
    --dir-wordlist /path/to/dir_wordlist.txt \
    --fuzz-wordlist /path/to/fuzz_wordlist.txt
  ```

- **Поверхностный сбор** (без сохранения уязвимостей в БД, отчёт в файл):
  ```bash
  poetry run python cli.py surface example.com \
    --dir-wordlist /path/to/dir_wordlist.txt \
    --fuzz-wordlist /path/to/fuzz_wordlist.txt \
    --output scan_results.txt
  ```

- **Просмотр уязвимостей и сводок**:
  ```bash
  # Полный отчёт по цели из БД
  poetry run python cli.py report --target http://example.com --db scan_results.db

  # Краткая сводка c эмодзи
  poetry run python cli.py summary --target http://example.com --db scan_results.db

  # История сессий
  poetry run python cli.py sessions --db scan_results.db
  ```

- **Работа с целями (хосты/субдомены) из БД**:
  ```bash
  # Показать сохранённые цели (host.hostname)
  poetry run python cli.py targets-list --db scan_results.db

  # Показать только субдомены
  poetry run python cli.py targets-list --db scan_results.db --subdomains

  # Выбрать цели из БД и запустить полные сканы
  poetry run python cli.py targets-scan \
    --db scan_results.db \
    --dir-wordlist /path/to/dir_wordlist.txt \
    --fuzz-wordlist /path/to/fuzz_wordlist.txt \
    --subdomains
  ```

## Принципы работы

- **Пайплайн полного скана**:
  - Nmap: скан портов и извлечение уязвимостей (vulners).
  - Извлечение контактов (email/телефоны) со стартовой страницы.
  - Wapiti: веб-уязвимости; Nuclei: шаблонное сканирование.
  - Subfinder: поиск субдоменов.
  - Gobuster dir/fuzz: директории и параметры.
  - Все результаты уязвимостей проходят **AI-парсинг** и сохраняются в `vulnerability`.

- **Хранение целей**:
  - Таблица `host`: `hostname`, `ip_address`, `type` (`domain`/`subdomain`/`ip`), `parent_domain`, `session_id`, `last_scanned_session_id`, `source`, `target`.
  - Таблица `subdomain`: `name`, `parent_domain`, `host_id`, `session_first_seen`, `session_last_seen`, `source`, `target`.
  - Результаты subfinder и IP целей автоматически сохраняются и индексируются.

- **Сессии и отчёты**:
  - Каждое полное сканирование — запись в `scansession`.
  - Просмотр отчётов и сводок через команды `report`, `summary`, `sessions`.
  - Повторные сканы субдоменов доступны интерактивно сразу после `full-scan` и через `targets-scan`.

## Установка

### Требования

- Python 3.9+
- Poetry
- Инструменты системы:
  - `nmap`, `wapiti`, `nuclei`, `subfinder`, `gobuster`

### Установка зависимостей

```bash
# Клонирование репозитория
git clone <repository-url>
cd pntst

# Установка зависимостей (без установки самого пакета)
poetry install --no-root

# (опционально) Установка spaCy модели для AI-парсинга
poetry run python -m spacy download en_core_web_sm
```

### Установка инструментов сканирования (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install -y nmap wapiti gobuster

# Nuclei
curl -sfL https://raw.githubusercontent.com/projectdiscovery/nuclei/master/v2/cmd/nuclei/install.sh | sh -s

# Subfinder
curl -sfL https://raw.githubusercontent.com/projectdiscovery/subfinder/master/v2/cmd/subfinder/install.sh | sh -s
```

### Быстрый старт

```bash
# 1) Инициализация БД
poetry run python cli.py init --db scan_results.db

# 2) Первый полный скан
poetry run python cli.py full-scan http://example.com \
  --db scan_results.db \
  --dir-wordlist /path/to/dir_wordlist.txt \
  --fuzz-wordlist /path/to/fuzz_wordlist.txt

# 3) Просмотр целей и запуск повторных сканов
poetry run python cli.py targets-list --db scan_results.db --subdomains
poetry run python cli.py targets-scan --db scan_results.db --dir-wordlist /path/to/dir_wordlist.txt --fuzz-wordlist /path/to/fuzz_wordlist.txt --subdomains
```
