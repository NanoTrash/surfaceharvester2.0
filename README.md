# SurfaceHarvester 2 — Инструмент для поверхностного анализа безопасности

Инструмент для комплексного сканирования веб-приложений и сетевых сервисов с использованием нескольких сканеров безопасности и AI-парсинга, с сохранением результатов в SQLite.

## 🚀 Быстрый старт

```bash
# 1. Клонирование и установка
git clone <repository-url>
cd surfaceharvester2.0
poetry install --no-root

# 2. Инициализация БД
poetry run python cli.py init --db scan_results.db

# 3. Первый скан
poetry run python cli.py full-scan http://testphp.vulnweb.com \
  --db scan_results.db \
  --dir-wordlist dir_wordlist.txt \
  --fuzz-wordlist LFI-Jhaddix.txt

# 4. Просмотр результатов
python reports.py 1                    # Краткая сводка
python reports.py 6                    # Эксплойты и CVE
```

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

## 📊 Команды отчетов

### Быстрые отчеты (python reports.py)

```bash
# 1. Краткая сводка (статистика уязвимостей)
python reports.py 1

# 2. Детальный анализ уязвимостей
python reports.py 2

# 3. История сессий сканирования
python reports.py 3

# 4. Хосты и субдомены
python reports.py 4

# 5. Оценка безопасности
python reports.py 5

# 6. Эксплойты и CVE
python reports.py 6

# 7. Все отчеты сразу
python reports.py 7

# Интерактивное меню
python reports.py i
```

### Расширенные отчеты (reports_manager.py)

```bash
# Краткая сводка
python reports_manager.py --report 1

# Детальный анализ
python reports_manager.py --report 2

# История сессий
python reports_manager.py --report 3

# Хосты и субдомены
python reports_manager.py --report 4

# Оценка безопасности
python reports_manager.py --report 5

# Эксплойты и CVE
python reports_manager.py --report 6

# Все отчеты
python reports_manager.py --report all
```

## 🔧 Команды Vulnx (эксплойты)

### Поиск и анализ эксплойтов

```bash
# Поиск эксплойтов по уязвимостям (последние 10)
poetry run python cli.py exploits search --limit 10

# Поиск по конкретной цели
poetry run python cli.py exploits search --target testphp.vulnweb.com --limit 5

# Статус обработки эксплойтов
poetry run python cli.py exploits status

# Подробный отчет по найденным эксплойтам
poetry run python cli.py exploits report

# Отчет по конкретной цели
poetry run python cli.py exploits report --target testphp.vulnweb.com

# Отчет в формате JSON
poetry run python cli.py exploits report --format json
```

### Мониторинг CVE

```bash
# Мониторинг новых CVE и автопоиск эксплойтов
poetry run python cli.py exploits monitor --interval 60

# Запуск мониторинга в фоне
poetry run python cli.py exploits monitor --interval 60 --daemon
```

## 🔧 Возможности и функции

### Сканеры безопасности
- **Nmap** - сканирование портов и извлечение уязвимостей через vulners
- **Nuclei** - шаблонное сканирование с обширной базой шаблонов
- **Wapiti** - веб-уязвимости (запуск через Docker)
- **Subfinder** - поиск субдоменов
- **Gobuster** - перебор директорий и параметров
- **Contacts** - извлечение email/телефонов со страниц

### AI-парсинг уязвимостей
- Автоматический анализ и классификация найденных уязвимостей
- Извлечение CVE, описаний и уровней критичности
- Интеграция с spaCy для обработки естественного языка

### База данных SQLite
- Централизованное хранение всех результатов
- Таблицы: `vulnerability`, `host`, `subdomain`, `scansession`, `cve`, `exploits`
- Поддержка множественных сессий сканирования

### Интеграция с Vulnx
- Автоматический поиск эксплойтов для найденных CVE
- Кэширование результатов для оптимизации
- Мониторинг новых уязвимостей в реальном времени

### Система отчетов
- **6 типов отчетов**: от краткой сводки до детального анализа
- **Интерактивное меню** для удобной навигации
- **Экспорт в JSON** для интеграции с другими инструментами
- **Оценка безопасности** с рекомендациями

## 📊 Принципы работы

### Пайплайн полного скана
1. **Nmap** - скан портов и извлечение уязвимостей (vulners)
2. **Contacts** - извлечение email/телефонов со стартовой страницы
3. **Wapiti** (Docker) - веб-уязвимости
4. **Nuclei** - шаблонное сканирование
5. **Subfinder** - поиск субдоменов
6. **Gobuster** - перебор директорий и параметров
7. **AI-парсинг** - анализ и классификация всех результатов

### Хранение данных
- **Таблица `host`**: хосты, IP-адреса, типы, родительские домены
- **Таблица `subdomain`**: субдомены с отслеживанием сессий
- **Таблица `vulnerability`**: все найденные уязвимости с метаданными
- **Таблица `exploits`**: эксплойты для найденных CVE
- **Таблица `cvecache`**: кэш результатов vulnx

### Сессии и отчеты
- Каждое сканирование создает запись в `scansession`
- Поддержка повторных сканов субдоменов
- Интерактивный выбор целей для сканирования
- Детальная история всех операций

## 📦 Установка

### Требования

- **Python 3.9+**
- **Poetry** (менеджер зависимостей)
- **Docker** (для Wapiti)
- **Инструменты сканирования**:
  - `nmap` - сканирование портов
  - `nuclei` - шаблонное сканирование
  - `subfinder` - поиск субдоменов
  - `gobuster` - перебор директорий

### Пошаговая установка

#### 1. Клонирование репозитория
```bash
git clone <repository-url>
cd surfaceharvester2.0
```

#### 2. Установка Python зависимостей
```bash
# Установка зависимостей через Poetry
poetry install --no-root

# Установка spaCy модели для AI-парсинга
poetry run python -m spacy download en_core_web_sm
```

#### 3. Установка инструментов сканирования

**Ubuntu/Debian:**
```bash
# Обновление и установка базовых инструментов
sudo apt update && sudo apt install -y nmap gobuster

# Nuclei (шаблонное сканирование)
curl -sfL https://raw.githubusercontent.com/projectdiscovery/nuclei/master/v2/cmd/nuclei/install.sh | sh -s

# Subfinder (поиск субдоменов)
curl -sfL https://raw.githubusercontent.com/projectdiscovery/subfinder/master/v2/cmd/subfinder/install.sh | sh -s
```

**macOS:**
```bash
# Установка через Homebrew
brew install nmap gobuster

# Nuclei и Subfinder
brew install nuclei subfinder
```

**Windows:**
```bash
# Установка через Chocolatey
choco install nmap

# Скачивание бинарных файлов с GitHub:
# - Nuclei: https://github.com/projectdiscovery/nuclei/releases
# - Subfinder: https://github.com/projectdiscovery/subfinder/releases
# - Gobuster: https://github.com/OJ/gobuster/releases
```

#### 4. Проверка установки
```bash
# Проверка доступности инструментов
nmap --version
nuclei --version
subfinder --version
gobuster version

# Проверка Python окружения
poetry run python cli.py --help
```

## ⚙️ Конфигурация

### Переменные окружения

```bash
# Docker образ для Wapiti (по умолчанию: cyberwatch/wapiti)
export SURFH2_WAPITI_DOCKER_IMAGE=cyberwatch/wapiti

# Авто-установка spaCy модели при первом запуске
export SURFH2_AUTO_INSTALL_SPACY=1

# Путь к базе данных (по умолчанию: scan_results.db)
export SURFH2_DB_PATH=scan_results.db

# Уровень логирования (DEBUG, INFO, WARNING, ERROR)
export SURFH2_LOG_LEVEL=INFO
```

### Wapiti через Docker

- Локальная установка Wapiti не требуется
- Сканер запускается в контейнере Docker (`cyberwatch/wapiti`)
- HTML-отчёт автоматически монтируется и преобразуется в единый формат
- Образ можно переопределить переменной `SURFH2_WAPITI_DOCKER_IMAGE`

### Структура проекта

```
surfaceharvester2.0/
├── cli.py                 # Основной CLI интерфейс
├── reports.py             # Быстрые отчеты
├── reports_manager.py     # Расширенная система отчетов
├── db/                    # Модули базы данных
│   ├── models.py          # Модели данных
│   ├── schema.py          # Схема БД
│   └── report.py          # Функции отчетов
├── scanner/               # Модули сканирования
│   ├── full_scanner.py    # Полное сканирование
│   ├── nuclei.py          # Nuclei интеграция
│   ├── vulnx_processor.py # Vulnx интеграция
│   └── ai_parser.py       # AI-парсинг
├── scan_results.db        # База данных результатов
└── wordlists/             # Словари для сканирования
```

## 🚀 Примеры использования

### Рабочий процесс

```bash
# 1. Сканирование новой цели
poetry run python cli.py full-scan http://example.com \
  --db scan_results.db \
  --dir-wordlist common.txt \
  --fuzz-wordlist LFI-Jhaddix.txt

# 2. Анализ результатов
python reports.py 1                    # Краткая сводка
python reports.py 2                    # Детальный анализ
python reports.py 5                    # Оценка безопасности
python reports.py 6                    # Эксплойты и CVE

# 3. Поиск эксплойтов для найденных CVE
poetry run python cli.py exploits search --limit 20
poetry run python cli.py exploits report --format json

# 4. Мониторинг новых уязвимостей
poetry run python cli.py exploits monitor --interval 300 --daemon
```

### Повторное сканирование субдоменов

```bash
# Просмотр найденных субдоменов
poetry run python cli.py targets-list --db scan_results.db --subdomains

# Сканирование всех субдоменов
poetry run python cli.py targets-scan \
  --db scan_results.db \
  --dir-wordlist common.txt \
  --fuzz-wordlist LFI-Jhaddix.txt \
  --subdomains
```

### Интерактивные отчеты

```bash
# Запуск интерактивного меню отчетов
python reports.py i

# Или через reports_manager.py
python reports_manager.py --interactive
```

## 🔧 Устранение неполадок

### Частые проблемы

**Ошибка: "command not found" для nmap/nuclei/subfinder**
```bash
# Проверьте установку инструментов
which nmap nuclei subfinder gobuster

# Если не установлены, выполните установку заново
sudo apt install nmap gobuster  # Ubuntu/Debian
brew install nmap gobuster      # macOS
```

**Ошибка: "Docker not found"**
```bash
# Установка Docker
sudo apt install docker.io      # Ubuntu/Debian
brew install docker            # macOS

# Добавление пользователя в группу docker
sudo usermod -aG docker $USER
```

**Ошибка: "spaCy model not found"**
```bash
# Установка spaCy модели
poetry run python -m spacy download en_core_web_sm

# Или установка через Poetry
poetry run spacy download en_core_web_sm
```

**Ошибка: "database is locked"**
```bash
# Закройте все процессы, использующие БД
# Или используйте другую БД
poetry run python cli.py init --db new_scan_results.db
```

**Ошибка: "vulnx not found"**
```bash
# Установка vulnx
go install github.com/khulnasoft-lab/vulnx/cmd/vulnx@latest

# Проверка установки
vulnx --version
```

### Логи и отладка

```bash
# Включение подробного логирования
export SURFH2_LOG_LEVEL=DEBUG

# Просмотр логов в реальном времени
tail -f surfaceharvester.log

# Проверка конфигурации
poetry run python cli.py --help
```

## 📝 Лицензия

MIT License - см. файл LICENSE для подробностей.

## 🤝 Вклад в проект

1. Форкните репозиторий
2. Создайте ветку для новой функции (`git checkout -b feature/amazing-feature`)
3. Зафиксируйте изменения (`git commit -m 'Add amazing feature'`)
4. Отправьте в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request