# SurfaceHarvester 2 - Инструмент для поверхностного анализа безопасности

Инструмент для комплексного сканирования веб-приложений и сетевых сервисов с использованием различных сканеров безопасности.

## Возможности

- **Nmap**: Сканирование портов и сервисов с проверкой уязвимостей
- **Wapiti**: Веб-сканер уязвимостей
- **Nuclei**: Быстрое сканирование уязвимостей по шаблонам
- **Subfinder**: Поиск субдоменов
- **Gobuster**: Поиск директорий и фаззинг параметров
- **Извлечение контактов**: Автоматическое извлечение email и телефонов с веб-страниц
- **AI-парсинг**: Интеллектуальная обработка результатов сканирования
- **База данных**: Сохранение результатов в SQLite
- **Отчеты**: Генерация подробных отчетов

## Установка

### Требования

- Python 3.8+
- Poetry (для управления зависимостями)
- Следующие инструменты должны быть установлены в системе:
  - `nmap` - сканирование портов
  - `wapiti` - веб-сканер уязвимостей
  - `nuclei` - сканер уязвимостей
  - `subfinder` - поиск субдоменов
  - `gobuster` - поиск директорий и фаззинг

### Установка зависимостей

```bash
# Клонирование репозитория
git clone <repository-url>
cd pntst

# Создание виртуального окружения и установка зависимостей
poetry install

# Активация виртуального окружения
poetry shell

# Установка spaCy модели (для AI-парсинга)
python -m spacy download en_core_web_sm
```

### Установка инструментов сканирования

#### Ubuntu/Debian:
```bash
# Nmap
sudo apt update && sudo apt install -y nmap

# Wapiti
sudo apt install -y wapiti

# Nuclei
curl -sfL https://raw.githubusercontent.com/projectdiscovery/nuclei/master/v2/cmd/nuclei/install.sh | sh -s

# Subfinder
curl -sfL https://raw.githubusercontent.com/projectdiscovery/subfinder/master/v2/cmd/subfinder/install.sh | sh -s

# Gobuster
sudo apt install -y gobuster
```

## Использование

### Полное сканирование

```bash
# Полное сканирование с использованием всех инструментов
python cli.py full-scan http://example.com --dir-wordlist /path/to/dir_wordlist.txt --fuzz-wordlist /path/to/fuzz_wordlist.txt
```

### Поверхностное сканирование

```bash
# Сканирование поверхности (nmap, gobuster, subfinder, контакты)
python cli.py surface http://example.com --dir-wordlist /path/to/dir_wordlist.txt --fuzz-wordlist /path/to/fuzz_wordlist.txt
```

### Просмотр отчетов

```bash
# Просмотр отчета по конкретной цели
python cli.py report --target http://example.com

# Список всех сессий сканирования
python cli.py list-sessions
```

### Инициализация базы данных

```bash
# Создание базы данных
python cli.py init
```
