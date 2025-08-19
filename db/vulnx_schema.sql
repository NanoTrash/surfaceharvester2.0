-- Таблица для хранения найденных эксплойтов
CREATE TABLE IF NOT EXISTS exploits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    exploit_type TEXT NOT NULL, -- 'poc', 'exploit', 'nuclei_template'
    source TEXT NOT NULL, -- 'github', 'exploitdb', 'nuclei', 'packetstorm', 'etc'
    title TEXT,
    description TEXT,
    url TEXT,
    file_path TEXT, -- локальный путь если скачан
    language TEXT, -- python, c, bash, etc
    severity_score INTEGER DEFAULT 0, -- приоритет 0-10
    is_working BOOLEAN DEFAULT NULL, -- протестирован ли
    metadata JSON, -- дополнительные данные из vulnx
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerability(id)
);

-- Кэш запросов к vulnx для избежания повторных вызовов
CREATE TABLE IF NOT EXISTS cve_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE NOT NULL,
    vulnx_response JSON, -- полный ответ vulnx
    exploits_found INTEGER DEFAULT 0,
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_stale BOOLEAN DEFAULT 0 -- устарел ли кэш
);

-- Таблица для отслеживания обработки CVE
CREATE TABLE IF NOT EXISTS cve_processing (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    status TEXT DEFAULT 'pending', -- pending, processing, completed, failed
    vulnx_checked BOOLEAN DEFAULT 0,
    nuclei_checked BOOLEAN DEFAULT 0,
    exploits_downloaded BOOLEAN DEFAULT 0,
    last_processed TIMESTAMP,
    error_message TEXT,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerability(id)
);

-- Индексы для производительности
CREATE INDEX IF NOT EXISTS idx_exploits_cve_id ON exploits(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_type ON exploits(exploit_type);
CREATE INDEX IF NOT EXISTS idx_exploits_severity ON exploits(severity_score DESC);
CREATE INDEX IF NOT EXISTS idx_cve_cache_cve_id ON cve_cache(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_processing_status ON cve_processing(status);
