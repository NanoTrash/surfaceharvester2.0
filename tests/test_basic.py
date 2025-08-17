# tests/test_basic.py

import pytest
import tempfile
import os
import sqlite3
from unittest.mock import patch, MagicMock

from db.models import Vulnerability, ScanSession, Host, Url, CVE, ScanResult
from db.schema import setup_database
from scanner.ai_parser import AIVulnerabilityParser


class TestDatabaseModels:
    """Тесты для моделей базы данных"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.temp_db.name
        self.temp_db.close()
        
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        setup_database(self.cursor)
        self.conn.commit()
    
    def teardown_method(self):
        """Очистка после каждого теста"""
        self.conn.close()
        os.unlink(self.db_path)
    
    def test_vulnerability_insert(self):
        """Тест вставки уязвимости"""
        Vulnerability.insert(
            self.cursor,
            resource="https://example.com",
            vulnerability_type="SQL Injection",
            description="Test vulnerability",
            severity="High",
            scanner="nikto"
        )
        
        self.cursor.execute("SELECT * FROM vulnerability")
        result = self.cursor.fetchone()
        
        assert result is not None
        assert result[1] == "https://example.com"  # resource
        assert result[2] == "SQL Injection"  # vulnerability_type
        assert result[3] == "Test vulnerability"  # description
        assert result[4] == "High"  # severity
        assert result[5] == "nikto"  # scanner
    
    def test_scan_session_insert(self):
        """Тест вставки сессии сканирования"""
        ScanSession.insert(
            self.cursor,
            target="https://example.com",
            status="running"
        )
        
        self.cursor.execute("SELECT * FROM scansession")
        result = self.cursor.fetchone()
        
        assert result is not None
        assert result[1] == "https://example.com"  # target
        assert result[4] == "running"  # status
    
    def test_scan_session_update(self):
        """Тест обновления сессии сканирования"""
        # Вставляем сессию
        ScanSession.insert(
            self.cursor,
            target="https://example.com",
            status="running"
        )
        session_id = self.cursor.lastrowid
        
        # Обновляем статус
        ScanSession.update(
            self.cursor,
            session_id,
            status="completed",
            end_time="2023-01-01T12:00:00"
        )
        
        # Проверяем обновление
        result = ScanSession.select_by_id(self.cursor, session_id)
        assert result[4] == "completed"  # status
        assert result[3] == "2023-01-01T12:00:00"  # end_time


class TestAIParser:
    """Тесты для AI парсера"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.parser = AIVulnerabilityParser()
    
    def test_extract_vulnerability_type_sql_injection(self):
        """Тест извлечения типа SQL Injection"""
        text = "SQL injection vulnerability found in login form"
        vuln_type = self.parser.extract_vulnerability_type(text)
        assert vuln_type == "SQL Injection"
    
    def test_extract_vulnerability_type_xss(self):
        """Тест извлечения типа XSS"""
        text = "Cross-site scripting vulnerability detected"
        vuln_type = self.parser.extract_vulnerability_type(text)
        assert vuln_type == "XSS"
    
    def test_extract_vulnerability_type_unknown(self):
        """Тест извлечения неизвестного типа"""
        text = "Some random text without vulnerability keywords"
        vuln_type = self.parser.extract_vulnerability_type(text)
        assert vuln_type == "Unknown"
    
    def test_extract_severity_critical(self):
        """Тест извлечения критической критичности"""
        text = "Critical vulnerability found"
        severity = self.parser.extract_severity(text)
        assert severity == "Critical"
    
    def test_extract_severity_high(self):
        """Тест извлечения высокой критичности"""
        text = "High severity issue detected"
        severity = self.parser.extract_severity(text)
        assert severity == "High"
    
    def test_extract_severity_default(self):
        """Тест извлечения критичности по умолчанию"""
        text = "Some vulnerability found"
        severity = self.parser.extract_severity(text)
        assert severity == "Medium"
    
    def test_extract_resource_url(self):
        """Тест извлечения URL ресурса"""
        text = "Vulnerability found at https://example.com/admin"
        resource = self.parser.extract_resource(text, {})
        assert resource == "https://example.com/admin"
    
    def test_extract_resource_ip(self):
        """Тест извлечения IP адреса"""
        text = "Vulnerability found on 192.168.1.1"
        resource = self.parser.extract_resource(text, {})
        assert resource == "192.168.1.1"
    
    def test_parse_nuclei_output(self):
        """Тест парсинга вывода Nuclei"""
        nuclei_output = [
            {
                "host": "https://example.com",
                "info": {
                    "name": "SQL Injection",
                    "severity": "High",
                    "cve": ["CVE-2023-1234"]
                }
            }
        ]
        
        vulnerabilities = self.parser._parse_nuclei_output(nuclei_output)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["resource"] == "https://example.com"
        assert vulnerabilities[0]["vulnerability_type"] == "CVE-2023-1234"
        assert vulnerabilities[0]["severity"] == "High"
        assert vulnerabilities[0]["scanner"] == "nuclei"
    
    def test_parse_nikto_output(self):
        """Тест парсинга вывода Nikto"""
        nikto_output = {
            "vulnerabilities": [
                {
                    "description": "SQL injection vulnerability",
                    "severity": "High",
                    "osvdb_id": "12345"
                }
            ]
        }
        
        vulnerabilities = self.parser._parse_nikto_output(nikto_output)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["vulnerability_type"] == "OSVDB-12345"
        assert vulnerabilities[0]["severity"] == "High"
        assert vulnerabilities[0]["scanner"] == "nikto"


class TestValidation:
    """Тесты валидации"""
    
    def test_validate_target_valid_url(self):
        """Тест валидации корректного URL"""
        from cli import validate_target
        
        valid_urls = [
            "https://example.com",
            "http://test.com",
            "https://subdomain.example.com/path"
        ]
        
        for url in valid_urls:
            result = validate_target(url)
            assert result == url
    
    def test_validate_target_invalid_url(self):
        """Тест валидации некорректного URL"""
        from cli import validate_target
        
        invalid_urls = [
            "ftp://example.com",
            "not-a-url",
            "",
            None
        ]
        
        for url in invalid_urls:
            with pytest.raises(ValueError):
                validate_target(url)
    
    def test_validate_target_dangerous_chars(self):
        """Тест валидации URL с опасными символами"""
        from cli import validate_target
        
        dangerous_urls = [
            "https://example.com; rm -rf /",
            "https://example.com & echo 'hacked'",
            "https://example.com | cat /etc/passwd"
        ]
        
        for url in dangerous_urls:
            with pytest.raises(ValueError):
                validate_target(url)


if __name__ == "__main__":
    pytest.main([__file__])
