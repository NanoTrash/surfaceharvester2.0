# tests/test_surface_harvester.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import tempfile
import os

from scanner.surface_harvester import SurfaceHarvester


class TestSurfaceHarvester:
    """Тесты для SurfaceHarvester"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.harvester = SurfaceHarvester()
    
    def test_validate_wordlist_valid(self):
        """Тест валидации корректного словаря"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test\n")
            wordlist_path = f.name
        
        try:
            result = self.harvester.validate_wordlist(wordlist_path)
            assert result is True
        finally:
            os.unlink(wordlist_path)
    
    def test_validate_wordlist_invalid(self):
        """Тест валидации некорректного словаря"""
        with pytest.raises(FileNotFoundError):
            self.harvester.validate_wordlist("/nonexistent/file.txt")
    
    def test_validate_target_valid(self):
        """Тест валидации корректной цели"""
        result = self.harvester.validate_target("example.com")
        assert result is True
    
    def test_validate_target_empty(self):
        """Тест валидации пустой цели"""
        with pytest.raises(ValueError, match="Target cannot be empty"):
            self.harvester.validate_target("")
    
    def test_validate_target_none(self):
        """Тест валидации None цели"""
        with pytest.raises(ValueError, match="Target cannot be empty"):
            self.harvester.validate_target(None)
    
    def test_is_ip_address_valid(self):
        """Тест проверки корректного IP адреса"""
        assert self.harvester.is_ip_address("192.168.1.1") is True
        assert self.harvester.is_ip_address("10.0.0.1") is True
        assert self.harvester.is_ip_address("172.16.0.1") is True
    
    def test_is_ip_address_invalid(self):
        """Тест проверки некорректного IP адреса"""
        assert self.harvester.is_ip_address("example.com") is False
        assert self.harvester.is_ip_address("192.168.1") is False
        assert self.harvester.is_ip_address("192.168.1.256") is False
        assert self.harvester.is_ip_address("") is False
    
    @patch('subprocess.run')
    def test_check_tool_installed_available(self, mock_run):
        """Тест проверки доступного инструмента"""
        mock_run.return_value.returncode = 0
        
        result = self.harvester.check_tool_installed('nmap')
        assert result is True
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_check_tool_installed_unavailable(self, mock_run):
        """Тест проверки недоступного инструмента"""
        mock_run.side_effect = FileNotFoundError()
        
        result = self.harvester.check_tool_installed('nonexistent')
        assert result is False
    
    @patch('subprocess.run')
    def test_run_nmap_scan_success(self, mock_run):
        """Тест успешного nmap сканирования"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Nmap scan results"
        
        result = self.harvester.run_nmap_scan("192.168.1.1")
        assert "Nmap scan results" in result
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_run_nmap_scan_timeout(self, mock_run):
        """Тест таймаута nmap сканирования"""
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired(['nmap'], 600)
        
        result = self.harvester.run_nmap_scan("192.168.1.1")
        assert "превысил таймаут" in result
    
    @patch('subprocess.run')
    def test_run_gobuster_dir_success(self, mock_run):
        """Тест успешного gobuster dir сканирования"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Gobuster results"
        
        result = self.harvester.run_gobuster_dir("example.com", "/path/to/wordlist.txt")
        assert "Gobuster results" in result
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_run_subfinder_success(self, mock_run):
        """Тест успешного subfinder сканирования"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "sub1.example.com\nsub2.example.com\n"
        
        result = self.harvester.run_subfinder("example.com")
        assert len(result) == 2
        assert "sub1.example.com" in result
        assert "sub2.example.com" in result
    
    @patch('aiohttp.ClientSession')
    async def test_extract_contacts_success(self, mock_session):
        """Тест успешного извлечения контактов"""
        # Мокаем ответ
        mock_response = AsyncMock()
        mock_response.text.return_value = """
        <html>
            <body>
                <p>Contact us at test@example.com</p>
                <p>Call us at +1234567890</p>
            </body>
        </html>
        """
        
        mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response
        
        emails, phones = await self.harvester.extract_contacts("http://example.com")
        
        assert "test@example.com" in emails
        assert "+1234567890" in phones
    
    @patch('aiohttp.ClientSession')
    async def test_extract_contacts_error(self, mock_session):
        """Тест ошибки извлечения контактов"""
        mock_session.return_value.__aenter__.return_value.get.side_effect = Exception("Connection error")
        
        emails, phones = await self.harvester.extract_contacts("http://example.com")
        
        assert emails == []
        assert phones == []
    
    @patch.object(SurfaceHarvester, 'run_nmap_scan')
    @patch.object(SurfaceHarvester, 'run_gobuster_dir')
    @patch.object(SurfaceHarvester, 'run_subfinder')
    @patch.object(SurfaceHarvester, 'extract_contacts')
    async def test_scan_target_domain(self, mock_contacts, mock_subfinder, mock_gobuster, mock_nmap):
        """Тест сканирования домена"""
        # Мокаем результаты
        mock_nmap.return_value = "Nmap results"
        mock_gobuster.return_value = "Gobuster results"
        mock_subfinder.return_value = ["sub1.example.com", "sub2.example.com"]
        mock_contacts.return_value = (["test@example.com"], ["+1234567890"])
        
        # Создаем временный словарь
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"admin\nlogin\n")
            wordlist_path = f.name
        
        try:
            result = await self.harvester.scan_target("example.com", wordlist_path)
            
            assert result['original_target'] == "example.com"
            assert result['is_ip'] is False
            assert "test@example.com" in result['contacts']['emails']
            assert "+1234567890" in result['contacts']['phones']
            assert len(result['results']) == 1
            assert result['results'][0]['target'] == "example.com"
            
        finally:
            os.unlink(wordlist_path)
    
    @patch.object(SurfaceHarvester, 'run_nmap_scan')
    async def test_scan_target_ip(self, mock_nmap):
        """Тест сканирования IP адреса"""
        mock_nmap.return_value = "Nmap results"
        
        # Создаем временный словарь
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"admin\nlogin\n")
            wordlist_path = f.name
        
        try:
            result = await self.harvester.scan_target("192.168.1.1", wordlist_path)
            
            assert result['original_target'] == "192.168.1.1"
            assert result['is_ip'] is True
            assert len(result['results']) == 1
            assert result['results'][0]['target'] == "192.168.1.1"
            
        finally:
            os.unlink(wordlist_path)
    
    def test_save_report(self):
        """Тест сохранения отчета"""
        scan_data = {
            'original_target': 'example.com',
            'is_ip': False,
            'contacts': {
                'emails': ['test@example.com'],
                'phones': ['+1234567890']
            },
            'results': [
                {
                    'target': 'example.com',
                    'type': 'domain',
                    'nmap': 'Nmap results',
                    'gobuster_dir': 'Gobuster results',
                    'subfinder': ['sub1.example.com']
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            output_file = f.name
        
        try:
            result = self.harvester.save_report(scan_data, output_file)
            
            assert result == output_file
            assert os.path.exists(output_file)
            
            # Проверяем содержимое файла
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
                assert "SurfaceHarvester Scan Report" in content
                assert "example.com" in content
                assert "test@example.com" in content
                assert "+1234567890" in content
                
        finally:
            os.unlink(output_file)


@pytest.mark.asyncio
async def test_surface_harvester_integration():
    """Интеграционный тест SurfaceHarvester"""
    harvester = SurfaceHarvester()
    
    # Тест с моканными инструментами
    with patch.object(harvester, 'check_tool_installed', return_value=True), \
         patch.object(harvester, 'run_nmap_scan', return_value="Mock nmap results"), \
         patch.object(harvester, 'run_gobuster_dir', return_value="Mock gobuster results"), \
         patch.object(harvester, 'run_subfinder', return_value=["mock.sub.example.com"]), \
         patch.object(harvester, 'extract_contacts', return_value=(["mock@example.com"], ["+1234567890"])):
        
        # Создаем временный словарь
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"admin\nlogin\n")
            wordlist_path = f.name
        
        try:
            result = await harvester.scan_target("example.com", wordlist_path)
            
            assert result['original_target'] == "example.com"
            assert result['is_ip'] is False
            assert len(result['results']) == 1
            
        finally:
            os.unlink(wordlist_path)


if __name__ == "__main__":
    pytest.main([__file__])
