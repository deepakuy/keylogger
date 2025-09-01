"""
Unit Tests for Educational Keylogger
===================================

These tests verify the functionality of the educational keylogger
for learning purposes. They include safety checks and ethical considerations.

Author: Educational Project
License: MIT
"""

import pytest
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Import the modules to test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from keylogger import EducationalKeylogger
from utils import (
    validate_file_path, create_safe_directory, encrypt_data, 
    decrypt_data, generate_file_hash, sanitize_log_data,
    format_timestamp, get_system_info, create_backup, cleanup_old_logs
)


class TestEducationalKeylogger:
    """Test cases for the EducationalKeylogger class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def mock_keyboard_listener(self):
        """Mock the keyboard listener to avoid actual key monitoring."""
        with patch('keylogger.keyboard.Listener') as mock_listener:
            mock_listener.return_value.__enter__.return_value.join.return_value = None
            yield mock_listener
    
    @pytest.fixture
    def mock_encryption(self):
        """Mock encryption to avoid actual key generation."""
        with patch('keylogger.Fernet') as mock_fernet:
            mock_key = b'test_key_32_bytes_long_for_testing'
            mock_fernet.generate_key.return_value = mock_key
            mock_fernet.return_value.encrypt.return_value = b'encrypted_data'
            yield mock_fernet
    
    def test_initialization(self, temp_dir, mock_encryption):
        """Test keylogger initialization."""
        with patch('builtins.input', return_value='yes'):
            with patch('keylogger.EducationalKeylogger._display_ethical_warning'):
                with patch('keylogger.EducationalKeylogger._require_consent'):
                    keylogger = EducationalKeylogger(log_dir=temp_dir)
                    
                    assert keylogger.log_dir == Path(temp_dir)
                    assert keylogger.encrypt_logs is True
                    assert keylogger.is_running is False
                    assert keylogger.key_count == 0
    
    def test_ethical_warning_display(self, temp_dir):
        """Test that ethical warning is displayed."""
        with patch('builtins.print') as mock_print:
            with patch('builtins.input', return_value='yes'):
                keylogger = EducationalKeylogger(log_dir=temp_dir)
                
                # Check that ethical warning was displayed
                mock_print.assert_called()
                # Verify warning contains key terms
                calls = [str(call) for call in mock_print.call_args_list]
                assert any('EDUCATIONAL' in call for call in calls)
                assert any('WARNING' in call for call in calls)
    
    def test_consent_requirement(self, temp_dir):
        """Test that consent is required before proceeding."""
        with patch('builtins.input', return_value='no'):
            with pytest.raises(SystemExit):
                EducationalKeylogger(log_dir=temp_dir)
    
    def test_consent_confirmation(self, temp_dir):
        """Test that consent confirmation works."""
        with patch('builtins.input', return_value='yes'):
            with patch('builtins.print') as mock_print:
                keylogger = EducationalKeylogger(log_dir=temp_dir)
                
                # Check that consent was confirmed
                mock_print.assert_called()
                calls = [str(call) for call in mock_print.call_args_list]
                assert any('Consent confirmed' in call for call in calls)
    
    def test_key_press_handling(self, temp_dir, mock_encryption):
        """Test key press event handling."""
        with patch('builtins.input', return_value='yes'):
            with patch('keylogger.EducationalKeylogger._display_ethical_warning'):
                with patch('keylogger.EducationalKeylogger._require_consent'):
                    keylogger = EducationalKeylogger(log_dir=temp_dir)
                    
                    # Test regular character key
                    mock_key = Mock()
                    mock_key.char = 'a'
                    keylogger._on_key_press(mock_key)
                    
                    assert keylogger.key_count == 1
                    
                    # Test special key
                    mock_key = Mock()
                    mock_key.char = None
                    with patch('keylogger.Key.space', ' '):
                        keylogger._on_key_press(mock_key)
                    
                    assert keylogger.key_count == 2
    
    def test_key_release_handling(self, temp_dir, mock_encryption):
        """Test key release event handling."""
        with patch('builtins.input', return_value='yes'):
            with patch('keylogger.EducationalKeylogger._display_ethical_warning'):
                with patch('keylogger.EducationalKeylogger._require_consent'):
                    keylogger = EducationalKeylogger(log_dir=temp_dir)
                    
                    # Test ESC key release
                    mock_key = Mock()
                    mock_key.__eq__ = lambda self, other: str(other) == 'Key.esc'
                    
                    result = keylogger._on_key_release(mock_key)
                    assert result is False  # Should stop the listener
    
    def test_log_file_creation(self, temp_dir, mock_encryption):
        """Test that log files are created properly."""
        with patch('builtins.input', return_value='yes'):
            with patch('keylogger.EducationalKeylogger._display_ethical_warning'):
                with patch('keylogger.EducationalKeylogger._require_consent'):
                    keylogger = EducationalKeylogger(log_dir=temp_dir)
                    
                    # Simulate key press
                    mock_key = Mock()
                    mock_key.char = 't'
                    keylogger._on_key_press(mock_key)
                    
                    # Check if log file was created
                    log_files = list(Path(temp_dir).glob("*.json"))
                    assert len(log_files) > 0
    
    def test_start_stop_functionality(self, temp_dir, mock_keyboard_listener, mock_encryption):
        """Test start and stop functionality."""
        with patch('builtins.input', return_value='yes'):
            with patch('keylogger.EducationalKeylogger._display_ethical_warning'):
                with patch('keylogger.EducationalKeylogger._require_consent'):
                    keylogger = EducationalKeylogger(log_dir=temp_dir)
                    
                    # Test start
                    keylogger.start()
                    assert keylogger.is_running is True
                    assert keylogger.start_time is not None
                    
                    # Test stop
                    keylogger.stop()
                    assert keylogger.is_running is False
    
    def test_statistics_retrieval(self, temp_dir, mock_encryption):
        """Test statistics retrieval functionality."""
        with patch('builtins.input', return_value='yes'):
            with patch('keylogger.EducationalKeylogger._display_ethical_warning'):
                with patch('keylogger.EducationalKeylogger._require_consent'):
                    keylogger = EducationalKeylogger(log_dir=temp_dir)
                    
                    stats = keylogger.get_statistics()
                    
                    assert 'is_running' in stats
                    assert 'key_count' in stats
                    assert 'log_directory' in stats
                    assert 'encryption_enabled' in stats


class TestUtilityFunctions:
    """Test cases for utility functions."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_validate_file_path_safe(self, temp_dir):
        """Test file path validation with safe paths."""
        safe_paths = [
            temp_dir,
            os.path.join(temp_dir, "test.txt"),
            os.path.join(temp_dir, "subdir", "file.txt")
        ]
        
        for path in safe_paths:
            assert validate_file_path(path) is True
    
    def test_validate_file_path_unsafe(self):
        """Test file path validation with unsafe paths."""
        unsafe_paths = [
            "/etc/passwd",
            "C:\\Windows\\System32\\config",
            "../../../etc/shadow",
            "~/.bashrc"
        ]
        
        for path in unsafe_paths:
            assert validate_file_path(path) is False
    
    def test_create_safe_directory(self, temp_dir):
        """Test safe directory creation."""
        new_dir = os.path.join(temp_dir, "new_directory")
        assert create_safe_directory(new_dir) is True
        assert os.path.exists(new_dir)
    
    def test_create_safe_directory_unsafe(self):
        """Test safe directory creation with unsafe paths."""
        unsafe_dir = "/etc/unsafe"
        assert create_safe_directory(unsafe_dir) is False
    
    def test_encrypt_decrypt_data(self):
        """Test encryption and decryption functionality."""
        test_data = "Hello, World!"
        key = b'test_key_32_bytes_long_for_testing'
        
        # Test encryption
        encrypted = encrypt_data(test_data, key)
        assert isinstance(encrypted, bytes)
        assert encrypted != test_data.encode()
        
        # Test decryption
        decrypted = decrypt_data(encrypted, key)
        assert decrypted == test_data
    
    def test_generate_file_hash(self, temp_dir):
        """Test file hash generation."""
        test_file = os.path.join(temp_dir, "test.txt")
        test_content = "Test content for hashing"
        
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        file_hash = generate_file_hash(test_file)
        assert isinstance(file_hash, str)
        assert len(file_hash) == 64  # SHA-256 hash length
    
    def test_sanitize_log_data(self):
        """Test log data sanitization."""
        test_data = {
            'username': 'testuser',
            'password': 'secret123',
            'api_key': 'abc123def456',
            'normal_field': 'normal_value'
        }
        
        sanitized = sanitize_log_data(test_data)
        
        # Check that sensitive fields are redacted
        assert sanitized['password'] == 'password: "[REDACTED]"'
        assert sanitized['api_key'] == 'api_key: "[REDACTED]"'
        
        # Check that normal fields remain unchanged
        assert sanitized['username'] == 'testuser'
        assert sanitized['normal_field'] == 'normal_value'
    
    def test_format_timestamp(self):
        """Test timestamp formatting."""
        test_time = datetime(2023, 12, 25, 14, 30, 45)
        formatted = format_timestamp(test_time)
        
        assert isinstance(formatted, str)
        assert "2023-12-25 14:30:45" in formatted
    
    def test_get_system_info(self):
        """Test system information retrieval."""
        system_info = get_system_info()
        
        assert isinstance(system_info, dict)
        # Should contain basic system information
        assert 'platform' in system_info or 'error' in system_info
    
    def test_create_backup(self, temp_dir):
        """Test backup creation functionality."""
        # Create a test file
        test_file = os.path.join(temp_dir, "test.txt")
        test_content = "Test content"
        
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Create backup
        backup_dir = os.path.join(temp_dir, "backups")
        success = create_backup(test_file, backup_dir)
        
        assert success is True
        assert os.path.exists(backup_dir)
        
        # Check if backup file exists
        backup_files = list(Path(backup_dir).glob("test_*.txt"))
        assert len(backup_files) > 0
    
    def test_cleanup_old_logs(self, temp_dir):
        """Test old log cleanup functionality."""
        # Create some test log files
        for i in range(3):
            test_file = os.path.join(temp_dir, f"log_{i}.json")
            with open(test_file, 'w') as f:
                json.dump({"test": "data"}, f)
        
        # Clean up old logs (should remove all since they're new)
        removed_count = cleanup_old_logs(temp_dir, max_age_days=0)
        
        # Should remove all files
        assert removed_count == 3


class TestEthicalSafeguards:
    """Test cases for ethical safeguards and safety features."""
    
    def test_consent_requirement(self):
        """Test that consent is always required."""
        with patch('builtins.input', return_value='no'):
            with pytest.raises(SystemExit):
                EducationalKeylogger()
    
    def test_ethical_warning_display(self):
        """Test that ethical warning is always displayed."""
        with patch('builtins.print') as mock_print:
            with patch('builtins.input', return_value='yes'):
                EducationalKeylogger()
                
                # Verify warning was displayed
                calls = [str(call) for call in mock_print.call_args_list]
                assert any('EDUCATIONAL' in call for call in calls)
                assert any('WARNING' in call for call in calls)
    
    def test_safe_file_operations(self):
        """Test that file operations are restricted to safe paths."""
        # Test that utility functions reject unsafe paths
        unsafe_paths = [
            "/etc/passwd",
            "C:\\Windows\\System32",
            "../../../etc/shadow"
        ]
        
        for path in unsafe_paths:
            assert validate_file_path(path) is False
            assert create_safe_directory(path) is False


if __name__ == "__main__":
    pytest.main([__file__])
