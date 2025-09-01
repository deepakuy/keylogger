"""
Unit Tests for Utility Functions
================================

Additional test cases for utility functions used in the educational keylogger.

Author: Educational Project
License: MIT
"""

import pytest
import tempfile
import shutil
import os
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime

# Import the modules to test
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utils import (
    validate_file_path, create_safe_directory, encrypt_data, 
    decrypt_data, generate_file_hash, sanitize_log_data,
    format_timestamp, get_system_info, create_backup, cleanup_old_logs
)


class TestFilePathValidation:
    """Test cases for file path validation functions."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_validate_file_path_current_directory(self, temp_dir):
        """Test validation of paths within current directory."""
        # Create a subdirectory
        sub_dir = os.path.join(temp_dir, "subdir")
        os.makedirs(sub_dir)
        
        # Test various safe paths
        safe_paths = [
            temp_dir,
            sub_dir,
            os.path.join(sub_dir, "file.txt"),
            os.path.join(temp_dir, "..", "..", temp_dir.split(os.sep)[-1])
        ]
        
        for path in safe_paths:
            assert validate_file_path(path) is True, f"Path should be safe: {path}"
    
    def test_validate_file_path_suspicious_patterns(self):
        """Test rejection of suspicious file paths."""
        suspicious_paths = [
            "/etc/passwd",
            "/var/log/syslog",
            "/usr/bin/python",
            "/bin/bash",
            "C:\\Windows\\System32\\config",
            "C:\\Program Files\\Common Files",
            "~/.bashrc",
            "~/.ssh/id_rsa",
            "../../../etc/shadow",
            "..\\..\\..\\Windows\\System32"
        ]
        
        for path in suspicious_paths:
            assert validate_file_path(path) is False, f"Path should be rejected: {path}"
    
    def test_validate_file_path_edge_cases(self):
        """Test edge cases in file path validation."""
        # Test with None or empty paths
        assert validate_file_path("") is False
        assert validate_file_path(None) is False
        
        # Test with very long paths
        long_path = "a" * 1000
        assert validate_file_path(long_path) is False
    
    def test_validate_file_path_special_characters(self, temp_dir):
        """Test validation with special characters."""
        # Test with spaces and special characters
        special_path = os.path.join(temp_dir, "file with spaces.txt")
        assert validate_file_path(special_path) is True
        
        # Test with unicode characters
        unicode_path = os.path.join(temp_dir, "file_ñáéíóú.txt")
        assert validate_file_path(unicode_path) is True


class TestDirectoryOperations:
    """Test cases for directory creation and management."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_create_safe_directory_success(self, temp_dir):
        """Test successful directory creation."""
        new_dir = os.path.join(temp_dir, "new_directory")
        assert create_safe_directory(new_dir) is True
        assert os.path.exists(new_dir)
        assert os.path.isdir(new_dir)
    
    def test_create_safe_directory_nested(self, temp_dir):
        """Test creation of nested directories."""
        nested_dir = os.path.join(temp_dir, "level1", "level2", "level3")
        assert create_safe_directory(nested_dir) is True
        assert os.path.exists(nested_dir)
        assert os.path.isdir(nested_dir)
    
    def test_create_safe_directory_already_exists(self, temp_dir):
        """Test directory creation when directory already exists."""
        existing_dir = os.path.join(temp_dir, "existing_dir")
        os.makedirs(existing_dir)
        
        # Should succeed even if directory exists
        assert create_safe_directory(existing_dir) is True
        assert os.path.exists(existing_dir)
    
    def test_create_safe_directory_unsafe_path(self):
        """Test directory creation with unsafe paths."""
        unsafe_paths = [
            "/etc/unsafe",
            "C:\\Windows\\Unsafe",
            "../../../etc/unsafe"
        ]
        
        for path in unsafe_paths:
            assert create_safe_directory(path) is False
            assert not os.path.exists(path)


class TestEncryptionFunctions:
    """Test cases for encryption and decryption functions."""
    
    def test_encrypt_data_success(self):
        """Test successful data encryption."""
        test_data = "Hello, World! This is a test message."
        key = b'test_key_32_bytes_long_for_testing'
        
        encrypted = encrypt_data(test_data, key)
        
        assert isinstance(encrypted, bytes)
        assert encrypted != test_data.encode('utf-8')
        assert len(encrypted) > 0
    
    def test_encrypt_data_empty_string(self):
        """Test encryption of empty string."""
        test_data = ""
        key = b'test_key_32_bytes_long_for_testing'
        
        encrypted = encrypt_data(test_data, key)
        
        assert isinstance(encrypted, bytes)
        assert encrypted != b""
    
    def test_encrypt_data_unicode(self):
        """Test encryption of unicode data."""
        test_data = "Hello, 世界! Привет! ¡Hola!"
        key = b'test_key_32_bytes_long_for_testing'
        
        encrypted = encrypt_data(test_data, key)
        
        assert isinstance(encrypted, bytes)
        assert encrypted != test_data.encode('utf-8')
    
    def test_decrypt_data_success(self):
        """Test successful data decryption."""
        original_data = "Test message for decryption"
        key = b'test_key_32_bytes_long_for_testing'
        
        encrypted = encrypt_data(original_data, key)
        decrypted = decrypt_data(encrypted, key)
        
        assert decrypted == original_data
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test complete encrypt-decrypt roundtrip."""
        test_cases = [
            "Simple text",
            "Text with numbers 12345",
            "Text with symbols !@#$%^&*()",
            "Text with spaces and\t tabs",
            "Text with\n newlines",
            "Unicode text: ñáéíóú 你好 привет",
            "",  # Empty string
            "a" * 1000,  # Long string
        ]
        
        key = b'test_key_32_bytes_long_for_testing'
        
        for test_data in test_cases:
            encrypted = encrypt_data(test_data, key)
            decrypted = decrypt_data(encrypted, key)
            assert decrypted == test_data, f"Failed for: {repr(test_data)}"
    
    def test_encrypt_data_invalid_key(self):
        """Test encryption with invalid key."""
        test_data = "Test data"
        invalid_keys = [
            b"",  # Empty key
            b"short",  # Too short key
            b"very_long_key_that_exceeds_32_bytes_limit",
            "string_key",  # String instead of bytes
            123,  # Integer instead of bytes
        ]
        
        for key in invalid_keys:
            if isinstance(key, bytes) and len(key) != 32:
                with pytest.raises(Exception):
                    encrypt_data(test_data, key)
            else:
                with pytest.raises(Exception):
                    encrypt_data(test_data, key)
    
    def test_decrypt_data_invalid_key(self):
        """Test decryption with wrong key."""
        test_data = "Test data"
        key1 = b'test_key_32_bytes_long_for_testing'
        key2 = b'diff_key_32_bytes_long_for_testing'
        
        encrypted = encrypt_data(test_data, key1)
        
        # Try to decrypt with wrong key
        with pytest.raises(Exception):
            decrypt_data(encrypted, key2)


class TestFileHashGeneration:
    """Test cases for file hash generation."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_generate_file_hash_success(self, temp_dir):
        """Test successful file hash generation."""
        test_file = os.path.join(temp_dir, "test.txt")
        test_content = "Test content for hashing"
        
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_content)
        
        file_hash = generate_file_hash(test_file)
        
        assert isinstance(file_hash, str)
        assert len(file_hash) == 64  # SHA-256 hash length
        assert all(c in '0123456789abcdef' for c in file_hash)
    
    def test_generate_file_hash_different_content(self, temp_dir):
        """Test that different content produces different hashes."""
        file1 = os.path.join(temp_dir, "file1.txt")
        file2 = os.path.join(temp_dir, "file2.txt")
        
        with open(file1, 'w') as f:
            f.write("Content 1")
        
        with open(file2, 'w') as f:
            f.write("Content 2")
        
        hash1 = generate_file_hash(file1)
        hash2 = generate_file_hash(file2)
        
        assert hash1 != hash2
        assert len(hash1) == 64
        assert len(hash2) == 64
    
    def test_generate_file_hash_same_content(self, temp_dir):
        """Test that same content produces same hash."""
        file1 = os.path.join(temp_dir, "file1.txt")
        file2 = os.path.join(temp_dir, "file2.txt")
        
        content = "Same content for both files"
        
        with open(file1, 'w') as f:
            f.write(content)
        
        with open(file2, 'w') as f:
            f.write(content)
        
        hash1 = generate_file_hash(file1)
        hash2 = generate_file_hash(file2)
        
        assert hash1 == hash2
    
    def test_generate_file_hash_large_file(self, temp_dir):
        """Test hash generation for large files."""
        test_file = os.path.join(temp_dir, "large.txt")
        
        # Create a file with 1MB of data
        with open(test_file, 'w') as f:
            for i in range(100000):  # 100k lines
                f.write(f"Line {i}: This is test content for hashing\n")
        
        file_hash = generate_file_hash(test_file)
        
        assert isinstance(file_hash, str)
        assert len(file_hash) == 64
    
    def test_generate_file_hash_nonexistent_file(self, temp_dir):
        """Test hash generation for non-existent file."""
        nonexistent_file = os.path.join(temp_dir, "nonexistent.txt")
        
        with pytest.raises(ValueError):
            generate_file_hash(nonexistent_file)
    
    def test_generate_file_hash_unsafe_path(self):
        """Test hash generation with unsafe file path."""
        unsafe_path = "/etc/passwd"
        
        with pytest.raises(ValueError):
            generate_file_hash(unsafe_path)


class TestDataSanitization:
    """Test cases for data sanitization functions."""
    
    def test_sanitize_log_data_string(self):
        """Test sanitization of string data."""
        test_cases = [
            ('password: "secret123"', 'password: "[REDACTED]"'),
            ('api_key: "abc123def456"', 'api_key: "[REDACTED]"'),
            ('token: "xyz789"', 'token: "[REDACTED]"'),
            ('secret: "mypassword"', 'secret: "[REDACTED]"'),
            ('normal_text', 'normal_text'),
            ('PASSWORD: "test"', 'PASSWORD: "[REDACTED]"'),
            ('Api_Key: "test"', 'Api_Key: "[REDACTED]"'),
        ]
        
        for input_data, expected_output in test_cases:
            sanitized = sanitize_log_data(input_data)
            assert sanitized == expected_output
    
    def test_sanitize_log_data_dict(self):
        """Test sanitization of dictionary data."""
        test_data = {
            'username': 'testuser',
            'password': 'secret123',
            'api_key': 'abc123def456',
            'normal_field': 'normal_value',
            'nested': {
                'password': 'nested_secret',
                'other': 'other_value'
            }
        }
        
        sanitized = sanitize_log_data(test_data)
        
        # Check top-level fields
        assert sanitized['username'] == 'testuser'
        assert sanitized['password'] == 'password: "[REDACTED]"'
        assert sanitized['api_key'] == 'api_key: "[REDACTED]"'
        assert sanitized['normal_field'] == 'normal_value'
        
        # Check nested fields
        assert sanitized['nested']['password'] == 'password: "[REDACTED]"'
        assert sanitized['nested']['other'] == 'other_value'
    
    def test_sanitize_log_data_list(self):
        """Test sanitization of list data."""
        test_data = [
            'normal_item',
            'password: "secret"',
            {'key': 'password: "nested_secret"'},
            ['api_key: "list_secret"']
        ]
        
        sanitized = sanitize_log_data(test_data)
        
        assert sanitized[0] == 'normal_item'
        assert sanitized[1] == 'password: "[REDACTED]"'
        assert sanitized[2]['key'] == 'key: "[REDACTED]"'
        assert sanitized[3][0] == 'api_key: "[REDACTED]"'
    
    def test_sanitize_log_data_other_types(self):
        """Test sanitization of other data types."""
        # Test with None
        assert sanitize_log_data(None) is None
        
        # Test with numbers
        assert sanitize_log_data(42) == 42
        assert sanitize_log_data(3.14) == 3.14
        
        # Test with boolean
        assert sanitize_log_data(True) is True
        assert sanitize_log_data(False) is False


class TestTimestampFormatting:
    """Test cases for timestamp formatting functions."""
    
    def test_format_timestamp_success(self):
        """Test successful timestamp formatting."""
        test_time = datetime(2023, 12, 25, 14, 30, 45, 123456)
        formatted = format_timestamp(test_time)
        
        assert isinstance(formatted, str)
        assert "2023-12-25 14:30:45" in formatted
    
    def test_format_timestamp_edge_cases(self):
        """Test timestamp formatting edge cases."""
        # Test with different years
        test_cases = [
            datetime(2000, 1, 1, 0, 0, 0),
            datetime(2023, 6, 15, 12, 30, 0),
            datetime(2099, 12, 31, 23, 59, 59),
        ]
        
        for test_time in test_cases:
            formatted = format_timestamp(test_time)
            assert isinstance(formatted, str)
            assert len(formatted) == 19  # YYYY-MM-DD HH:MM:SS format


class TestSystemInfo:
    """Test cases for system information functions."""
    
    @patch('utils.platform')
    @patch('utils.psutil')
    def test_get_system_info_success(self, mock_psutil, mock_platform):
        """Test successful system information retrieval."""
        # Mock platform functions
        mock_platform.system.return_value = "Windows"
        mock_platform.version.return_value = "10.0.19044"
        mock_platform.architecture.return_value = ("64bit", "WindowsPE")
        mock_platform.processor.return_value = "Intel64 Family 6"
        mock_platform.python_version.return_value = "3.9.7"
        
        # Mock psutil functions
        mock_memory = MagicMock()
        mock_memory.total = 16 * 1024**3  # 16 GB
        mock_psutil.virtual_memory.return_value = mock_memory
        
        system_info = get_system_info()
        
        assert isinstance(system_info, dict)
        assert system_info['platform'] == "Windows"
        assert system_info['platform_version'] == "10.0.19044"
        assert system_info['architecture'] == "64bit"
        assert system_info['processor'] == "Intel64 Family 6"
        assert system_info['python_version'] == "3.9.7"
        assert system_info['memory_total'] == "16 GB"
    
    def test_get_system_info_import_error(self):
        """Test system info when required packages are not available."""
        with patch('utils.platform') as mock_platform:
            mock_platform.system.side_effect = ImportError("No module named 'platform'")
            
            system_info = get_system_info()
            
            assert isinstance(system_info, dict)
            assert 'error' in system_info


class TestBackupAndCleanup:
    """Test cases for backup and cleanup functions."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_create_backup_success(self, temp_dir):
        """Test successful backup creation."""
        # Create source file
        source_file = os.path.join(temp_dir, "source.txt")
        source_content = "Source file content"
        
        with open(source_file, 'w') as f:
            f.write(source_content)
        
        # Create backup
        backup_dir = os.path.join(temp_dir, "backups")
        success = create_backup(source_file, backup_dir)
        
        assert success is True
        assert os.path.exists(backup_dir)
        
        # Check backup file
        backup_files = list(Path(backup_dir).glob("source_*.txt"))
        assert len(backup_files) == 1
        
        # Verify backup content
        with open(backup_files[0], 'r') as f:
            backup_content = f.read()
        assert backup_content == source_content
    
    def test_create_backup_nonexistent_source(self, temp_dir):
        """Test backup creation with non-existent source file."""
        nonexistent_file = os.path.join(temp_dir, "nonexistent.txt")
        backup_dir = os.path.join(temp_dir, "backups")
        
        success = create_backup(nonexistent_file, backup_dir)
        assert success is False
    
    def test_create_backup_unsafe_path(self):
        """Test backup creation with unsafe paths."""
        unsafe_source = "/etc/passwd"
        unsafe_backup = "/etc/backups"
        
        success = create_backup(unsafe_source, unsafe_backup)
        assert success is False
    
    def test_cleanup_old_logs_success(self, temp_dir):
        """Test successful cleanup of old log files."""
        # Create some test log files
        for i in range(5):
            test_file = os.path.join(temp_dir, f"log_{i}.json")
            with open(test_file, 'w') as f:
                json.dump({"test": f"data_{i}"}, f)
        
        # Clean up old logs (remove all since max_age_days=0)
        removed_count = cleanup_old_logs(temp_dir, max_age_days=0)
        
        assert removed_count == 5
        
        # Check that all files were removed
        remaining_files = list(Path(temp_dir).glob("*.json"))
        assert len(remaining_files) == 0
    
    def test_cleanup_old_logs_partial(self, temp_dir):
        """Test partial cleanup of old log files."""
        # Create files with different timestamps
        current_time = datetime.now().timestamp()
        
        # Create old file (2 days ago)
        old_file = os.path.join(temp_dir, "old_log.json")
        old_time = current_time - (3 * 24 * 3600)  # 3 days ago
        with open(old_file, 'w') as f:
            json.dump({"test": "old_data"}, f)
        os.utime(old_file, (old_time, old_time))
        
        # Create new file (1 day ago)
        new_file = os.path.join(temp_dir, "new_log.json")
        new_time = current_time - (1 * 24 * 3600)  # 1 day ago
        with open(new_file, 'w') as f:
            json.dump({"test": "new_data"}, f)
        os.utime(new_file, (new_time, new_time))
        
        # Clean up files older than 2 days
        removed_count = cleanup_old_logs(temp_dir, max_age_days=2)
        
        assert removed_count == 1
        
        # Check that only old file was removed
        remaining_files = list(Path(temp_dir).glob("*.json"))
        assert len(remaining_files) == 1
        assert "new_log.json" in remaining_files[0].name
    
    def test_cleanup_old_logs_unsafe_path(self):
        """Test cleanup with unsafe path."""
        removed_count = cleanup_old_logs("/etc/unsafe", max_age_days=30)
        assert removed_count == 0


if __name__ == "__main__":
    pytest.main([__file__])
