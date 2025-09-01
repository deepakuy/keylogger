"""
Unit Tests for Enhanced Educational Keylogger
============================================

These tests verify the functionality of the enhanced educational keylogger
including threading, consent mechanisms, file rotation, and advanced features.

Author: Educational Project
License: MIT
"""

import pytest
import tempfile
import shutil
import json
import time
import threading
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime
import queue

# Import the modules to test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from enhanced_keylogger import (
    EthicalConsentManager, LogFileManager, EnhancedEducationalKeylogger
)


class TestEthicalConsentManager:
    """Test cases for the EthicalConsentManager class."""
    
    def test_initialization(self):
        """Test consent manager initialization."""
        consent_manager = EthicalConsentManager()
        
        assert consent_manager.consent_given is False
        assert consent_manager.consent_timestamp is None
        assert consent_manager.ethical_agreement is False
        assert consent_manager.usage_purpose_confirmed is False
    
    @patch('builtins.print')
    def test_display_comprehensive_warning(self, mock_print):
        """Test that comprehensive warning is displayed."""
        consent_manager = EthicalConsentManager()
        consent_manager.display_comprehensive_warning()
        
        # Verify warning was displayed
        assert mock_print.called
        calls = [str(call) for call in mock_print.call_args_list]
        
        # Check for key warning sections
        assert any('ETHICAL WARNING' in call for call in calls)
        assert any('LEGAL NOTICE' in call for call in calls)
        assert any('USAGE RESTRICTIONS' in call for call in calls)
        assert any('CONSENT REQUIREMENTS' in call for call in calls)
    
    @patch('builtins.input', return_value='yes')
    def test_get_ethical_agreement_yes(self, mock_input):
        """Test ethical agreement with yes response."""
        consent_manager = EthicalConsentManager()
        result = consent_manager.get_ethical_agreement()
        
        assert result is True
        assert consent_manager.ethical_agreement is True
    
    @patch('builtins.input', return_value='no')
    def test_get_ethical_agreement_no(self, mock_input):
        """Test ethical agreement with no response."""
        consent_manager = EthicalConsentManager()
        result = consent_manager.get_ethical_agreement()
        
        assert result is False
        assert consent_manager.ethical_agreement is False
    
    @patch('builtins.input', return_value='yes')
    def test_get_usage_purpose_confirmation_yes(self, mock_input):
        """Test usage purpose confirmation with yes response."""
        consent_manager = EthicalConsentManager()
        result = consent_manager.get_usage_purpose_confirmation()
        
        assert result is True
        assert consent_manager.usage_purpose_confirmed is True
    
    @patch('builtins.input', return_value='no')
    def test_get_usage_purpose_confirmation_no(self, mock_input):
        """Test usage purpose confirmation with no response."""
        consent_manager = EthicalConsentManager()
        result = consent_manager.get_usage_purpose_confirmation()
        
        assert result is False
        assert consent_manager.usage_purpose_confirmed is False
    
    @patch('builtins.input', return_value='yes')
    def test_get_final_consent_yes(self, mock_input):
        """Test final consent with yes response."""
        consent_manager = EthicalConsentManager()
        result = consent_manager.get_final_consent()
        
        assert result is True
        assert consent_manager.consent_given is True
        assert consent_manager.consent_timestamp is not None
    
    @patch('builtins.input', return_value='no')
    def test_get_final_consent_no(self, mock_input):
        """Test final consent with no response."""
        consent_manager = EthicalConsentManager()
        result = consent_manager.get_final_consent()
        
        assert result is False
        assert consent_manager.consent_given is False
        assert consent_manager.consent_timestamp is None
    
    def test_verify_complete_consent_all_true(self):
        """Test consent verification when all levels are met."""
        consent_manager = EthicalConsentManager()
        consent_manager.ethical_agreement = True
        consent_manager.usage_purpose_confirmed = True
        consent_manager.consent_given = True
        
        result = consent_manager.verify_complete_consent()
        assert result is True
    
    def test_verify_complete_consent_missing_ethical(self):
        """Test consent verification when ethical agreement is missing."""
        consent_manager = EthicalConsentManager()
        consent_manager.ethical_agreement = False
        consent_manager.usage_purpose_confirmed = True
        consent_manager.consent_given = True
        
        result = consent_manager.verify_complete_consent()
        assert result is False
    
    def test_verify_complete_consent_missing_purpose(self):
        """Test consent verification when purpose confirmation is missing."""
        consent_manager = EthicalConsentManager()
        consent_manager.ethical_agreement = True
        consent_manager.usage_purpose_confirmed = False
        consent_manager.consent_given = True
        
        result = consent_manager.verify_complete_consent()
        assert result is False
    
    def test_verify_complete_consent_missing_final(self):
        """Test consent verification when final consent is missing."""
        consent_manager = EthicalConsentManager()
        consent_manager.ethical_agreement = True
        consent_manager.usage_purpose_confirmed = True
        consent_manager.consent_given = False
        
        result = consent_manager.verify_complete_consent()
        assert result is False


class TestLogFileManager:
    """Test cases for the LogFileManager class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_initialization(self, temp_dir):
        """Test log file manager initialization."""
        log_manager = LogFileManager(temp_dir, max_file_size_mb=5, max_files=3)
        
        assert log_manager.log_dir == Path(temp_dir)
        assert log_manager.max_file_size_mb == 5
        assert log_manager.max_files == 3
        assert log_manager.current_log_file is None
        assert log_manager.current_log_size == 0
        assert len(log_manager.log_files) == 0
    
    def test_get_current_log_file_creates_new(self, temp_dir):
        """Test that get_current_log_file creates a new file when none exists."""
        log_manager = LogFileManager(temp_dir)
        
        log_file = log_manager.get_current_log_file()
        
        assert log_file.exists()
        assert log_file.name.startswith("keylog_")
        assert log_file.suffix == ".json"
        
        # Check file content
        with open(log_file, 'r') as f:
            content = json.load(f)
        assert content == []
    
    def test_file_rotation_on_size_limit(self, temp_dir):
        """Test that files are rotated when size limit is reached."""
        log_manager = LogFileManager(temp_dir, max_file_size_mb=0.001)  # 1KB limit
        
        # Get initial log file
        initial_file = log_manager.get_current_log_file()
        
        # Create a large log entry to trigger rotation
        large_log = {"data": "x" * 2000}  # 2KB entry
        
        # Manually trigger rotation by setting file size
        with open(initial_file, 'w') as f:
            json.dump([large_log], f)
        
        # Get new log file (should trigger rotation)
        new_file = log_manager.get_current_log_file()
        
        # Should be different files
        assert new_file != initial_file
        assert new_file.exists()
        
        # Check that old file was archived
        archive_files = list(Path(temp_dir).glob("keylog_archive_*.json"))
        assert len(archive_files) > 0
    
    def test_cleanup_old_logs(self, temp_dir):
        """Test cleanup of old log files."""
        log_manager = LogFileManager(temp_dir, max_files=2)
        
        # Create some test log files
        for i in range(4):
            test_file = Path(temp_dir) / f"keylog_{i}.json"
            with open(test_file, 'w') as f:
                json.dump([{"test": i}], f)
        
        # Clean up old logs
        log_manager.cleanup_old_logs()
        
        # Should keep only 2 most recent files
        remaining_files = list(Path(temp_dir).glob("keylog_*.json"))
        assert len(remaining_files) <= 2


class TestEnhancedEducationalKeylogger:
    """Test cases for the EnhancedEducationalKeylogger class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def mock_consent_manager(self):
        """Mock consent manager that always returns True."""
        with patch('enhanced_keylogger.EthicalConsentManager') as mock_class:
            mock_instance = Mock()
            mock_instance.verify_complete_consent.return_value = True
            mock_instance.consent_timestamp = datetime.now()
            mock_class.return_value = mock_instance
            yield mock_instance
    
    @pytest.fixture
    def mock_encryption(self):
        """Mock encryption to avoid actual key generation."""
        with patch('enhanced_keylogger.Fernet') as mock_fernet:
            mock_key = b'test_key_32_bytes_long_for_testing'
            mock_fernet.generate_key.return_value = mock_key
            mock_fernet.return_value.encrypt.return_value = b'encrypted_data'
            yield mock_fernet
    
    def test_initialization(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test enhanced keylogger initialization."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                
                assert keylogger.log_manager.log_dir == Path(temp_dir)
                assert keylogger.encrypt_logs is True
                assert keylogger.is_running is False
                assert keylogger.key_count == 0
                assert keylogger.shutdown_event is not None
                assert keylogger.key_queue is not None
    
    def test_key_to_string_conversion(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test key to string conversion."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                
                # Test regular character key
                mock_key = Mock()
                mock_key.char = 'a'
                result = keylogger._key_to_string(mock_key)
                assert result == 'a'
                
                # Test special keys
                from pynput.keyboard import Key
                assert keylogger._key_to_string(Key.space) == ' '
                assert keylogger._key_to_string(Key.enter) == '\n'
                assert keylogger._key_to_string(Key.backspace) == '[BACKSPACE]'
                assert keylogger._key_to_string(Key.tab) == '[TAB]'
                assert keylogger._key_to_string(Key.esc) == '[ESC]'
                assert keylogger._key_to_string(Key.shift) == '[SHIFT]'
                assert keylogger._key_to_string(Key.ctrl) == '[CTRL]'
                assert keylogger._key_to_string(Key.alt) == '[ALT]'
    
    def test_key_press_handling(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test key press event handling."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                
                # Test key press
                mock_key = Mock()
                mock_key.char = 't'
                keylogger._on_key_press(mock_key)
                
                assert keylogger.key_count == 1
                assert keylogger.stats['keys_logged'] == 1
                
                # Check that key was added to queue
                assert not keylogger.key_queue.empty()
    
    def test_key_release_handling(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test key release event handling."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                
                # Test ESC key release
                from pynput.keyboard import Key
                result = keylogger._on_key_release(Key.esc)
                
                assert result is False  # Should stop the listener
                assert keylogger.shutdown_event.is_set()
    
    def test_process_key_log(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test key log processing."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                
                # Create test log entry
                test_entry = {
                    'timestamp': '2023-12-25T14:30:45.123456',
                    'event_type': 'press',
                    'key': 't',
                    'key_code': 't',
                    'process': 'Test'
                }
                
                # Process the log entry
                keylogger._process_key_log(test_entry)
                
                # Check that log file was created and contains the entry
                log_files = list(Path(temp_dir).glob("keylog_*.json"))
                assert len(log_files) > 0
                
                # Check content (encrypted or plain)
                log_file = log_files[0]
                if keylogger.encrypt_logs:
                    # For encrypted files, just check they exist
                    assert log_file.stat().st_size > 0
                else:
                    # For plain files, check content
                    with open(log_file, 'r') as f:
                        content = json.load(f)
                    assert len(content) == 1
                    assert content[0]['key'] == 't'
    
    def test_start_stop_functionality(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test start and stop functionality."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                
                # Mock threading components
                with patch('threading.Thread') as mock_thread_class:
                    mock_thread = Mock()
                    mock_thread_class.return_value = mock_thread
                    
                    # Test start
                    with patch('time.sleep'):
                        keylogger.start()
                    
                    assert keylogger.is_running is True
                    assert keylogger.start_time is not None
                    assert keylogger.stats['start_time'] is not None
                    
                    # Test stop
                    keylogger.stop()
                    assert keylogger.is_running is False
    
    def test_statistics_retrieval(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test statistics retrieval functionality."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                
                stats = keylogger.get_statistics()
                
                assert 'is_running' in stats
                assert 'key_count' in stats
                assert 'log_directory' in stats
                assert 'encryption_enabled' in stats
                assert 'files_rotated' in stats
                assert 'errors_encountered' in stats
                assert 'consent_timestamp' in stats
    
    def test_error_handling(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test error handling in various scenarios."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                
                # Test error in key processing
                mock_key = Mock()
                mock_key.char = None
                mock_key.__str__ = Mock(side_effect=Exception("Test error"))
                
                keylogger._on_key_press(mock_key)
                
                # Should increment error count
                assert keylogger.stats['errors_encountered'] > 0
    
    def test_threading_components(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test threading components and queue operations."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                
                # Test queue operations
                test_data = {"test": "data"}
                keylogger.key_queue.put(test_data)
                
                assert not keylogger.key_queue.empty()
                retrieved_data = keylogger.key_queue.get()
                assert retrieved_data == test_data
    
    def test_graceful_shutdown(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test graceful shutdown mechanism."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                
                # Test shutdown event
                assert not keylogger.shutdown_event.is_set()
                keylogger.shutdown_event.set()
                assert keylogger.shutdown_event.is_set()
    
    def test_session_summary_display(self, temp_dir, mock_consent_manager, mock_encryption):
        """Test session summary display."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                with patch('builtins.print') as mock_print:
                    keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                    
                    # Set some test data
                    keylogger.key_count = 100
                    keylogger.stats['session_duration'] = "0:01:30"
                    keylogger.stats['files_rotated'] = 2
                    keylogger.stats['errors_encountered'] = 1
                    
                    # Display summary
                    keylogger._display_session_summary()
                    
                    # Verify summary was displayed
                    assert mock_print.called
                    calls = [str(call) for call in mock_print.call_args_list]
                    assert any('ENHANCED SESSION SUMMARY' in call for call in calls)


class TestIntegrationFeatures:
    """Integration tests for the enhanced keylogger."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_complete_consent_flow(self, temp_dir):
        """Test the complete consent flow."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EthicalConsentManager.get_ethical_agreement', return_value=True):
                with patch('enhanced_keylogger.EthicalConsentManager.get_usage_purpose_confirmation', return_value=True):
                    with patch('enhanced_keylogger.EthicalConsentManager.get_final_consent', return_value=True):
                        with patch('enhanced_keylogger.EthicalConsentManager.verify_complete_consent', return_value=True):
                            keylogger = EnhancedEducationalKeylogger(log_dir=temp_dir)
                            
                            # Should complete initialization
                            assert keylogger.consent_manager.ethical_agreement is True
                            assert keylogger.consent_manager.usage_purpose_confirmed is True
                            assert keylogger.consent_manager.consent_given is True
    
    def test_file_rotation_integration(self, temp_dir):
        """Test file rotation integration with the keylogger."""
        with patch('enhanced_keylogger.EthicalConsentManager.display_comprehensive_warning'):
            with patch('enhanced_keylogger.EnhancedEducationalKeylogger._get_complete_consent', return_value=True):
                # Create keylogger with small file size limit
                keylogger = EnhancedEducationalKeylogger(
                    log_dir=temp_dir,
                    max_file_size_mb=0.001,  # 1KB limit
                    max_files=2
                )
                
                # Simulate multiple key presses to trigger rotation
                for i in range(10):
                    mock_key = Mock()
                    mock_key.char = 'x'
                    keylogger._on_key_press(mock_key)
                
                # Process the queue
                while not keylogger.key_queue.empty():
                    key_data = keylogger.key_queue.get()
                    keylogger._process_key_log(key_data)
                
                # Check that files were created
                log_files = list(Path(temp_dir).glob("keylog_*.json"))
                archive_files = list(Path(temp_dir).glob("keylog_archive_*.json"))
                
                assert len(log_files) > 0
                # May have archive files if rotation occurred


if __name__ == "__main__":
    pytest.main([__file__])
