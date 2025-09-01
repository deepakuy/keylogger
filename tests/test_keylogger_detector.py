"""
Unit Tests for Keylogger Detector Module
========================================

These tests verify the functionality of the keylogger detection module
including process scanning, filesystem monitoring, behavioral analysis,
and network monitoring capabilities.

Author: Educational Project
License: MIT
"""

import pytest
import tempfile
import shutil
import json
import os
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime

# Import the modules to test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from keylogger_detector import (
    ProcessScanner, FileSystemMonitor, BehavioralAnalyzer,
    NetworkMonitor, ReportGenerator, KeyloggerDetector
)


class TestProcessScanner:
    """Test cases for the ProcessScanner class."""
    
    def test_initialization(self):
        """Test process scanner initialization."""
        scanner = ProcessScanner()
        
        assert scanner.suspicious_patterns is not None
        assert 'process_names' in scanner.suspicious_patterns
        assert 'command_line_patterns' in scanner.suspicious_patterns
        assert len(scanner.suspicious_patterns['process_names']) > 0
        assert len(scanner.suspicious_patterns['command_line_patterns']) > 0
    
    @patch('psutil.process_iter')
    def test_scan_processes_no_suspicious(self, mock_process_iter):
        """Test process scanning when no suspicious processes are found."""
        # Mock process data
        mock_proc1 = Mock()
        mock_proc1.info = {
            'pid': 1234,
            'name': 'explorer.exe',
            'cmdline': ['explorer.exe'],
            'exe': 'C:\\Windows\\explorer.exe'
        }
        
        mock_proc2 = Mock()
        mock_proc2.info = {
            'pid': 5678,
            'name': 'notepad.exe',
            'cmdline': ['notepad.exe'],
            'exe': 'C:\\Windows\\notepad.exe'
        }
        
        mock_process_iter.return_value = [mock_proc1, mock_proc2]
        
        scanner = ProcessScanner()
        results = scanner.scan_processes()
        
        assert results['total_processes'] == 2
        assert len(results['suspicious_processes']) == 0
        assert len(results['high_risk_processes']) == 0
        assert 'scan_timestamp' in results
    
    def test_check_process_name_suspicious(self):
        """Test process name checking for suspicious patterns."""
        scanner = ProcessScanner()
        
        # Test suspicious names
        assert scanner._check_process_name('keylogger.exe') > 0
        assert scanner._check_process_name('spyware.exe') > 0
        assert scanner._check_process_name('monitor.exe') > 0
        
        # Test normal names
        assert scanner._check_process_name('explorer.exe') == 0
        assert scanner._check_process_name('notepad.exe') == 0
        assert scanner._check_process_name('') == 0
    
    def test_check_command_line_suspicious(self):
        """Test command line checking for suspicious patterns."""
        scanner = ProcessScanner()
        
        # Test suspicious command lines
        assert scanner._check_command_line(['python', '--hidden']) > 0
        assert scanner._check_command_line(['app', '--stealth']) > 0
        assert scanner._check_command_line(['script', '--background']) > 0
        
        # Test normal command lines
        assert scanner._check_command_line(['notepad.exe']) == 0
        assert scanner._check_command_line([]) == 0
        assert scanner._check_command_line(None) == 0


class TestFileSystemMonitor:
    """Test cases for the FileSystemMonitor class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_initialization(self):
        """Test filesystem monitor initialization."""
        monitor = FileSystemMonitor()
        
        assert monitor.scan_directories is not None
        assert len(monitor.scan_directories) > 0
        assert monitor.keylogger_signatures is not None
        assert len(monitor.keylogger_signatures) > 0
    
    def test_scan_filesystem_no_suspicious(self, temp_dir):
        """Test filesystem scanning when no suspicious files are found."""
        # Create normal files
        normal_file1 = os.path.join(temp_dir, "document.txt")
        normal_file2 = os.path.join(temp_dir, "image.jpg")
        
        with open(normal_file1, 'w') as f:
            f.write("Normal content")
        with open(normal_file2, 'w') as f:
            f.write("Image data")
        
        monitor = FileSystemMonitor()
        monitor.scan_directories = [temp_dir]
        
        results = monitor.scan_filesystem()
        
        assert results['total_files_scanned'] == 2
        assert len(results['suspicious_files']) == 0
        assert 'scan_timestamp' in results
    
    def test_is_suspicious_filename(self):
        """Test filename suspicious pattern detection."""
        monitor = FileSystemMonitor()
        
        # Test suspicious filenames
        assert monitor._is_suspicious_filename('keylogger.exe') is True
        assert monitor._is_suspicious_filename('spyware.dll') is True
        assert monitor._is_suspicious_filename('monitor.exe') is True
        assert monitor._is_suspicious_filename('stealer.bat') is True
        
        # Test normal filenames
        assert monitor._is_suspicious_filename('document.txt') is False
        assert monitor._is_suspicious_filename('image.jpg') is False
        assert monitor._is_suspicious_filename('') is False


class TestBehavioralAnalyzer:
    """Test cases for the BehavioralAnalyzer class."""
    
    def test_initialization(self):
        """Test behavioral analyzer initialization."""
        analyzer = BehavioralAnalyzer()
        
        assert analyzer.baseline_data is not None
        assert isinstance(analyzer.baseline_data, dict)
    
    @patch('psutil.process_iter')
    def test_analyze_system_behavior_baseline_establishment(self, mock_process_iter):
        """Test behavioral analysis when establishing baseline."""
        # Mock initial process data
        mock_proc1 = Mock()
        mock_proc1.info = {'pid': 1234}
        mock_proc2 = Mock()
        mock_proc2.info = {'pid': 5678}
        
        mock_process_iter.return_value = [mock_proc1, mock_proc2]
        
        analyzer = BehavioralAnalyzer()
        results = analyzer.analyze_system_behavior()
        
        assert results['analysis_timestamp'] is not None
        assert len(results['suspicious_behaviors']) == 0
        assert results['risk_level'] == 'LOW'
        assert analyzer.baseline_data['processes'] == {1234, 5678}


class TestNetworkMonitor:
    """Test cases for the NetworkMonitor class."""
    
    def test_initialization(self):
        """Test network monitor initialization."""
        monitor = NetworkMonitor()
        
        assert monitor.suspicious_ports is not None
        assert len(monitor.suspicious_ports) > 0
        assert 22 in monitor.suspicious_ports  # SSH
        assert 3389 in monitor.suspicious_ports  # RDP
    
    @patch('psutil.net_connections')
    def test_monitor_network_activity_no_suspicious(self, mock_net_connections):
        """Test network monitoring when no suspicious connections are found."""
        # Mock normal connections
        mock_conn1 = Mock()
        mock_conn1.status = 'ESTABLISHED'
        mock_conn1.laddr = Mock()
        mock_conn1.laddr.ip = '127.0.0.1'
        mock_conn1.laddr.port = 12345
        mock_conn1.raddr = Mock()
        mock_conn1.raddr.ip = '192.168.1.1'
        mock_conn1.raddr.port = 80  # HTTP - not suspicious
        mock_conn1.pid = 1234
        
        mock_net_connections.return_value = [mock_conn1]
        
        monitor = NetworkMonitor()
        results = monitor.monitor_network_activity()
        
        assert results['total_connections'] == 1
        assert len(results['suspicious_connections']) == 0
        assert 'scan_timestamp' in results


class TestReportGenerator:
    """Test cases for the ReportGenerator class."""
    
    def test_initialization(self):
        """Test report generator initialization."""
        generator = ReportGenerator()
        
        assert generator.report_template is not None
        assert 'header' in generator.report_template
        assert 'timestamp' in generator.report_template
        assert 'summary' in generator.report_template
    
    def test_generate_report(self):
        """Test report generation with sample data."""
        generator = ReportGenerator()
        
        # Sample scan data
        process_scan = {
            'total_processes': 100,
            'suspicious_processes': [{'name': 'suspicious.exe'}],
            'high_risk_processes': []
        }
        
        filesystem_scan = {
            'total_files_scanned': 1000,
            'suspicious_files': [{'name': 'suspicious.dll'}]
        }
        
        behavioral_analysis = {
            'suspicious_behaviors': [{'type': 'process_creation'}]
        }
        
        network_scan = {
            'total_connections': 50,
            'suspicious_connections': [{'port': 22}]
        }
        
        report = generator.generate_report(
            process_scan, filesystem_scan, behavioral_analysis, network_scan
        )
        
        assert report['timestamp'] is not None
        assert report['summary'] is not None
        assert report['detailed_findings'] is not None
        assert report['risk_assessment'] is not None
        assert report['recommendations'] is not None
        assert report['disclaimers'] is not None


class TestKeyloggerDetector:
    """Test cases for the main KeyloggerDetector class."""
    
    def test_initialization(self):
        """Test keylogger detector initialization."""
        detector = KeyloggerDetector()
        
        assert detector.process_scanner is not None
        assert detector.filesystem_monitor is not None
        assert detector.behavioral_analyzer is not None
        assert detector.network_monitor is not None
        assert detector.report_generator is not None


if __name__ == "__main__":
    pytest.main([__file__])
