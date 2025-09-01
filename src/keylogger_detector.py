"""
Keylogger Detection Module
==========================

This module demonstrates how security software detects potential keyloggers.
It includes various detection methods commonly used by antivirus and security tools.

WARNING: This module is for EDUCATIONAL PURPOSES ONLY.
It demonstrates detection mechanisms for learning about cybersecurity and protection methods.

DO NOT use this code for malicious purposes or to evade security software.
Always respect privacy and follow applicable laws.

Author: Educational Project
License: MIT
"""

import os
import sys
import time
import json
import psutil
import hashlib
import platform
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, deque
import queue

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError:
    # Fallback if colorama is not available
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
    class Style:
        RESET_ALL = BRIGHT = DIM = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""


class ProcessScanner:
    """Scans system processes for suspicious patterns that might indicate keylogger activity."""
    
    def __init__(self):
        self.suspicious_patterns = {
            'process_names': [
                'keylogger', 'kl', 'logger', 'spy', 'monitor', 'track',
                'capture', 'record', 'stealer', 'hack', 'malware'
            ],
            'command_line_patterns': [
                'pynput', 'keyboard', 'hook', 'listener', 'monitor',
                '--hidden', '--stealth', '--silent', '--background'
            ]
        }
    
    def scan_processes(self) -> Dict[str, Any]:
        """Scan all running processes for suspicious patterns."""
        results = {
            'total_processes': 0,
            'suspicious_processes': [],
            'high_risk_processes': [],
            'scan_timestamp': datetime.now().isoformat()
        }
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    results['total_processes'] += 1
                    proc_info = proc.info
                    
                    # Check process name and command line
                    risk_score = self._check_process_name(proc_info['name'])
                    risk_score += self._check_command_line(proc_info['cmdline'])
                    
                    if risk_score > 0:
                        suspicious_proc = {
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                            'risk_score': risk_score
                        }
                        
                        if risk_score >= 5:
                            results['high_risk_processes'].append(suspicious_proc)
                        else:
                            results['suspicious_processes'].append(suspicious_proc)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _check_process_name(self, name: str) -> int:
        """Check process name for suspicious patterns."""
        if not name:
            return 0
        
        name_lower = name.lower()
        risk_score = 0
        
        for pattern in self.suspicious_patterns['process_names']:
            if pattern in name_lower:
                risk_score += 2
        
        return risk_score
    
    def _check_command_line(self, cmdline: List[str]) -> int:
        """Check command line arguments for suspicious patterns."""
        if not cmdline:
            return 0
        
        cmd_str = ' '.join(cmdline).lower()
        risk_score = 0
        
        for pattern in self.suspicious_patterns['command_line_patterns']:
            if pattern in cmd_str:
                risk_score += 3
        
        return risk_score


class FileSystemMonitor:
    """Monitors file system for keylogger signatures and suspicious files."""
    
    def __init__(self):
        self.scan_directories = [
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Documents")
        ]
        
        self.keylogger_signatures = [
            'keylog', 'logger', 'spy', 'monitor', 'capture',
            'stealer', 'hack', 'malware', 'trojan'
        ]
    
    def scan_filesystem(self) -> Dict[str, Any]:
        """Scan file system for suspicious files and patterns."""
        results = {
            'total_files_scanned': 0,
            'suspicious_files': [],
            'scan_timestamp': datetime.now().isoformat()
        }
        
        try:
            for directory in self.scan_directories:
                if os.path.exists(directory):
                    self._scan_directory(directory, results)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _scan_directory(self, directory: str, results: Dict[str, Any]):
        """Recursively scan a directory for suspicious files."""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    results['total_files_scanned'] += 1
                    
                    # Check filename for suspicious patterns
                    if self._is_suspicious_filename(file):
                        file_path = os.path.join(root, file)
                        suspicious_file = {
                            'path': file_path,
                            'name': file,
                            'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
                        }
                        results['suspicious_files'].append(suspicious_file)
                        
        except (OSError, PermissionError):
            pass
    
    def _is_suspicious_filename(self, filename: str) -> bool:
        """Check if filename contains suspicious patterns."""
        filename_lower = filename.lower()
        
        for pattern in self.keylogger_signatures:
            if pattern in filename_lower:
                return True
        
        return False


class BehavioralAnalyzer:
    """Analyzes system behavior for patterns that might indicate keylogger activity."""
    
    def __init__(self):
        self.baseline_data = {}
    
    def analyze_system_behavior(self) -> Dict[str, Any]:
        """Analyze current system behavior for suspicious patterns."""
        results = {
            'analysis_timestamp': datetime.now().isoformat(),
            'suspicious_behaviors': [],
            'risk_level': 'LOW'
        }
        
        try:
            # Analyze process creation patterns
            process_analysis = self._analyze_process_creation()
            if process_analysis['suspicious']:
                results['suspicious_behaviors'].append(process_analysis)
            
            # Calculate overall risk level
            risk_score = len(results['suspicious_behaviors'])
            if risk_score >= 2:
                results['risk_level'] = 'HIGH'
            elif risk_score >= 1:
                results['risk_level'] = 'MEDIUM'
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _analyze_process_creation(self) -> Dict[str, Any]:
        """Analyze process creation patterns."""
        try:
            current_processes = set()
            for proc in psutil.process_iter(['pid']):
                try:
                    current_processes.add(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Compare with baseline
            if not self.baseline_data.get('processes'):
                self.baseline_data['processes'] = current_processes
                return {'suspicious': False, 'type': 'process_creation'}
            
            new_processes = current_processes - self.baseline_data['processes']
            
            if len(new_processes) > 10:  # More than 10 new processes
                return {
                    'suspicious': True,
                    'type': 'process_creation',
                    'details': f'High number of new processes: {len(new_processes)}'
                }
            
            return {'suspicious': False, 'type': 'process_creation'}
            
        except Exception as e:
            return {'suspicious': False, 'type': 'process_creation', 'error': str(e)}


class NetworkMonitor:
    """Basic network activity monitoring for suspicious connections."""
    
    def __init__(self):
        self.suspicious_ports = [22, 23, 3389, 5900, 8080, 3128, 1080]
    
    def monitor_network_activity(self) -> Dict[str, Any]:
        """Monitor current network connections for suspicious activity."""
        results = {
            'total_connections': 0,
            'suspicious_connections': [],
            'scan_timestamp': datetime.now().isoformat()
        }
        
        try:
            connections = psutil.net_connections()
            results['total_connections'] = len(connections)
            
            for conn in connections:
                try:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        # Check for suspicious ports
                        if conn.raddr.port in self.suspicious_ports:
                            connection_info = {
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                                'status': conn.status,
                                'pid': conn.pid
                            }
                            results['suspicious_connections'].append(connection_info)
                
                except (AttributeError, TypeError):
                    continue
            
        except Exception as e:
            results['error'] = str(e)
        
        return results


class ReportGenerator:
    """Generates comprehensive reports from detection results."""
    
    def __init__(self):
        self.report_template = {
            'header': 'KEYLOGGER DETECTION REPORT',
            'timestamp': '',
            'summary': {},
            'detailed_findings': {},
            'risk_assessment': {},
            'recommendations': [],
            'disclaimers': []
        }
    
    def generate_report(self, 
                       process_scan: Dict[str, Any],
                       filesystem_scan: Dict[str, Any],
                       behavioral_analysis: Dict[str, Any],
                       network_scan: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive detection report."""
        report = self.report_template.copy()
        report['timestamp'] = datetime.now().isoformat()
        
        # Generate summary
        report['summary'] = self._generate_summary(
            process_scan, filesystem_scan, behavioral_analysis, network_scan
        )
        
        # Detailed findings
        report['detailed_findings'] = {
            'process_scan': process_scan,
            'filesystem_scan': filesystem_scan,
            'behavioral_analysis': behavioral_analysis,
            'network_scan': network_scan
        }
        
        # Risk assessment
        report['risk_assessment'] = self._assess_overall_risk(
            process_scan, filesystem_scan, behavioral_analysis, network_scan
        )
        
        # Recommendations
        report['recommendations'] = self._generate_recommendations(report['risk_assessment'])
        
        # Disclaimers
        report['disclaimers'] = self._generate_disclaimers()
        
        return report
    
    def _generate_summary(self, *scan_results) -> Dict[str, Any]:
        """Generate executive summary of all scan results."""
        total_suspicious = 0
        
        for result in scan_results:
            if isinstance(result, dict):
                if 'suspicious_processes' in result:
                    total_suspicious += len(result.get('suspicious_processes', []))
                if 'suspicious_files' in result:
                    total_suspicious += len(result.get('suspicious_files', []))
                if 'suspicious_behaviors' in result:
                    total_suspicious += len(result.get('suspicious_behaviors', []))
                if 'suspicious_connections' in result:
                    total_suspicious += len(result.get('suspicious_connections', []))
        
        return {
            'total_suspicious_items': total_suspicious,
            'overall_risk_level': 'HIGH' if total_suspicious > 5 else 'MEDIUM' if total_suspicious > 0 else 'LOW'
        }
    
    def _assess_overall_risk(self, *scan_results) -> Dict[str, Any]:
        """Assess overall system risk based on all scan results."""
        risk_score = 0
        
        for result in scan_results:
            if isinstance(result, dict):
                if 'suspicious_processes' in result:
                    risk_score += len(result.get('suspicious_processes', []))
                if 'high_risk_processes' in result:
                    risk_score += len(result.get('high_risk_processes', [])) * 2
        
        if risk_score >= 5:
            risk_level = 'HIGH'
        elif risk_score >= 2:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score
        }
    
    def _generate_recommendations(self, risk_assessment: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on risk assessment."""
        risk_level = risk_assessment.get('risk_level', 'LOW')
        
        if risk_level == 'HIGH':
            return [
                "Run comprehensive security scan",
                "Check for unauthorized software",
                "Monitor system performance",
                "Review startup programs"
            ]
        elif risk_level == 'MEDIUM':
            return [
                "Run security scan",
                "Monitor system behavior",
                "Keep security software updated"
            ]
        else:
            return [
                "Continue regular security practices",
                "Monitor for changes",
                "Keep software updated"
            ]
    
    def _generate_disclaimers(self) -> List[str]:
        """Generate important disclaimers about the detection results."""
        return [
            "This report is for EDUCATIONAL PURPOSES ONLY",
            "Results may include false positives",
            "Always verify findings manually",
            "Consult security professionals for critical decisions"
        ]
    
    def save_report(self, report: Dict[str, Any], filename: str = None) -> str:
        """Save the detection report to a file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"keylogger_detection_report_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            return filename
            
        except Exception as e:
            raise Exception(f"Failed to save report: {e}")
    
    def display_report_summary(self, report: Dict[str, Any]):
        """Display a formatted summary of the detection report."""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{'='*20} KEYLOGGER DETECTION REPORT {'='*20}")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        # Summary
        summary = report.get('summary', {})
        print(f"\n{Fore.YELLOW}EXECUTIVE SUMMARY:{Style.RESET_ALL}")
        print(f"  Overall Risk Level: {Fore.RED}{summary.get('overall_risk_level', 'UNKNOWN')}{Style.RESET_ALL}")
        print(f"  Suspicious Items Found: {summary.get('total_suspicious_items', 0)}")
        
        # Risk Assessment
        risk_assessment = report.get('risk_assessment', {})
        print(f"\n{Fore.YELLOW}RISK ASSESSMENT:{Style.RESET_ALL}")
        print(f"  Risk Level: {Fore.RED}{risk_assessment.get('risk_level', 'UNKNOWN')}{Style.RESET_ALL}")
        print(f"  Risk Score: {risk_assessment.get('risk_score', 0)}")
        
        # Recommendations
        recommendations = report.get('recommendations', [])
        if recommendations:
            print(f"\n{Fore.YELLOW}RECOMMENDATIONS:{Style.RESET_ALL}")
            for i, rec in enumerate(recommendations[:5], 1):
                print(f"  {i}. {rec}")
        
        # Disclaimers
        print(f"\n{Fore.RED}IMPORTANT DISCLAIMERS:{Style.RESET_ALL}")
        print("  • This report is for EDUCATIONAL PURPOSES ONLY")
        print("  • Results may include false positives")
        print("  • Always verify findings manually")
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")


class KeyloggerDetector:
    """Main keylogger detection class that orchestrates all detection methods."""
    
    def __init__(self):
        self.process_scanner = ProcessScanner()
        self.filesystem_monitor = FileSystemMonitor()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.network_monitor = NetworkMonitor()
        self.report_generator = ReportGenerator()
    
    def run_comprehensive_scan(self) -> Dict[str, Any]:
        """Run a comprehensive keylogger detection scan."""
        print(f"{Fore.CYAN}Starting comprehensive keylogger detection scan...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This scan demonstrates how security software detects potential threats{Style.RESET_ALL}")
        print()
        
        try:
            # Step 1: Process scanning
            print(f"{Fore.BLUE}Step 1/4: Scanning processes for suspicious patterns...{Style.RESET_ALL}")
            process_scan = self.process_scanner.scan_processes()
            
            # Step 2: Filesystem monitoring
            print(f"{Fore.BLUE}Step 2/4: Monitoring filesystem for keylogger signatures...{Style.RESET_ALL}")
            filesystem_scan = self.filesystem_monitor.scan_filesystem()
            
            # Step 3: Behavioral analysis
            print(f"{Fore.BLUE}Step 3/4: Analyzing system behavior patterns...{Style.RESET_ALL}")
            behavioral_analysis = self.behavioral_analyzer.analyze_system_behavior()
            
            # Step 4: Network monitoring
            print(f"{Fore.BLUE}Step 4/4: Monitoring network activity...{Style.RESET_ALL}")
            network_scan = self.network_monitor.monitor_network_activity()
            
            # Generate comprehensive report
            print(f"\n{Fore.GREEN}Generating comprehensive detection report...{Style.RESET_ALL}")
            report = self.report_generator.generate_report(
                process_scan, filesystem_scan, behavioral_analysis, network_scan
            )
            
            print(f"\n{Fore.GREEN}✓ Comprehensive scan completed successfully{Style.RESET_ALL}")
            
            return report
            
        except Exception as e:
            print(f"\n{Fore.RED}✗ Scan failed: {e}{Style.RESET_ALL}")
            return {'error': str(e)}
    
    def save_scan_report(self, report: Dict[str, Any], filename: str = None) -> str:
        """Save the scan report to a file."""
        try:
            return self.report_generator.save_report(report, filename)
        except Exception as e:
            print(f"{Fore.RED}Failed to save report: {e}{Style.RESET_ALL}")
            return ""
    
    def display_scan_results(self, report: Dict[str, Any]):
        """Display the scan results in a formatted way."""
        self.report_generator.display_report_summary(report)


def main():
    """Main function to demonstrate the keylogger detection module."""
    print(f"{Fore.CYAN}Keylogger Detection Module Demo")
    print(f"{Fore.CYAN}================================{Style.RESET_ALL}")
    print()
    print(f"{Fore.YELLOW}This demo shows how security software detects potential keyloggers.")
    print(f"It demonstrates various detection mechanisms used by antivirus and security tools.{Style.RESET_ALL}")
    print()
    print(f"{Fore.RED}WARNING: This is for EDUCATIONAL PURPOSES ONLY!")
    print(f"DO NOT use this code for malicious purposes or to evade security software.{Style.RESET_ALL}")
    print()
    
    try:
        # Create detector instance
        detector = KeyloggerDetector()
        
        # Run comprehensive scan
        report = detector.run_comprehensive_scan()
        
        if 'error' not in report:
            # Display results
            detector.display_scan_results(report)
            
            # Save report
            filename = detector.save_scan_report(report)
            if filename:
                print(f"\n{Fore.GREEN}Report saved to: {filename}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}Demo completed successfully!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Remember: This tool demonstrates detection mechanisms for educational purposes.{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Demo interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Unexpected error during demo: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
