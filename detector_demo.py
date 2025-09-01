#!/usr/bin/env python3
"""
Keylogger Detector Demo Script
==============================

This script demonstrates the keylogger detection module's capabilities
including process scanning, filesystem monitoring, behavioral analysis,
and network monitoring.

WARNING: This is for EDUCATIONAL PURPOSES ONLY!
DO NOT use this code for malicious purposes or to evade security software.

Author: Educational Project
License: MIT
"""

import sys
import os
import time
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from keylogger_detector import KeyloggerDetector
from utils import get_system_info, create_safe_directory


def display_detector_demo_info():
    """Display comprehensive information about the detector demo."""
    print("=" * 80)
    print("KEYLOGGER DETECTOR MODULE DEMO")
    print("=" * 80)
    print()
    print("This demo showcases how security software detects potential keyloggers:")
    print()
    print("🔍 DETECTION METHODS:")
    print("  • Process scanning for suspicious patterns")
    print("  • Filesystem monitoring for keylogger signatures")
    print("  • Behavioral analysis of system activity")
    print("  • Network activity monitoring")
    print("  • Comprehensive report generation")
    print()
    print("🛡️ EDUCATIONAL VALUE:")
    print("  • Understanding how antivirus software works")
    print("  • Learning about threat detection mechanisms")
    print("  • Studying cybersecurity protection methods")
    print("  • Practicing ethical security research")
    print()
    print("⚠️  IMPORTANT NOTES:")
    print("  • This tool demonstrates detection mechanisms")
    print("  • Results may include false positives")
    print("  • Always verify findings manually")
    print("  • Use for learning and research only")
    print()
    print("Press ENTER to continue or Ctrl+C to exit...")
    input()


def run_basic_detection_demo():
    """Run the basic keylogger detection demo."""
    print("\n" + "=" * 80)
    print("BASIC KEYLOGGER DETECTION DEMO")
    print("=" * 80)
    print()
    
    # Create a custom log directory for the demo
    demo_log_dir = "detector_demo_logs"
    if create_safe_directory(demo_log_dir):
        print(f"✓ Created detector demo log directory: {demo_log_dir}")
    else:
        print(f"✗ Failed to create detector demo log directory: {demo_log_dir}")
        return False
    
    # Create and configure the detector
    print("Creating keylogger detector instance...")
    print("Configuration:")
    print(f"  • Log directory: {demo_log_dir}")
    print(f"  • Process scanning: Enabled")
    print(f"  • Filesystem monitoring: Enabled")
    print(f"  • Behavioral analysis: Enabled")
    print(f"  • Network monitoring: Enabled")
    
    detector = KeyloggerDetector()
    
    print(f"✓ Keylogger detector created successfully")
    print(f"✓ Process scanner: {detector.process_scanner.__class__.__name__}")
    print(f"✓ Filesystem monitor: {detector.filesystem_monitor.__class__.__name__}")
    print(f"✓ Behavioral analyzer: {detector.behavioral_analyzer.__class__.__name__}")
    print(f"✓ Network monitor: {detector.network_monitor.__class__.__name__}")
    
    # Display system information
    print("\nSystem Information:")
    system_info = get_system_info()
    for key, value in system_info.items():
        print(f"  {key}: {value}")
    
    print("\n" + "=" * 80)
    print("STARTING KEYLOGGER DETECTION SCAN")
    print("=" * 80)
    print("The detector will now run a comprehensive scan including:")
    print("• Process scanning for suspicious patterns")
    print("• Filesystem monitoring for keylogger signatures")
    print("• Behavioral analysis of system activity")
    print("• Network activity monitoring")
    print("• Comprehensive report generation")
    print()
    print("This demonstrates how security software identifies potential threats.")
    print("The scan may take a few moments to complete.")
    print()
    
    try:
        # Run the comprehensive detection scan
        report = detector.run_comprehensive_scan()
        
        if 'error' not in report:
            # Display results
            detector.display_scan_results(report)
            
            # Save report
            filename = detector.save_scan_report(report)
            if filename:
                print(f"\n{Fore.GREEN}Detection report saved to: {filename}{Style.RESET_ALL}")
            
            return True
        else:
            print(f"\n{Fore.RED}Detection scan failed: {report['error']}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"\nError during detection demo: {e}")
        return False


def run_advanced_detection_demo():
    """Run advanced detection features demonstration."""
    print("\n" + "=" * 80)
    print("ADVANCED DETECTION FEATURES DEMO")
    print("=" * 80)
    print()
    
    # Create a new detector instance for advanced demo
    advanced_log_dir = "advanced_detection_demo_logs"
    if create_safe_directory(advanced_log_dir):
        print(f"✓ Created advanced detection demo log directory: {advanced_log_dir}")
    else:
        print(f"✗ Failed to create advanced detection demo log directory: {advanced_log_dir}")
        return False
    
    print("Creating detector with advanced configuration...")
    detector = KeyloggerDetector()
    
    print("\nDemonstrating advanced detection capabilities:")
    
    # Test individual components
    print("  Process Scanner Test:")
    process_results = detector.process_scanner.scan_processes()
    print(f"    Total processes scanned: {process_results.get('total_processes', 0)}")
    print(f"    Suspicious processes found: {len(process_results.get('suspicious_processes', []))}")
    print(f"    High-risk processes found: {len(process_results.get('high_risk_processes', []))}")
    
    print("  Filesystem Monitor Test:")
    filesystem_results = detector.filesystem_monitor.scan_filesystem()
    print(f"    Total files scanned: {filesystem_results.get('total_files_scanned', 0)}")
    print(f"    Suspicious files found: {len(filesystem_results.get('suspicious_files', []))}")
    
    print("  Behavioral Analyzer Test:")
    behavioral_results = detector.behavioral_analyzer.analyze_system_behavior()
    print(f"    Risk level: {behavioral_results.get('risk_level', 'UNKNOWN')}")
    print(f"    Suspicious behaviors: {len(behavioral_results.get('suspicious_behaviors', []))}")
    
    print("  Network Monitor Test:")
    network_results = detector.network_monitor.monitor_network_activity()
    print(f"    Total connections: {network_results.get('total_connections', 0)}")
    print(f"    Suspicious connections: {len(network_results.get('suspicious_connections', []))}")
    
    print("\nAdvanced detection features demo completed successfully!")
    return True


def run_false_positive_demo():
    """Demonstrate false positive handling and disclaimers."""
    print("\n" + "=" * 80)
    print("FALSE POSITIVE HANDLING DEMO")
    print("=" * 80)
    print()
    
    print("This demo shows how the detector handles potential false positives:")
    print()
    print("🔍 FALSE POSITIVE SCENARIOS:")
    print("  • Legitimate software with suspicious names")
    print("  • Normal system processes with unusual patterns")
    print("  • Educational tools that trigger detection")
    print("  • Development software with monitoring capabilities")
    print()
    print("⚠️  IMPORTANT DISCLAIMERS:")
    print("  • Detection results may include false positives")
    print("  • Always verify findings manually")
    print("  • Consider context and legitimate use cases")
    print("  • Consult security professionals for critical decisions")
    print()
    print("📚 EDUCATIONAL VALUE:")
    print("  • Understanding detection limitations")
    print("  • Learning about false positive reduction")
    print("  • Practicing critical analysis of security alerts")
    print("  • Developing better security awareness")
    print()
    
    print("False positive handling demo completed successfully!")
    return True


def run_educational_insights_demo():
    """Demonstrate educational insights about detection mechanisms."""
    print("\n" + "=" * 80)
    print("EDUCATIONAL INSIGHTS DEMO")
    print("=" * 80)
    print()
    
    print("This demo provides insights into how security software works:")
    print()
    print("🔬 DETECTION MECHANISMS EXPLAINED:")
    print("  • Process scanning: Identifies suspicious running programs")
    print("  • Filesystem monitoring: Detects malicious file patterns")
    print("  • Behavioral analysis: Recognizes unusual system activity")
    print("  • Network monitoring: Identifies suspicious connections")
    print()
    print("🛡️ PROTECTION METHODS:")
    print("  • Signature-based detection: Known threat patterns")
    print("  • Heuristic analysis: Suspicious behavior patterns")
    print("  • Behavioral monitoring: System activity analysis")
    print("  • Network analysis: Connection pattern recognition")
    print()
    print("🎯 LEARNING OUTCOMES:")
    print("  • Understanding threat detection principles")
    print("  • Learning about security software capabilities")
    print("  • Developing cybersecurity awareness")
    print("  • Practicing ethical security research")
    print()
    
    print("Educational insights demo completed successfully!")
    return True


def cleanup_demo_files():
    """Clean up all demo files and directories."""
    print("\n" + "=" * 80)
    print("CLEANUP")
    print("=" * 80)
    print()
    
    demo_dirs = [
        "detector_demo_logs",
        "advanced_detection_demo_logs"
    ]
    
    for demo_dir in demo_dirs:
        if os.path.exists(demo_dir):
            try:
                import shutil
                shutil.rmtree(demo_dir)
                print(f"✓ Removed demo directory: {demo_dir}")
            except Exception as e:
                print(f"✗ Failed to remove {demo_dir}: {e}")
        else:
            print(f"- Demo directory not found: {demo_dir}")


def display_demo_summary():
    """Display comprehensive demo summary."""
    print("\n" + "=" * 80)
    print("KEYLOGGER DETECTOR DEMO COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    print()
    print("What you've learned about Keylogger Detection:")
    print()
    print("🔍 DETECTION CAPABILITIES:")
    print("  • Process scanning for suspicious patterns")
    print("  • Filesystem monitoring for keylogger signatures")
    print("  • Behavioral analysis of system activity")
    print("  • Network activity monitoring")
    print("  • Comprehensive report generation")
    print()
    print("🛡️ SECURITY INSIGHTS:")
    print("  • How antivirus software detects threats")
    print("  • Understanding detection mechanisms")
    print("  • Recognizing security software limitations")
    print("  • False positive handling and analysis")
    print()
    print("🎯 EDUCATIONAL VALUE:")
    print("  • Cybersecurity awareness and understanding")
    print("  • Threat detection principles")
    print("  • Security software capabilities")
    print("  • Ethical security research practices")
    print()
    print("⚠️  IMPORTANT REMINDERS:")
    print("  • This tool is for EDUCATIONAL PURPOSES ONLY")
    print("  • Results may include false positives")
    print("  • Always verify findings manually")
    print("  • Use responsibly and ethically")
    print()
    print("Remember: Understanding how security software works helps you")
    print("better protect your systems and develop security awareness!")


def main():
    """Main detector demo function."""
    try:
        # Display detector demo information
        display_detector_demo_info()
        
        # Run basic detection demo
        if run_basic_detection_demo():
            print("\n✓ Basic detection demo completed successfully!")
        else:
            print("\n✗ Basic detection demo failed!")
            return 1
        
        # Run advanced detection demo
        if run_advanced_detection_demo():
            print("\n✓ Advanced detection demo completed successfully!")
        else:
            print("\n✗ Advanced detection demo failed!")
            return 1
        
        # Run false positive demo
        if run_false_positive_demo():
            print("\n✓ False positive handling demo completed successfully!")
        else:
            print("\n✗ False positive handling demo failed!")
            return 1
        
        # Run educational insights demo
        if run_educational_insights_demo():
            print("\n✓ Educational insights demo completed successfully!")
        else:
            print("\n✗ Educational insights demo failed!")
            return 1
        
        # Display comprehensive summary
        display_demo_summary()
        
        # Ask if user wants to clean up demo files
        print("Would you like to clean up the demo files? (yes/no): ", end="")
        response = input().lower().strip()
        
        if response in ['yes', 'y']:
            cleanup_demo_files()
            print("✓ Detector demo cleanup completed!")
        else:
            print("- Demo files left in place for inspection.")
            print("  Remember to clean them up manually later.")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\nDetector demo interrupted by user.")
        return 1
    except Exception as e:
        print(f"\n\nUnexpected error during detector demo: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
