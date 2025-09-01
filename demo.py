#!/usr/bin/env python3
"""
Educational Keylogger Demo Script
=================================

This script demonstrates how to use the educational keylogger
in a safe and ethical manner for learning purposes.

WARNING: This is for EDUCATIONAL PURPOSES ONLY!
DO NOT use this code for malicious purposes.

Author: Educational Project
License: MIT
"""

import sys
import os
import time
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from keylogger import EducationalKeylogger
from utils import get_system_info, create_safe_directory


def display_demo_info():
    """Display information about the demo."""
    print("=" * 60)
    print("EDUCATIONAL KEYLOGGER DEMO")
    print("=" * 60)
    print()
    print("This demo will show you how the educational keylogger works.")
    print("It will monitor your keystrokes for educational purposes only.")
    print()
    print("Features demonstrated:")
    print("• Keyboard event monitoring")
    print("• Log file creation and encryption")
    print("• Real-time statistics")
    print("• Ethical safeguards and consent requirements")
    print("• Safe file operations")
    print()
    print("Press ENTER to continue or Ctrl+C to exit...")
    input()


def run_basic_demo():
    """Run the basic keylogger demo."""
    print("\n" + "=" * 60)
    print("BASIC KEYLOGGER DEMO")
    print("=" * 60)
    print()
    
    # Create a custom log directory for the demo
    demo_log_dir = "demo_logs"
    if create_safe_directory(demo_log_dir):
        print(f"✓ Created demo log directory: {demo_log_dir}")
    else:
        print(f"✗ Failed to create demo log directory: {demo_log_dir}")
        return False
    
    # Create and configure the keylogger
    print("Creating educational keylogger instance...")
    keylogger = EducationalKeylogger(
        log_dir=demo_log_dir,
        encrypt_logs=True
    )
    
    print(f"✓ Keylogger created successfully")
    print(f"✓ Log directory: {keylogger.log_dir}")
    print(f"✓ Encryption enabled: {keylogger.encrypt_logs}")
    
    # Display system information
    print("\nSystem Information:")
    system_info = get_system_info()
    for key, value in system_info.items():
        print(f"  {key}: {value}")
    
    print("\n" + "=" * 60)
    print("STARTING KEYLOGGER")
    print("=" * 60)
    print("The keylogger will now start monitoring your keystrokes.")
    print("Type some text to see it in action.")
    print("Press ESC to stop the keylogger.")
    print()
    
    try:
        # Start the keylogger
        keylogger.start()
    except KeyboardInterrupt:
        print("\nDemo interrupted by user.")
    except Exception as e:
        print(f"\nError during demo: {e}")
        return False
    
    return True


def run_advanced_demo():
    """Run advanced features demo."""
    print("\n" + "=" * 60)
    print("ADVANCED FEATURES DEMO")
    print("=" * 60)
    print()
    
    # Create a new keylogger instance for advanced demo
    advanced_log_dir = "advanced_demo_logs"
    if create_safe_directory(advanced_log_dir):
        print(f"✓ Created advanced demo log directory: {advanced_log_dir}")
    else:
        print(f"✗ Failed to create advanced demo log directory: {advanced_log_dir}")
        return False
    
    print("Creating keylogger with advanced configuration...")
    keylogger = EducationalKeylogger(
        log_dir=advanced_log_dir,
        encrypt_logs=True
    )
    
    print("\nDemonstrating utility functions:")
    
    # Test utility functions
    from utils import (
        validate_file_path, sanitize_log_data,
        format_timestamp, create_backup
    )
    
    # Test path validation
    safe_path = os.path.join(advanced_log_dir, "test.txt")
    unsafe_path = "/etc/passwd"
    
    print(f"  Path validation test:")
    print(f"    Safe path '{safe_path}': {validate_file_path(safe_path)}")
    print(f"    Unsafe path '{unsafe_path}': {validate_file_path(unsafe_path)}")
    
    # Test data sanitization
    test_data = {
        'username': 'demo_user',
        'password': 'secret123',
        'api_key': 'abc123def456',
        'normal_field': 'normal_value'
    }
    
    print(f"  Data sanitization test:")
    print(f"    Original data: {test_data}")
    sanitized_data = sanitize_log_data(test_data)
    print(f"    Sanitized data: {sanitized_data}")
    
    # Test timestamp formatting
    from datetime import datetime
    current_time = datetime.now()
    formatted_time = format_timestamp(current_time)
    print(f"  Timestamp formatting test:")
    print(f"    Current time: {formatted_time}")
    
    print("\nAdvanced demo completed successfully!")
    return True


def cleanup_demo_files():
    """Clean up demo files and directories."""
    print("\n" + "=" * 60)
    print("CLEANUP")
    print("=" * 60)
    print()
    
    demo_dirs = ["demo_logs", "advanced_demo_logs"]
    
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


def main():
    """Main demo function."""
    try:
        # Display demo information
        display_demo_info()
        
        # Run basic demo
        if run_basic_demo():
            print("\n✓ Basic demo completed successfully!")
        else:
            print("\n✗ Basic demo failed!")
            return 1
        
        # Run advanced demo
        if run_advanced_demo():
            print("\n✓ Advanced demo completed successfully!")
        else:
            print("\n✗ Advanced demo failed!")
            return 1
        
        print("\n" + "=" * 60)
        print("DEMO COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print()
        print("What you've learned:")
        print("• How to create and configure the educational keylogger")
        print("• How to use utility functions safely")
        print("• How ethical safeguards protect users")
        print("• How encryption secures log data")
        print("• How to validate file paths and sanitize data")
        print()
        print("Remember: This tool is for EDUCATIONAL PURPOSES ONLY!")
        print()
        
        # Ask if user wants to clean up demo files
        print("Would you like to clean up the demo files? (yes/no): ", end="")
        response = input().lower().strip()
        
        if response in ['yes', 'y']:
            cleanup_demo_files()
            print("✓ Demo cleanup completed!")
        else:
            print("- Demo files left in place for inspection.")
            print("  Remember to clean them up manually later.")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        return 1
    except Exception as e:
        print(f"\n\nUnexpected error during demo: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
