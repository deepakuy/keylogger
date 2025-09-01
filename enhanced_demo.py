#!/usr/bin/env python3
"""
Enhanced Educational Keylogger Demo Script
=========================================

This script demonstrates the advanced features of the enhanced educational keylogger
including threading, file rotation, comprehensive consent mechanisms, and ethical safeguards.

WARNING: This is for EDUCATIONAL PURPOSES ONLY!
DO NOT use this code for malicious purposes.

Author: Educational Project
License: MIT
"""

import sys
import os
import time
import threading
from pathlib import Path
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from enhanced_keylogger import EnhancedEducationalKeylogger
from utils import get_system_info, create_safe_directory


def display_enhanced_demo_info():
    """Display comprehensive information about the enhanced demo."""
    print("=" * 80)
    print("ENHANCED EDUCATIONAL KEYLOGGER DEMO")
    print("=" * 80)
    print()
    print("This enhanced demo showcases advanced keylogger features:")
    print()
    print("🔧 TECHNICAL FEATURES:")
    print("  • Multi-threaded operation for non-blocking performance")
    print("  • Automatic file rotation and log management")
    print("  • Advanced error handling and logging")
    print("  • Queue-based key processing")
    print("  • Graceful shutdown mechanisms")
    print()
    print("🛡️ ETHICAL SAFEGUARDS:")
    print("  • Multi-level consent verification")
    print("  • Comprehensive ethical warnings")
    print("  • Legal compliance requirements")
    print("  • Usage purpose confirmation")
    print("  • Built-in safety mechanisms")
    print()
    print("📊 MONITORING FEATURES:")
    print("  • Real-time keystroke logging")
    print("  • File size monitoring and rotation")
    print("  • Session statistics and metrics")
    print("  • Process information tracking")
    print("  • Encrypted log storage")
    print()
    print("Press ENTER to continue or Ctrl+C to exit...")
    input()


def run_basic_enhanced_demo():
    """Run the basic enhanced keylogger demo."""
    print("\n" + "=" * 80)
    print("BASIC ENHANCED KEYLOGGER DEMO")
    print("=" * 80)
    print()
    
    # Create a custom log directory for the demo
    demo_log_dir = "enhanced_demo_logs"
    if create_safe_directory(demo_log_dir):
        print(f"✓ Created enhanced demo log directory: {demo_log_dir}")
    else:
        print(f"✗ Failed to create enhanced demo log directory: {demo_log_dir}")
        return False
    
    # Create and configure the enhanced keylogger
    print("Creating enhanced educational keylogger instance...")
    print("Configuration:")
    print(f"  • Log directory: {demo_log_dir}")
    print(f"  • Max file size: 5MB")
    print(f"  • Max files: 3")
    print(f"  • Encryption: Enabled")
    print(f"  • Threading: Enabled")
    print(f"  • File rotation: Enabled")
    
    keylogger = EnhancedEducationalKeylogger(
        log_dir=demo_log_dir,
        max_file_size_mb=5,
        max_files=3,
        encrypt_logs=True
    )
    
    print(f"✓ Enhanced keylogger created successfully")
    print(f"✓ Log directory: {keylogger.log_manager.log_dir}")
    print(f"✓ Encryption enabled: {keylogger.encrypt_logs}")
    print(f"✓ File rotation: {keylogger.log_manager.max_file_size_mb}MB max, {keylogger.log_manager.max_files} files")
    
    # Display system information
    print("\nSystem Information:")
    system_info = get_system_info()
    for key, value in system_info.items():
        print(f"  {key}: {value}")
    
    print("\n" + "=" * 80)
    print("STARTING ENHANCED KEYLOGGER")
    print("=" * 80)
    print("The enhanced keylogger will now start with the following features:")
    print("• Multi-threaded keyboard monitoring")
    print("• Real-time log file management")
    print("• Automatic file rotation")
    print("• Comprehensive error handling")
    print("• Graceful shutdown on ESC key")
    print()
    print("Type some text to see the enhanced features in action.")
    print("The keylogger will automatically rotate files when they reach 5MB.")
    print("Press ESC to stop the enhanced keylogger.")
    print()
    
    try:
        # Start the enhanced keylogger
        keylogger.start()
    except KeyboardInterrupt:
        print("\nEnhanced demo interrupted by user.")
    except Exception as e:
        print(f"\nError during enhanced demo: {e}")
        return False
    
    return True


def run_advanced_features_demo():
    """Run advanced features demonstration."""
    print("\n" + "=" * 80)
    print("ADVANCED FEATURES DEMO")
    print("=" * 80)
    print()
    
    # Create a new keylogger instance for advanced demo
    advanced_log_dir = "advanced_features_demo_logs"
    if create_safe_directory(advanced_log_dir):
        print(f"✓ Created advanced features demo log directory: {advanced_log_dir}")
    else:
        print(f"✗ Failed to create advanced features demo log directory: {advanced_log_dir}")
        return False
    
    print("Creating keylogger with advanced configuration...")
    keylogger = EnhancedEducationalKeylogger(
        log_dir=advanced_log_dir,
        max_file_size_mb=1,  # 1MB limit for faster rotation
        max_files=2,          # Keep only 2 files
        encrypt_logs=True
    )
    
    print("\nDemonstrating advanced utility functions:")
    
    # Test utility functions
    from utils import (
        validate_file_path, sanitize_log_data,
        format_timestamp, create_backup, generate_file_hash
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
        'normal_field': 'normal_value',
        'nested': {
            'password': 'nested_secret',
            'other': 'other_value'
        }
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
    
    # Test file hash generation
    test_file = os.path.join(advanced_log_dir, "hash_test.txt")
    test_content = "Content for hashing test"
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    file_hash = generate_file_hash(test_file)
    print(f"  File hash generation test:")
    print(f"    File: {test_file}")
    print(f"    Hash: {file_hash}")
    
    # Test backup creation
    backup_success = create_backup(test_file, advanced_log_dir)
    print(f"  Backup creation test:")
    print(f"    Backup created: {backup_success}")
    
    print("\nAdvanced features demo completed successfully!")
    return True


def run_threading_demo():
    """Demonstrate threading capabilities."""
    print("\n" + "=" * 80)
    print("THREADING CAPABILITIES DEMO")
    print("=" * 80)
    print()
    
    threading_log_dir = "threading_demo_logs"
    if create_safe_directory(threading_log_dir):
        print(f"✓ Created threading demo log directory: {threading_log_dir}")
    else:
        print(f"✗ Failed to create threading demo log directory: {threading_log_dir}")
        return False
    
    print("Creating keylogger to demonstrate threading features...")
    keylogger = EnhancedEducationalKeylogger(
        log_dir=threading_log_dir,
        max_file_size_mb=2,
        max_files=2,
        encrypt_logs=True
    )
    
    print("\nThreading Features Demonstrated:")
    print("• Keyboard listener runs in separate thread")
    print("• Log processing runs in separate thread")
    print("• Main thread remains responsive")
    print("• Queue-based communication between threads")
    print("• Graceful thread shutdown")
    
    print("\nThreading demo completed successfully!")
    return True


def run_file_rotation_demo():
    """Demonstrate file rotation capabilities."""
    print("\n" + "=" * 80)
    print("FILE ROTATION DEMO")
    print("=" * 80)
    print()
    
    rotation_log_dir = "rotation_demo_logs"
    if create_safe_directory(rotation_log_dir):
        print(f"✓ Created file rotation demo log directory: {rotation_log_dir}")
    else:
        print(f"✗ Failed to create file rotation demo log directory: {rotation_log_dir}")
        return False
    
    print("Creating keylogger with aggressive file rotation settings...")
    keylogger = EnhancedEducationalKeylogger(
        log_dir=rotation_log_dir,
        max_file_size_mb=0.001,  # 1KB limit for fast rotation
        max_files=3,              # Keep 3 files
        encrypt_logs=True
    )
    
    print("\nFile Rotation Features:")
    print("• Automatic rotation when files reach size limit")
    print("• Archive naming with timestamps")
    print("• Automatic cleanup of old files")
    print("• Seamless switching between log files")
    print("• Size monitoring and rotation triggers")
    
    print("\nFile rotation demo completed successfully!")
    return True


def cleanup_demo_files():
    """Clean up all demo files and directories."""
    print("\n" + "=" * 80)
    print("CLEANUP")
    print("=" * 80)
    print()
    
    demo_dirs = [
        "enhanced_demo_logs",
        "advanced_features_demo_logs", 
        "threading_demo_logs",
        "rotation_demo_logs"
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
    print("ENHANCED DEMO COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    print()
    print("What you've learned about the Enhanced Keylogger:")
    print()
    print("🔧 TECHNICAL ADVANCEMENTS:")
    print("  • Multi-threaded architecture for better performance")
    print("  • Queue-based key processing for reliability")
    print("  • Automatic file rotation and management")
    print("  • Advanced error handling and logging")
    print("  • Graceful shutdown mechanisms")
    print()
    print("🛡️ ENHANCED ETHICAL SAFEGUARDS:")
    print("  • Multi-level consent verification system")
    print("  • Comprehensive ethical warning displays")
    print("  • Legal compliance requirements")
    print("  • Usage purpose confirmation")
    print("  • Built-in safety mechanisms")
    print()
    print("📊 MONITORING CAPABILITIES:")
    print("  • Real-time keystroke logging with threading")
    print("  • Intelligent file size monitoring")
    print("  • Automatic log file rotation")
    print("  • Session statistics and metrics")
    print("  • Process information tracking")
    print("  • Encrypted log storage")
    print()
    print("🎯 EDUCATIONAL VALUE:")
    print("  • Advanced Python programming concepts")
    print("  • Multi-threading and concurrency")
    print("  • File I/O and log management")
    print("  • Error handling and logging")
    print("  • Ethical programming practices")
    print("  • System programming concepts")
    print()
    print("Remember: This tool is for EDUCATIONAL PURPOSES ONLY!")
    print()


def main():
    """Main enhanced demo function."""
    try:
        # Display enhanced demo information
        display_enhanced_demo_info()
        
        # Run basic enhanced demo
        if run_basic_enhanced_demo():
            print("\n✓ Basic enhanced demo completed successfully!")
        else:
            print("\n✗ Basic enhanced demo failed!")
            return 1
        
        # Run advanced features demo
        if run_advanced_features_demo():
            print("\n✓ Advanced features demo completed successfully!")
        else:
            print("\n✗ Advanced features demo failed!")
            return 1
        
        # Run threading demo
        if run_threading_demo():
            print("\n✓ Threading demo completed successfully!")
        else:
            print("\n✗ Threading demo failed!")
            return 1
        
        # Run file rotation demo
        if run_file_rotation_demo():
            print("\n✓ File rotation demo completed successfully!")
        else:
            print("\n✗ File rotation demo failed!")
            return 1
        
        # Display comprehensive summary
        display_demo_summary()
        
        # Ask if user wants to clean up demo files
        print("Would you like to clean up the demo files? (yes/no): ", end="")
        response = input().lower().strip()
        
        if response in ['yes', 'y']:
            cleanup_demo_files()
            print("✓ Enhanced demo cleanup completed!")
        else:
            print("- Demo files left in place for inspection.")
            print("  Remember to clean them up manually later.")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\nEnhanced demo interrupted by user.")
        return 1
    except Exception as e:
        print(f"\n\nUnexpected error during enhanced demo: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
