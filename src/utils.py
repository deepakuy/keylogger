"""
Utility Functions for Educational Keylogger
==========================================

This module provides utility functions for the educational keylogger project.
These functions are designed for learning purposes and include safety checks.

Author: Educational Project
License: MIT
"""

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from cryptography.fernet import Fernet


def validate_file_path(file_path: str) -> bool:
    """
    Validate if a file path is safe and within allowed directories.
    
    Args:
        file_path: Path to validate
        
    Returns:
        True if path is safe, False otherwise
    """
    try:
        path = Path(file_path).resolve()
        current_dir = Path.cwd().resolve()
        
        # Check if path is within current directory (safety measure)
        if not str(path).startswith(str(current_dir)):
            return False
        
        # Check for suspicious patterns
        suspicious_patterns = [
            '..', '~', '/etc', '/var', '/usr', '/bin', '/sbin',
            'C:\\Windows', 'C:\\System32', 'C:\\Program Files'
        ]
        
        path_str = str(path).lower()
        for pattern in suspicious_patterns:
            if pattern.lower() in path_str:
                return False
        
        return True
    except Exception:
        return False


def create_safe_directory(dir_path: str) -> bool:
    """
    Create a directory safely with validation.
    
    Args:
        dir_path: Directory path to create
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if not validate_file_path(dir_path):
            return False
        
        path = Path(dir_path)
        path.mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def encrypt_data(data: str, key: bytes) -> bytes:
    """
    Encrypt data using Fernet encryption.
    
    Args:
        data: String data to encrypt
        key: Encryption key
        
    Returns:
        Encrypted data as bytes
    """
    try:
        fernet = Fernet(key)
        return fernet.encrypt(data.encode('utf-8'))
    except Exception as e:
        raise ValueError(f"Encryption failed: {e}")


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """
    Decrypt data using Fernet encryption.
    
    Args:
        encrypted_data: Encrypted data as bytes
        key: Decryption key
        
    Returns:
        Decrypted data as string
    """
    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


def generate_file_hash(file_path: str) -> str:
    """
    Generate SHA-256 hash of a file for integrity checking.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Hexadecimal hash string
    """
    try:
        if not validate_file_path(file_path):
            raise ValueError("Invalid file path")
        
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()
    except Exception as e:
        raise ValueError(f"Hash generation failed: {e}")


def sanitize_log_data(data: Any) -> Any:
    """
    Sanitize log data to remove potentially sensitive information.
    
    Args:
        data: Data to sanitize
        
    Returns:
        Sanitized data
    """
    if isinstance(data, str):
        # Remove common sensitive patterns
        sensitive_patterns = [
            r'password["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'api_key["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'token["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'secret["\']?\s*[:=]\s*["\'][^"\']*["\']'
        ]
        
        import re
        for pattern in sensitive_patterns:
            data = re.sub(pattern, r'\1: "[REDACTED]"', data, flags=re.IGNORECASE)
        
        return data
    elif isinstance(data, dict):
        return {k: sanitize_log_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_log_data(item) for item in data]
    else:
        return data


def format_timestamp(timestamp: datetime) -> str:
    """
    Format timestamp in a human-readable format.
    
    Args:
        timestamp: Datetime object
        
    Returns:
        Formatted timestamp string
    """
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def get_system_info() -> Dict[str, str]:
    """
    Get basic system information for educational purposes.
    
    Returns:
        Dictionary with system information
    """
    try:
        import platform
        import psutil
        
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'memory_total': f"{psutil.virtual_memory().total // (1024**3)} GB"
        }
    except ImportError:
        return {'error': 'Required packages not available'}


def create_backup(file_path: str, backup_dir: str = "backups") -> bool:
    """
    Create a backup of a file.
    
    Args:
        file_path: Path to the file to backup
        backup_dir: Directory to store backups
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if not validate_file_path(file_path):
            return False
        
        source_path = Path(file_path)
        if not source_path.exists():
            return False
        
        # Create backup directory
        backup_path = Path(backup_dir)
        backup_path.mkdir(exist_ok=True)
        
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{source_path.stem}_{timestamp}{source_path.suffix}"
        backup_file = backup_path / backup_filename
        
        # Copy file
        import shutil
        shutil.copy2(source_path, backup_file)
        
        return True
    except Exception:
        return False


def cleanup_old_logs(log_dir: str, max_age_days: int = 30) -> int:
    """
    Clean up old log files to prevent disk space issues.
    
    Args:
        log_dir: Directory containing log files
        max_age_days: Maximum age of files to keep
        
    Returns:
        Number of files removed
    """
    try:
        if not validate_file_path(log_dir):
            return 0
        
        log_path = Path(log_dir)
        if not log_path.exists():
            return 0
        
        cutoff_time = datetime.now().timestamp() - (max_age_days * 24 * 3600)
        removed_count = 0
        
        for file_path in log_path.glob("*.json"):
            if file_path.stat().st_mtime < cutoff_time:
                try:
                    file_path.unlink()
                    removed_count += 1
                except Exception:
                    continue
        
        return removed_count
    except Exception:
        return 0
