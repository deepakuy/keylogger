# Educational Keylogger Project

## ⚠️ **CRITICAL ETHICAL WARNING** ⚠️

**This project is for EDUCATIONAL PURPOSES ONLY. It demonstrates keylogging concepts for learning about system programming, input monitoring, and cybersecurity.**

**DO NOT use this code for malicious purposes, to monitor others without consent, or to violate privacy or laws.**

## 📚 Educational Purpose

This project is designed to teach:
- **System Programming**: Understanding how operating systems handle input events
- **Input Monitoring**: Learning about keyboard event handling and system hooks
- **File I/O Operations**: Working with log files and data persistence
- **Encryption Concepts**: Implementing data security and privacy protection
- **Ethical Programming**: Building tools with built-in safeguards and consent requirements
- **Cybersecurity Awareness**: Understanding how monitoring tools work to better protect against them

## 🚨 Legal and Ethical Considerations

### What This Tool Is NOT For:
- ❌ Monitoring others without explicit consent
- ❌ Stealing passwords or sensitive information
- ❌ Corporate espionage or unauthorized surveillance
- ❌ Violating privacy laws or regulations
- ❌ Any malicious or harmful activities

### What This Tool IS For:
- ✅ Learning about system programming concepts
- ✅ Understanding input monitoring mechanisms
- ✅ Educational research in cybersecurity
- ✅ Personal use on your own devices with consent
- ✅ Academic study and programming practice

## 🛡️ Built-in Ethical Safeguards

This project includes multiple layers of protection:

1. **Explicit Consent Requirement**: Users must confirm ethical usage before the tool starts
2. **Prominent Ethical Warnings**: Clear warnings displayed at startup
3. **Path Validation**: Prevents access to system-critical directories
4. **Data Sanitization**: Automatically redacts potentially sensitive information
5. **Encryption**: Log files are encrypted by default for privacy
6. **Educational Focus**: Code is designed for learning, not production use

## 📁 Project Structure

```
Project/
├── src/                    # Main source code
│   ├── __init__.py        # Package initialization
│   ├── keylogger.py       # Main keylogger implementation
│   └── utils.py           # Utility functions
├── tests/                  # Unit tests
│   ├── __init__.py        # Test package initialization
│   ├── test_keylogger.py  # Keylogger tests
│   └── test_utils.py      # Utility function tests
├── logs/                   # Output log files (created at runtime)
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── .gitignore             # Git ignore patterns
└── LICENSE                # MIT License
```

## 🚀 Installation and Setup

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation Steps

1. **Clone the repository** (if using git):
   ```bash
   git clone <repository-url>
   cd KeyLogger/Project
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python -c "import pynput, psutil, cryptography, colorama; print('All dependencies installed successfully!')"
   ```

## 📖 Usage Instructions

### Basic Usage

1. **Run the educational demonstration**:
   ```bash
   python src/keylogger.py
   ```

2. **Follow the ethical consent prompts**:
   - Read the ethical warning carefully
   - Type 'yes' to confirm ethical usage
   - The tool will start monitoring your own keystrokes

3. **Stop the keylogger**:
   - Press the `ESC` key to stop monitoring
   - Or use `Ctrl+C` to interrupt

### Advanced Usage

```python
from src.keylogger import EducationalKeylogger

# Create keylogger instance
keylogger = EducationalKeylogger(
    log_dir="custom_logs",
    encrypt_logs=True
)

# Start monitoring
keylogger.start()

# Get statistics
stats = keylogger.get_statistics()
print(f"Keys logged: {stats['key_count']}")

# Stop monitoring
keylogger.stop()
```

### Using Utility Functions

```python
from src.utils import (
    validate_file_path, create_safe_directory,
    encrypt_data, decrypt_data, sanitize_log_data
)

# Validate file paths
is_safe = validate_file_path("/safe/path/file.txt")

# Create directories safely
create_safe_directory("new_directory")

# Encrypt sensitive data
encrypted = encrypt_data("sensitive text", encryption_key)

# Sanitize log data
clean_data = sanitize_log_data({"password": "secret123"})
```

## 🧪 Running Tests

### Run All Tests
```bash
pytest tests/
```

### Run Specific Test Files
```bash
pytest tests/test_keylogger.py
pytest tests/test_utils.py
```

### Run Tests with Coverage
```bash
pytest tests/ --cov=src --cov-report=html
```

### Run Tests Verbosely
```bash
pytest tests/ -v
```

## 🔒 Security Features

### Encryption
- Log files are encrypted using Fernet (symmetric encryption)
- Encryption keys are stored securely in the logs directory
- Each session generates a unique encryption key

### Path Validation
- Prevents access to system-critical directories
- Restricts file operations to safe locations
- Validates all file paths before operations

### Data Sanitization
- Automatically detects and redacts sensitive patterns
- Removes passwords, API keys, and tokens from logs
- Protects against accidental exposure of sensitive data

## 📊 Log File Format

Log files are stored in JSON format with the following structure:

```json
[
  {
    "timestamp": "2023-12-25T14:30:45.123456",
    "event_type": "press",
    "key": "a",
    "process": "Educational Demo"
  },
  {
    "timestamp": "2023-12-25T14:30:45.234567",
    "event_type": "press",
    "key": "b",
    "process": "Educational Demo"
  }
]
```

## 🛠️ Development

### Code Style
- Follow PEP 8 guidelines
- Use type hints throughout
- Include comprehensive docstrings
- Write unit tests for all functions

### Adding New Features
1. Implement the feature in the appropriate module
2. Add comprehensive tests
3. Update documentation
4. Ensure ethical safeguards are maintained

### Testing Guidelines
- Test all ethical safeguards
- Verify path validation works correctly
- Ensure encryption/decryption functions properly
- Test edge cases and error conditions

## 🚨 Troubleshooting

### Common Issues

1. **Permission Denied Errors**:
   - Ensure you're running in a directory you have write access to
   - Check that the logs directory can be created

2. **Import Errors**:
   - Verify all dependencies are installed: `pip install -r requirements.txt`
   - Check Python version compatibility

3. **Encryption Errors**:
   - Ensure the cryptography package is properly installed
   - Check that the logs directory is writable

4. **Key Monitoring Not Working**:
   - On some systems, additional permissions may be required
   - Ensure no other key monitoring software is running

### Getting Help

If you encounter issues:
1. Check the error messages carefully
2. Verify all dependencies are installed
3. Ensure you're following ethical usage guidelines
4. Review the test cases for examples

## 📚 Learning Resources

### Related Topics to Study
- **Operating System Internals**: How input events are handled
- **Event-Driven Programming**: Understanding event listeners and callbacks
- **Cryptography**: Encryption algorithms and key management
- **System Security**: How to protect against unauthorized monitoring
- **Privacy Laws**: Understanding legal requirements around data collection

### Recommended Reading
- "Operating System Concepts" by Silberschatz et al.
- "Applied Cryptography" by Bruce Schneier
- "The Art of Deception" by Kevin Mitnick
- "Privacy in Context" by Helen Nissenbaum

## 🤝 Contributing

### Contributing Guidelines
1. **Maintain Ethical Focus**: All contributions must support educational use
2. **Add Tests**: Include comprehensive tests for new features
3. **Update Documentation**: Keep README and docstrings current
4. **Follow Code Style**: Use consistent formatting and naming

### What We're Looking For
- Additional safety features
- Improved error handling
- Better documentation
- Performance optimizations
- Additional utility functions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal Disclaimer

**The authors of this project are not responsible for any misuse of this software. Users are solely responsible for ensuring their use complies with applicable laws and ethical guidelines.**

**This software is provided "as is" without warranty of any kind. Use at your own risk and only for educational purposes.**

## 📞 Contact

For questions about ethical usage, educational applications, or technical issues:

- **Educational Use**: Ensure you're using this for legitimate learning purposes
- **Legal Questions**: Consult with legal professionals familiar with your jurisdiction
- **Technical Support**: Check the troubleshooting section and test cases first

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally for educational purposes only.**
