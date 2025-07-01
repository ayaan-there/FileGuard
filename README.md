# FileGuard - Advanced Secure File Manager

<div align="center">

![FileGuard Logo](https://img.shields.io/badge/FileGuard-Secure%20File%20Manager-blue?style=for-the-badge)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Security](https://img.shields.io/badge/Security-AES--256-red?style=flat-square)](#encryption)
[![2FA](https://img.shields.io/badge/2FA-Microsoft%20Authenticator-orange?style=flat-square)](#two-factor-authentication)

*Military-grade file encryption, compression, and security management with advanced protection features*

</div>

## 🛡️ Overview

FileGuard is a comprehensive security-focused file management application that provides advanced encryption, compression, and protection mechanisms. Built with Python and featuring a modern GUI, it offers enterprise-level security features including decoy file protection, two-factor authentication, secure deletion, and comprehensive audit logging.

## ✨ Key Features

### 🔐 **Advanced Security**
- **AES-256 Encryption**: Military-grade encryption with password-based key derivation
- **Two-Factor Authentication**: Integration with Microsoft Authenticator for TOTP-based 2FA
- **Secure Key Management**: Automated TOTP secret storage and cleanup
- **Password Attempt Limiting**: Configurable failed attempt tracking with security responses

### 🎭 **Decoy Protection System**
- **Decoy File Mapping**: Serve fake files after failed authentication attempts
- **Secure Original Deletion**: Automatically delete real files after showing decoys
- **Enhanced Security Mode**: Multi-pass secure deletion for sensitive data
- **Attempt Tracking**: Monitor and respond to unauthorized access attempts

### 🗜️ **File Compression**
- **Pre-encryption Compression**: Reduce file size before encryption
- **Automatic Detection**: Smart handling of compressed and encrypted files
- **Ratio Reporting**: Compression efficiency metrics and logging

### 📊 **Comprehensive Logging**
- **Security Event Logging**: Detailed audit trail of all operations
- **Tamper-Proof Logs**: Secure logging with integrity verification
- **Real-time Monitoring**: Live log viewing with categorized events
- **Session Statistics**: Track encryption, decryption, and security events

### 🖥️ **Modern User Interface**
- **Tabbed Interface**: Separate tabs for encryption, decryption, and logs
- **Progress Indicators**: Real-time operation status and feedback
- **Responsive Design**: Modern, intuitive GUI with professional styling
- **Error Handling**: Comprehensive error reporting and user guidance

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Required Dependencies

```bash
pip install -r requirements.txt
```

**Core Dependencies:**
- `cryptography` - AES encryption and key derivation
- `pyotp` - TOTP two-factor authentication
- `qrcode[pil]` - QR code generation for 2FA setup
- `tkinter` - GUI framework (usually included with Python)

### Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd merinayimehantisfileecryptorpe
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python main.py
   ```

## 📖 Usage Guide

### 🔒 File Encryption & Compression

1. **Select File**: Click "Browse..." to select the file you want to protect
2. **Choose Options**:
   - ✅ **Compress file before encryption** - Reduces file size
   - ✅ **Encrypt file with AES-256** - Applies military-grade encryption
   - ✅ **Enable 2FA** - Adds Microsoft Authenticator protection
   - ✅ **Enable Decoy File Protection** - Sets up decoy system

3. **Configure 2FA** (if enabled):
   - Click "Setup 2FA" to generate a secret
   - Scan QR code with Microsoft Authenticator
   - Verify with a 6-digit code

4. **Set Decoy Protection** (if enabled):
   - Select a decoy file to show on failed attempts
   - Set a decoy password
   - Enable secure deletion of original file

5. **Enter Password**: Set a strong password for encryption
6. **Start Process**: Click to begin encryption

### 🔓 File Decryption & Decompression

1. **Select Encrypted File**: Choose a `.fgc` or `.fg2c` file
2. **Enter Password**: Provide the encryption password
3. **2FA Verification** (for `.fg2c` files): Enter the 6-digit code from Microsoft Authenticator
4. **Decrypt File**: Click to begin decryption

**Password Attempt Security:**
- Maximum of 3 password attempts allowed
- After 3 failed attempts, decoy file is served (if configured)
- Original file is securely deleted when decoy is shown
- 2FA secrets are automatically cleaned up after decryption

### 📋 Security Logs

Monitor all security events in real-time:
- Encryption/decryption operations
- Failed authentication attempts
- 2FA verifications
- Decoy system activations
- File operations and errors

## 🏗️ Architecture

### Project Structure

```
FileGuard/
├── main.py                 # Application entry point
├── requirements.txt        # Dependencies list
├── README.md              # This file
├── gui/
│   ├── __init__.py
│   └── app.py             # Main GUI application
├── encryption/
│   ├── __init__.py
│   └── encryptor.py       # AES-256 encryption module
├── compression/
│   ├── __init__.py
│   └── compressor.py      # File compression module
├── two_factor/
│   ├── __init__.py
│   └── authenticator.py   # TOTP 2FA implementation
├── decoy/
│   ├── __init__.py
│   └── decoy_manager.py   # Decoy file system
├── selfdestruct/
│   ├── __init__.py
│   └── secure_deletion.py # Secure file deletion
├── fileguardlogging/
│   ├── __init__.py
│   └── secure_logger.py   # Security audit logging
├── data/
│   └── totp_secrets/      # TOTP secret storage
└── logs/                  # Security log files
```

### File Extensions

- **`.fgc`**: Standard FileGuard encrypted/compressed file
- **`.fg2c`**: FileGuard file with 2FA protection enabled
- **`.fcomp`**: Intermediate compressed file (auto-deleted)
- **`.fenc`**: Intermediate encrypted file (auto-deleted)

## 🔧 Configuration

### Security Settings

**Encryption:**
- Algorithm: AES-256-GCM
- Key Derivation: PBKDF2 with SHA-256
- Salt Length: 32 bytes
- Iterations: 100,000

**Password Attempts:**
- Maximum attempts: 3 (configurable)
- Lockout behavior: Serve decoy file
- Secure deletion: Multi-pass overwrite

**2FA Settings:**
- TOTP Algorithm: SHA-1 (Microsoft Authenticator compatible)
- Token Length: 6 digits
- Time Step: 30 seconds
- Secret Storage: Encrypted in `data/totp_secrets/`

### Logging Configuration

- **Log Location**: `logs/` directory
- **Log Format**: Structured JSON with timestamps
- **Log Levels**: INFO, SUCCESS, WARNING, ERROR, SECURITY
- **Log Rotation**: Daily rotation with compression
- **Integrity**: Hash verification for tamper detection

## 🛡️ Security Features

### Encryption Details

- **Algorithm**: AES-256 in GCM mode for authenticated encryption
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Random Salt**: 32-byte cryptographically secure random salt per file
- **Authentication**: Built-in authentication tag prevents tampering

### Two-Factor Authentication

- **TOTP Implementation**: Time-based One-Time Passwords
- **Microsoft Authenticator Compatible**: Standard RFC 6238 implementation
- **Secret Management**: Automatic generation, storage, and cleanup
- **QR Code Setup**: Easy mobile app integration

### Decoy System

- **File Mapping**: Associate real files with decoy files
- **Password Attempts**: Serve decoy after failed authentication
- **Secure Deletion**: Original file destroyed when decoy shown
- **Attempt Tracking**: Monitor unauthorized access patterns

### Secure Deletion

- **Multi-Pass Overwrite**: DoD 5220.22-M standard compliance
- **Random Data**: Cryptographically secure random overwriting
- **Metadata Cleaning**: File system metadata sanitization
- **Verification**: Confirm successful deletion

## 🔍 Troubleshooting

### Common Issues

**"2FA module not available"**
- Install required dependencies: `pip install pyotp qrcode[pil]`
- Ensure Python has GUI support (tkinter)

**"Decryption failed"**
- Verify correct password
- Check file integrity (not corrupted)
- Ensure proper file extension (.fgc or .fg2c)

**"QR code not displaying"**
- Install PIL/Pillow: `pip install pillow`
- Check file permissions in current directory

**"Secure deletion failed"**
- Run as administrator (Windows) or with sudo (Linux/Mac)
- Check file permissions and disk space
- Ensure file is not in use by another process

### Debug Mode

Enable detailed logging by setting environment variable:
```bash
export FILEGUARD_DEBUG=1
python main.py
```

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Clone your fork
git clone <your-fork-url>
cd merinayimehantisfileecryptorpe

# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8

# Run tests
pytest tests/

# Format code
black .

# Lint code
flake8 .
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Notice

**Important Security Considerations:**

1. **Password Strength**: Use strong, unique passwords for encryption
2. **2FA Backup**: Save backup codes for your 2FA setup
3. **Secure Environment**: Run on trusted, malware-free systems
4. **File Backups**: Maintain secure backups of important files
5. **Log Security**: Protect log files from unauthorized access

## 🆘 Support

- **Issues**: Report bugs via GitHub Issues
- **Documentation**: Check the Wiki for detailed guides
- **Security**: Report vulnerabilities privately to [security email]

## 🎯 Roadmap

### Upcoming Features

- [ ] **Mobile App Companion**
- [ ] **Batch Processing**



<div align="center">

**FileGuard** - *Protecting your digital assets with military-grade security*

Made by Ayaan ❤️

</div>
