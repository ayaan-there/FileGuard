"""
FileGuard Secure Logging Module
Provides encrypted logging with hash chaining for tamper detection.
"""

import os
import json
import hashlib
import datetime
from typing import List, Dict, Tuple, Optional, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class SecureLogger:
    """
    Secure logging class with encryption and hash chaining for tamper detection.
    """
    
    def __init__(self, log_dir: Optional[str] = None, password: str = "default_log_password"):
        """
        Initialize the SecureLogger.
        
        Args:
            log_dir (str): Directory to store log files (default: logs/)
            password (str): Password for log encryption
        """
        if log_dir is None:
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.log_dir = os.path.join(current_dir, "logs")
        else:
            self.log_dir = log_dir
        
        self.password = password
        self._salt = b"fileguard_logging_salt_v1"  # Fixed salt for consistent key
        self._key = self._derive_key(password)
        
        # Create log directory if it doesn't exist
        os.makedirs(self.log_dir, exist_ok=True)
    
    def _derive_key(self, password: str) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password (str): Password to derive key from
            
        Returns:
            bytes: 32-byte derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=self._salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _encrypt_data(self, data: str) -> bytes:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data (str): Data to encrypt
            
        Returns:
            bytes: Encrypted data (nonce + ciphertext)
        """
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        return nonce + ciphertext
    
    def _decrypt_data(self, encrypted_data: bytes) -> str:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data (bytes): Encrypted data (nonce + ciphertext)
            
        Returns:
            str: Decrypted data
            
        Raises:
            ValueError: If decryption fails
        """
        if len(encrypted_data) < 12:
            raise ValueError("Invalid encrypted data format")
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        aesgcm = AESGCM(self._key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def _calculate_hash(self, data: str, previous_hash: str = "") -> str:
        """
        Calculate SHA-256 hash for hash chaining.
        
        Args:
            data (str): Data to hash
            previous_hash (str): Previous hash in the chain
            
        Returns:
            str: SHA-256 hash
        """
        combined = f"{previous_hash}{data}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    def _get_log_file_path(self, date: Optional[datetime.date] = None) -> str:
        """
        Get the log file path for a specific date.
        
        Args:
            date (datetime.date): Date for log file (default: today)
            
        Returns:
            str: Path to log file
        """
        if date is None:
            date = datetime.date.today()
        
        filename = f"fileguard_{date.strftime('%Y%m%d')}.log"
        return os.path.join(self.log_dir, filename)
    
    def _load_existing_logs(self, log_file_path: str) -> List[Dict[str, Any]]:
        """
        Load existing logs from file.
        
        Args:
            log_file_path (str): Path to log file
            
        Returns:
            List[Dict]: List of log entries
        """
        if not os.path.exists(log_file_path):
            return []
        
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    return []
                
                logs = []
                for line in content.split('\n'):
                    if line.strip():
                        log_entry = json.loads(line)
                        logs.append(log_entry)
                return logs
        except Exception:
            return []
    
    def log_event(self, event_type: str, message: str, 
                  metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Log an event with encryption and hash chaining.
        
        Args:
            event_type (str): Type of event (e.g., "ENCRYPTION", "DECRYPTION", "ERROR")
            message (str): Log message
            metadata (Dict): Additional metadata for the event
            
        Returns:
            bool: True if logging succeeded, False otherwise
        """
        try:
            if not event_type or not message:
                return False
            
            # Create timestamp
            timestamp = datetime.datetime.now().isoformat()
            
            # Get log file path
            log_file_path = self._get_log_file_path()
            
            # Load existing logs to get previous hash
            existing_logs = self._load_existing_logs(log_file_path)
            previous_hash = existing_logs[-1]['hash'] if existing_logs else ""
            
            # Create log entry
            log_entry = {
                'timestamp': timestamp,
                'event_type': event_type,
                'message': message,
                'metadata': metadata or {}
            }
            
            # Convert to JSON string for hashing and encryption
            log_json = json.dumps(log_entry, separators=(',', ':'))
            
            # Calculate hash for integrity
            entry_hash = self._calculate_hash(log_json, previous_hash)
            
            # Encrypt the log entry
            encrypted_data = self._encrypt_data(log_json)
            
            # Create final log record
            log_record = {
                'hash': entry_hash,
                'encrypted_data': encrypted_data.hex(),  # Store as hex string
                'previous_hash': previous_hash
            }
            
            # Append to log file
            with open(log_file_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_record, separators=(',', ':')) + '\n')
            
            return True
            
        except Exception as e:
            # Fallback logging to stderr if available
            print(f"Secure logging failed: {e}", file=__import__('sys').stderr)
            return False
    
    def read_logs(self, date: Optional[datetime.date] = None, 
                  limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Read and decrypt logs from a specific date.
        
        Args:
            date (datetime.date): Date to read logs from (default: today)
            limit (int): Maximum number of logs to return
            
        Returns:
            List[Dict]: List of decrypted log entries
        """
        try:
            log_file_path = self._get_log_file_path(date)
            
            if not os.path.exists(log_file_path):
                return []
            
            logs = []
            with open(log_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        log_record = json.loads(line)
                        encrypted_data = bytes.fromhex(log_record['encrypted_data'])
                        decrypted_json = self._decrypt_data(encrypted_data)
                        log_entry = json.loads(decrypted_json)
                        
                        # Add hash information
                        log_entry['_hash'] = log_record['hash']
                        log_entry['_previous_hash'] = log_record['previous_hash']
                        
                        logs.append(log_entry)
                        
                        if limit and len(logs) >= limit:
                            break
                            
                    except Exception:
                        # Skip corrupted entries
                        continue
            
            return logs
            
        except Exception:
            return []
    
    def verify_log_integrity(self, date: Optional[datetime.date] = None) -> Tuple[bool, List[str]]:
        """
        Verify the integrity of logs using hash chaining.
        
        Args:
            date (datetime.date): Date to verify logs for (default: today)
            
        Returns:
            Tuple[bool, List[str]]: (is_valid, list_of_issues)
        """
        try:
            log_file_path = self._get_log_file_path(date)
            
            if not os.path.exists(log_file_path):
                return True, []  # No logs to verify
            
            issues = []
            previous_hash = ""
            
            with open(log_file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        log_record = json.loads(line)
                        
                        # Verify previous hash matches
                        if log_record['previous_hash'] != previous_hash:
                            issues.append(f"Line {line_num}: Previous hash mismatch")
                        
                        # Decrypt and verify hash
                        encrypted_data = bytes.fromhex(log_record['encrypted_data'])
                        decrypted_json = self._decrypt_data(encrypted_data)
                        
                        # Recalculate hash
                        calculated_hash = self._calculate_hash(decrypted_json, previous_hash)
                        
                        if calculated_hash != log_record['hash']:
                            issues.append(f"Line {line_num}: Hash verification failed")
                        
                        previous_hash = log_record['hash']
                        
                    except Exception as e:
                        issues.append(f"Line {line_num}: Corrupted entry - {str(e)}")
            
            return len(issues) == 0, issues
            
        except Exception as e:
            return False, [f"Verification failed: {str(e)}"]


# Simple test functions
if __name__ == "__main__":
    import tempfile
    import time
    
    def test_secure_logging():
        """Test the SecureLogger functionality."""
        print("Testing FileGuard Secure Logging...")
        
        try:
            # Create temporary directory for testing
            with tempfile.TemporaryDirectory() as temp_dir:
                log_dir = os.path.join(temp_dir, "test_logs")
                
                # Initialize logger
                logger = SecureLogger(log_dir, "test_password_123")
                print("✓ SecureLogger initialized")
                
                # Test logging events
                success1 = logger.log_event("ENCRYPTION", "File encrypted successfully", 
                                          {"file": "test.txt", "size": 1024})
                success2 = logger.log_event("DECRYPTION", "File decrypted successfully")
                success3 = logger.log_event("ERROR", "Invalid password attempt", 
                                          {"attempts": 3, "source_ip": "192.168.1.1"})
                
                if success1 and success2 and success3:
                    print("✓ Test PASSED: All events logged successfully")
                else:
                    print("✗ Test FAILED: Some events failed to log")
                
                # Test reading logs
                logs = logger.read_logs()
                
                if len(logs) == 3:
                    print("✓ Test PASSED: All logs read successfully")
                    for i, log in enumerate(logs):
                        print(f"  Log {i+1}: {log['event_type']} - {log['message']}")
                else:
                    print(f"✗ Test FAILED: Expected 3 logs, got {len(logs)}")
                
                # Test log integrity verification
                is_valid, issues = logger.verify_log_integrity()
                
                if is_valid:
                    print("✓ Test PASSED: Log integrity verified")
                else:
                    print(f"✗ Test FAILED: Log integrity issues: {issues}")
                
                # Test with corrupted data
                log_file_path = logger._get_log_file_path()
                
                # Append corrupted entry
                with open(log_file_path, 'a') as f:
                    f.write('{"hash": "fake_hash", "encrypted_data": "corrupted", "previous_hash": "fake"}\n')
                
                is_valid, issues = logger.verify_log_integrity()
                
                if not is_valid and len(issues) > 0:
                    print("✓ Test PASSED: Corrupted data detected")
                else:
                    print("✗ Test FAILED: Should have detected corrupted data")
                
                # Test with wrong password
                wrong_logger = SecureLogger(log_dir, "wrong_password")
                wrong_logs = wrong_logger.read_logs()
                
                if len(wrong_logs) == 0:
                    print("✓ Test PASSED: Wrong password returns empty logs")
                else:
                    print("✗ Test FAILED: Wrong password should return empty logs")
                
                print("Secure logging tests completed")
                
        except Exception as e:
            print(f"✗ Test FAILED with error: {e}")
    
    test_secure_logging()