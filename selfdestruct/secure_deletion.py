"""
FileGuard Secure Deletion Module
Provides secure file deletion with multiple overwrite passes and attempt tracking.
"""

import os
import json
import random
import hashlib
import datetime
from typing import Optional, Dict, Any


class SecureDeletion:
    """
    Manages secure file deletion with attempt tracking and configuration.
    """
    
    def __init__(self, data_dir: Optional[str] = None):
        """
        Initialize the SecureDeletion manager.
        
        Args:
            data_dir (str): Directory to store configuration files (default: data/)
        """
        if data_dir is None:
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.data_dir = os.path.join(current_dir, "data")
        else:
            self.data_dir = data_dir
        
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        # File paths for storing data
        self.attempt_config_file = os.path.join(self.data_dir, "attempt_limits.json")
        self.attempt_tracking_file = os.path.join(self.data_dir, "failed_attempts.json")
    
    def _load_json_file(self, file_path: str) -> Dict[str, Any]:
        """
        Load data from a JSON file.
        
        Args:
            file_path (str): Path to the JSON file
            
        Returns:
            Dict: Loaded data or empty dict if file doesn't exist
        """
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return {}
        except Exception:
            return {}
    
    def _save_json_file(self, file_path: str, data: Dict[str, Any]) -> bool:
        """
        Save data to a JSON file.
        
        Args:
            file_path (str): Path to the JSON file
            data (Dict): Data to save
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False
    
    def _normalize_path(self, file_path: str) -> str:
        """
        Normalize file path for consistent storage.
        
        Args:
            file_path (str): File path to normalize
            
        Returns:
            str: Normalized absolute path
        """
        return os.path.normpath(os.path.abspath(file_path))
    
    def _create_file_hash(self, file_path: str) -> str:
        """
        Create a unique hash for a file path.
        
        Args:
            file_path (str): File path to hash
            
        Returns:
            str: SHA-256 hash of the file path
        """
        normalized_path = self._normalize_path(file_path)
        return hashlib.sha256(normalized_path.encode('utf-8')).hexdigest()
    
    def secure_delete_file(self, file_path: str, passes: int = 3) -> bool:
        """
        Securely delete a file by overwriting its contents multiple times.
        
        Args:
            file_path (str): Path to the file to delete
            passes (int): Number of overwrite passes (default: 3)
            
        Returns:
            bool: True if deletion successful, False otherwise
        """
        try:
            if not file_path or passes < 1:
                return False
            
            # Normalize the path
            normalized_path = self._normalize_path(file_path)
            
            # Check if file exists
            if not os.path.exists(normalized_path):
                return False
            
            # Check if it's actually a file (not a directory)
            if not os.path.isfile(normalized_path):
                return False
            
            # Get file size
            file_size = os.path.getsize(normalized_path)
            
            if file_size == 0:
                # Empty file, just delete it
                os.remove(normalized_path)
                return True
            
            # Perform multiple overwrite passes
            with open(normalized_path, 'r+b') as f:
                for pass_num in range(passes):
                    # Seek to beginning of file
                    f.seek(0)
                    
                    if pass_num == 0:
                        # First pass: overwrite with zeros
                        f.write(b'\x00' * file_size)
                    elif pass_num == 1:
                        # Second pass: overwrite with ones
                        f.write(b'\xFF' * file_size)
                    else:
                        # Subsequent passes: overwrite with random data
                        random_data = bytearray(random.getrandbits(8) for _ in range(file_size))
                        f.write(random_data)
                    
                    # Force write to disk
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally, delete the file
            os.remove(normalized_path)
            
            return True
            
        except Exception:
            return False
    
    def configure_attempt_limit(self, file_path: str, max_attempts: int) -> bool:
        """
        Configure the maximum number of failed attempts before secure deletion.
        
        Args:
            file_path (str): Path to the file to configure
            max_attempts (int): Maximum number of failed attempts allowed
            
        Returns:
            bool: True if configuration successful, False otherwise
        """
        try:
            if not file_path or max_attempts < 1:
                return False
            
            # Normalize the path
            normalized_path = self._normalize_path(file_path)
            
            # Load existing configuration
            config = self._load_json_file(self.attempt_config_file)
            
            # Create file hash for indexing
            file_hash = self._create_file_hash(normalized_path)
            
            # Set configuration
            config[file_hash] = {
                'file_path': normalized_path,
                'max_attempts': max_attempts,
                'configured_at': datetime.datetime.now().isoformat()
            }
            
            # Save configuration
            return self._save_json_file(self.attempt_config_file, config)
            
        except Exception:
            return False
    
    def track_failed_attempt(self, file_path: str) -> Optional[int]:
        """
        Track a failed attempt and return remaining attempts before deletion.
        
        Args:
            file_path (str): Path to the file that had a failed attempt
            
        Returns:
            Optional[int]: Number of remaining attempts, or None if no limit configured
        """
        try:
            if not file_path:
                return None
            
            # Normalize the path
            normalized_path = self._normalize_path(file_path)
            
            # Create file hash for indexing
            file_hash = self._create_file_hash(normalized_path)
            
            # Load configuration to check if file has attempt limit
            config = self._load_json_file(self.attempt_config_file)
            
            if file_hash not in config:
                return None  # No attempt limit configured for this file
            
            max_attempts = config[file_hash]['max_attempts']
            
            # Load existing attempt tracking
            attempts = self._load_json_file(self.attempt_tracking_file)
            
            # Initialize or update attempt count
            if file_hash not in attempts:
                attempts[file_hash] = {
                    'file_path': normalized_path,
                    'failed_attempts': 0,
                    'first_attempt': datetime.datetime.now().isoformat(),
                    'last_attempt': None
                }
            
            # Increment failed attempts
            attempts[file_hash]['failed_attempts'] += 1
            attempts[file_hash]['last_attempt'] = datetime.datetime.now().isoformat()
            
            current_attempts = attempts[file_hash]['failed_attempts']
            remaining_attempts = max_attempts - current_attempts
            
            # Save attempt tracking
            self._save_json_file(self.attempt_tracking_file, attempts)
            
            # Check if maximum attempts reached
            if remaining_attempts <= 0:
                # Trigger secure deletion
                if self.secure_delete_file(normalized_path):
                    # Remove from tracking after successful deletion
                    del attempts[file_hash]
                    if file_hash in config:
                        del config[file_hash]
                    
                    self._save_json_file(self.attempt_tracking_file, attempts)
                    self._save_json_file(self.attempt_config_file, config)
                    
                    return 0  # File has been deleted
            
            return max(0, remaining_attempts)
            
        except Exception:
            return None
    
    def get_attempt_status(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Get the current attempt status for a file.
        
        Args:
            file_path (str): Path to the file to check
            
        Returns:
            Optional[Dict]: Attempt status information, or None if not configured
        """
        try:
            if not file_path:
                return None
            
            # Normalize the path
            normalized_path = self._normalize_path(file_path)
            
            # Create file hash for indexing
            file_hash = self._create_file_hash(normalized_path)
            
            # Load configuration and attempts
            config = self._load_json_file(self.attempt_config_file)
            attempts = self._load_json_file(self.attempt_tracking_file)
            
            if file_hash not in config:
                return None  # No configuration for this file
            
            max_attempts = config[file_hash]['max_attempts']
            current_attempts = attempts.get(file_hash, {}).get('failed_attempts', 0)
            remaining_attempts = max_attempts - current_attempts
            
            return {
                'file_path': normalized_path,
                'max_attempts': max_attempts,
                'current_attempts': current_attempts,
                'remaining_attempts': max(0, remaining_attempts),
                'configured_at': config[file_hash]['configured_at'],
                'first_attempt': attempts.get(file_hash, {}).get('first_attempt'),
                'last_attempt': attempts.get(file_hash, {}).get('last_attempt')
            }
            
        except Exception:
            return None
    
    def reset_attempts(self, file_path: str) -> bool:
        """
        Reset the failed attempt count for a file.
        
        Args:
            file_path (str): Path to the file to reset
            
        Returns:
            bool: True if reset successful, False otherwise
        """
        try:
            if not file_path:
                return False
            
            # Normalize the path
            normalized_path = self._normalize_path(file_path)
            
            # Create file hash for indexing
            file_hash = self._create_file_hash(normalized_path)
            
            # Load existing attempt tracking
            attempts = self._load_json_file(self.attempt_tracking_file)
            
            # Remove entry if it exists
            if file_hash in attempts:
                del attempts[file_hash]
                return self._save_json_file(self.attempt_tracking_file, attempts)
            
            return True  # No attempts to reset is considered success
            
        except Exception:
            return False
    
    def remove_file_configuration(self, file_path: str) -> bool:
        """
        Remove attempt limit configuration for a file.
        
        Args:
            file_path (str): Path to the file to remove configuration for
            
        Returns:
            bool: True if removal successful, False otherwise
        """
        try:
            if not file_path:
                return False
            
            # Normalize the path
            normalized_path = self._normalize_path(file_path)
            
            # Create file hash for indexing
            file_hash = self._create_file_hash(normalized_path)
            
            # Load configuration and attempts
            config = self._load_json_file(self.attempt_config_file)
            attempts = self._load_json_file(self.attempt_tracking_file)
            
            # Remove from both files
            removed = False
            if file_hash in config:
                del config[file_hash]
                removed = True
            
            if file_hash in attempts:
                del attempts[file_hash]
                removed = True
            
            if removed:
                success1 = self._save_json_file(self.attempt_config_file, config)
                success2 = self._save_json_file(self.attempt_tracking_file, attempts)
                return success1 and success2
            
            return True  # Nothing to remove is considered success
            
        except Exception:
            return False


# Convenience functions for global usage
def secure_delete_file(file_path: str, passes: int = 3) -> bool:
    """
    Securely delete a file by overwriting its contents multiple times.
    
    Args:
        file_path (str): Path to the file to delete
        passes (int): Number of overwrite passes (default: 3)
        
    Returns:
        bool: True if deletion successful, False otherwise
    """
    manager = SecureDeletion()
    return manager.secure_delete_file(file_path, passes)


def configure_attempt_limit(file_path: str, max_attempts: int) -> bool:
    """
    Configure the maximum number of failed attempts before secure deletion.
    
    Args:
        file_path (str): Path to the file to configure
        max_attempts (int): Maximum number of failed attempts allowed
        
    Returns:
        bool: True if configuration successful, False otherwise
    """
    manager = SecureDeletion()
    return manager.configure_attempt_limit(file_path, max_attempts)


def track_failed_attempt(file_path: str) -> Optional[int]:
    """
    Track a failed attempt and return remaining attempts before deletion.
    
    Args:
        file_path (str): Path to the file that had a failed attempt
        
    Returns:
        Optional[int]: Number of remaining attempts, or None if no limit configured
    """
    manager = SecureDeletion()
    return manager.track_failed_attempt(file_path)


# Simple test functions
if __name__ == "__main__":
    import tempfile
    
    def test_secure_deletion():
        """Test the SecureDeletion functionality."""
        print("Testing FileGuard Secure Deletion...")
        
        try:
            # Create temporary directory for testing
            with tempfile.TemporaryDirectory() as temp_dir:
                data_dir = os.path.join(temp_dir, "test_data")
                
                # Create test file
                test_file_path = os.path.join(temp_dir, "test_file.txt")
                test_content = "This is sensitive data that should be securely deleted!" * 100
                
                with open(test_file_path, 'w') as f:
                    f.write(test_content)
                
                print(f"Created test file: {test_file_path}")
                print(f"Original file size: {os.path.getsize(test_file_path)} bytes")
                
                # Initialize manager
                manager = SecureDeletion(data_dir)
                print("✓ SecureDeletion initialized")
                
                # Test configuring attempt limit
                success = manager.configure_attempt_limit(test_file_path, 3)
                if success:
                    print("✓ Test PASSED: Attempt limit configured")
                else:
                    print("✗ Test FAILED: Attempt limit configuration failed")
                
                # Test getting attempt status
                status = manager.get_attempt_status(test_file_path)
                if status and status['max_attempts'] == 3:
                    print("✓ Test PASSED: Attempt status retrieved")
                    print(f"  Max attempts: {status['max_attempts']}")
                    print(f"  Current attempts: {status['current_attempts']}")
                    print(f"  Remaining attempts: {status['remaining_attempts']}")
                else:
                    print("✗ Test FAILED: Could not retrieve attempt status")
                
                # Test tracking failed attempts
                remaining = manager.track_failed_attempt(test_file_path)
                if remaining is not None:
                    print(f"✓ Test PASSED: Failed attempt tracked, {remaining} attempts remaining")
                else:
                    print("✗ Test FAILED: Failed attempt tracking failed")
                
                # Track more attempts
                remaining = manager.track_failed_attempt(test_file_path)
                print(f"After second attempt: {remaining} attempts remaining")
                
                # Create another test file for secure deletion test
                test_file2_path = os.path.join(temp_dir, "test_file2.txt")
                with open(test_file2_path, 'w') as f:
                    f.write("Another test file for secure deletion")
                
                # Test secure deletion directly
                success = manager.secure_delete_file(test_file2_path, passes=2)
                if success and not os.path.exists(test_file2_path):
                    print("✓ Test PASSED: File securely deleted")
                else:
                    print("✗ Test FAILED: Secure deletion failed")
                
                # Test convenience functions
                test_file3_path = os.path.join(temp_dir, "test_file3.txt")
                with open(test_file3_path, 'w') as f:
                    f.write("Test file for convenience functions")
                
                success1 = configure_attempt_limit(test_file3_path, 2)
                remaining = track_failed_attempt(test_file3_path)
                
                if success1 and remaining is not None:
                    print("✓ Test PASSED: Convenience functions work")
                    print(f"  Remaining attempts: {remaining}")
                else:
                    print("✗ Test FAILED: Convenience functions should work")
                
                # Test direct secure deletion convenience function
                test_file4_path = os.path.join(temp_dir, "test_file4.txt")
                with open(test_file4_path, 'w') as f:
                    f.write("Test file for direct deletion")
                
                success = secure_delete_file(test_file4_path, passes=1)
                if success and not os.path.exists(test_file4_path):
                    print("✓ Test PASSED: Direct secure deletion works")
                else:
                    print("✗ Test FAILED: Direct secure deletion failed")
                
                # Test edge cases
                success = manager.secure_delete_file("non_existent_file.txt")
                if not success:
                    print("✓ Test PASSED: Correctly handled non-existent file")
                else:
                    print("✗ Test FAILED: Should fail for non-existent file")
                
                # Test resetting attempts
                success = manager.reset_attempts(test_file_path)
                if success:
                    print("✓ Test PASSED: Attempts reset successfully")
                else:
                    print("✗ Test FAILED: Attempt reset failed")
                
                print("Secure deletion tests completed")
                
        except Exception as e:
            print(f"✗ Test FAILED with error: {e}")
    
    test_secure_deletion()