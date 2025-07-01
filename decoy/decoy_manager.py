"""
FileGuard Decoy Manager Module
Provides decoy file system functionality for enhanced security.
"""

import os
import json
import hashlib
import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path


class DecoyManager:
    """
    Manages decoy file system mappings and access tracking.
    """
    
    def __init__(self, data_dir: Optional[str] = None):
        """
        Initialize the DecoyManager.
        
        Args:
            data_dir (str): Directory to store decoy mappings (default: data/)
        """
        if data_dir is None:
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.data_dir = os.path.join(current_dir, "data")
        else:
            self.data_dir = data_dir
        
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        # File paths for storing data
        self.decoy_mappings_file = os.path.join(self.data_dir, "decoy_mappings.json")
        self.decoy_registry_file = os.path.join(self.data_dir, "decoy_registry.json")
        self.access_log_file = os.path.join(self.data_dir, "decoy_access_log.json")
    
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
    
    def register_decoy_file(self, decoy_path: str) -> bool:
        """
        Register a file as a decoy file.
        
        Args:
            decoy_path (str): Path to the decoy file
            
        Returns:
            bool: True if registration successful, False otherwise
        """
        try:
            if not decoy_path:
                return False
            
            # Normalize the path
            normalized_path = self._normalize_path(decoy_path)
            
            # Check if file exists
            if not os.path.exists(normalized_path):
                return False
            
            # Load existing registry
            registry = self._load_json_file(self.decoy_registry_file)
            
            # Create file hash for indexing
            file_hash = self._create_file_hash(normalized_path)
            
            # Register the decoy file
            registry[file_hash] = {
                'path': normalized_path,
                'registered_at': datetime.datetime.now().isoformat(),
                'access_count': 0,
                'last_accessed': None
            }
            
            # Save registry
            return self._save_json_file(self.decoy_registry_file, registry)
            
        except Exception:
            return False
    
    def register_decoy_mapping(self, real_file: str, decoy_file: str) -> bool:
        """
        Register a mapping between a real file and its decoy.
        
        Args:
            real_file (str): Path to the real file
            decoy_file (str): Path to the decoy file
            
        Returns:
            bool: True if mapping successful, False otherwise
        """
        try:
            if not real_file or not decoy_file:
                return False
            
            # Normalize paths
            real_path = self._normalize_path(real_file)
            decoy_path = self._normalize_path(decoy_file)
            
            # Validate that decoy file exists
            if not os.path.exists(decoy_path):
                return False
            
            # Register decoy file if not already registered
            self.register_decoy_file(decoy_path)
            
            # Load existing mappings
            mappings = self._load_json_file(self.decoy_mappings_file)
            
            # Create hash for real file
            real_file_hash = self._create_file_hash(real_path)
            
            # Create mapping
            mappings[real_file_hash] = {
                'real_file': real_path,
                'decoy_file': decoy_path,
                'created_at': datetime.datetime.now().isoformat(),
                'access_attempts': 0
            }
            
            # Save mappings
            return self._save_json_file(self.decoy_mappings_file, mappings)
            
        except Exception:
            return False
    
    def get_decoy_for_file(self, real_file: str) -> Optional[str]:
        """
        Get the decoy file path for a given real file.
        
        Args:
            real_file (str): Path to the real file
            
        Returns:
            Optional[str]: Path to decoy file if mapping exists, None otherwise
        """
        try:
            if not real_file:
                return None
            
            # Normalize path
            real_path = self._normalize_path(real_file)
            
            # Load mappings
            mappings = self._load_json_file(self.decoy_mappings_file)
            
            # Create hash for lookup
            real_file_hash = self._create_file_hash(real_path)
            
            # Find mapping
            if real_file_hash in mappings:
                mapping = mappings[real_file_hash]
                decoy_path = mapping['decoy_file']
                
                # Update access count
                mapping['access_attempts'] += 1
                mapping['last_accessed'] = datetime.datetime.now().isoformat()
                
                # Log access attempt
                self._log_access_attempt(real_path, decoy_path)
                
                # Save updated mappings
                self._save_json_file(self.decoy_mappings_file, mappings)
                
                # Return decoy file if it still exists
                if os.path.exists(decoy_path):
                    return decoy_path
            
            return None
            
        except Exception:
            return None
    
    def _log_access_attempt(self, real_file: str, decoy_file: str) -> None:
        """
        Log an access attempt to a decoy file.
        
        Args:
            real_file (str): Path to the real file
            decoy_file (str): Path to the decoy file accessed
        """
        try:
            # Load existing access log
            access_log = self._load_json_file(self.access_log_file)
            
            # Create log entry
            log_entry = {
                'timestamp': datetime.datetime.now().isoformat(),
                'real_file': real_file,
                'decoy_file': decoy_file,
                'event_type': 'decoy_access'
            }
            
            # Add to log (keep as list of entries)
            if 'entries' not in access_log:
                access_log['entries'] = []
            
            access_log['entries'].append(log_entry)
            
            # Keep only last 1000 entries to prevent file from growing too large
            if len(access_log['entries']) > 1000:
                access_log['entries'] = access_log['entries'][-1000:]
            
            # Save access log
            self._save_json_file(self.access_log_file, access_log)
            
        except Exception:
            pass  # Silently fail for logging
    
    def get_access_log(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get the access log for decoy files.
        
        Args:
            limit (int): Maximum number of entries to return
            
        Returns:
            List[Dict]: List of access log entries
        """
        try:
            access_log = self._load_json_file(self.access_log_file)
            entries = access_log.get('entries', [])
            
            # Sort by timestamp (most recent first)
            entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            # Apply limit if specified
            if limit:
                entries = entries[:limit]
            
            return entries
            
        except Exception:
            return []
    
    def get_decoy_stats(self) -> Dict[str, Any]:
        """
        Get statistics about decoy file system usage.
        
        Returns:
            Dict: Statistics about decoy files and mappings
        """
        try:
            # Load data
            registry = self._load_json_file(self.decoy_registry_file)
            mappings = self._load_json_file(self.decoy_mappings_file)
            access_log = self._load_json_file(self.access_log_file)
            
            # Calculate statistics
            total_decoys = len(registry)
            total_mappings = len(mappings)
            total_access_attempts = sum(mapping.get('access_attempts', 0) 
                                     for mapping in mappings.values())
            total_log_entries = len(access_log.get('entries', []))
            
            # Find most accessed decoy
            most_accessed = None
            max_attempts = 0
            for mapping in mappings.values():
                attempts = mapping.get('access_attempts', 0)
                if attempts > max_attempts:
                    max_attempts = attempts
                    most_accessed = mapping.get('decoy_file')
            
            return {
                'total_decoy_files': total_decoys,
                'total_mappings': total_mappings,
                'total_access_attempts': total_access_attempts,
                'total_log_entries': total_log_entries,
                'most_accessed_decoy': most_accessed,
                'max_access_attempts': max_attempts
            }
            
        except Exception:
            return {
                'total_decoy_files': 0,
                'total_mappings': 0,
                'total_access_attempts': 0,
                'total_log_entries': 0,
                'most_accessed_decoy': None,
                'max_access_attempts': 0
            }
    
    def remove_decoy_mapping(self, real_file: str) -> bool:
        """
        Remove a decoy mapping for a real file.
        
        Args:
            real_file (str): Path to the real file
            
        Returns:
            bool: True if removal successful, False otherwise
        """
        try:
            if not real_file:
                return False
            
            # Normalize path
            real_path = self._normalize_path(real_file)
            
            # Load mappings
            mappings = self._load_json_file(self.decoy_mappings_file)
            
            # Create hash for lookup
            real_file_hash = self._create_file_hash(real_path)
            
            # Remove mapping if it exists
            if real_file_hash in mappings:
                del mappings[real_file_hash]
                return self._save_json_file(self.decoy_mappings_file, mappings)
            
            return True  # No mapping to remove is considered success
            
        except Exception:
            return False


# Convenience functions for global usage
def register_decoy_file(decoy_path: str) -> bool:
    """
    Register a file as a decoy file.
    
    Args:
        decoy_path (str): Path to the decoy file
        
    Returns:
        bool: True if registration successful, False otherwise
    """
    manager = DecoyManager()
    return manager.register_decoy_file(decoy_path)


def register_decoy_mapping(real_file: str, decoy_file: str) -> bool:
    """
    Register a mapping between a real file and its decoy.
    
    Args:
        real_file (str): Path to the real file
        decoy_file (str): Path to the decoy file
        
    Returns:
        bool: True if mapping successful, False otherwise
    """
    manager = DecoyManager()
    return manager.register_decoy_mapping(real_file, decoy_file)


def get_decoy_for_file(real_file: str) -> Optional[str]:
    """
    Get the decoy file path for a given real file.
    
    Args:
        real_file (str): Path to the real file
        
    Returns:
        Optional[str]: Path to decoy file if mapping exists, None otherwise
    """
    manager = DecoyManager()
    return manager.get_decoy_for_file(real_file)


# Simple test functions
if __name__ == "__main__":
    import tempfile
    
    def test_decoy_manager():
        """Test the DecoyManager functionality."""
        print("Testing FileGuard Decoy Manager...")
        
        try:
            # Create temporary directory for testing
            with tempfile.TemporaryDirectory() as temp_dir:
                data_dir = os.path.join(temp_dir, "test_data")
                
                # Create test files
                real_file_path = os.path.join(temp_dir, "real_file.txt")
                decoy_file_path = os.path.join(temp_dir, "decoy_file.txt")
                
                with open(real_file_path, 'w') as f:
                    f.write("This is the real file content")
                
                with open(decoy_file_path, 'w') as f:
                    f.write("This is the decoy file content")
                
                # Initialize manager
                manager = DecoyManager(data_dir)
                print("✓ DecoyManager initialized")
                
                # Test registering decoy file
                success = manager.register_decoy_file(decoy_file_path)
                if success:
                    print("✓ Test PASSED: Decoy file registered")
                else:
                    print("✗ Test FAILED: Decoy file registration failed")
                
                # Test registering decoy mapping
                success = manager.register_decoy_mapping(real_file_path, decoy_file_path)
                if success:
                    print("✓ Test PASSED: Decoy mapping registered")
                else:
                    print("✗ Test FAILED: Decoy mapping registration failed")
                
                # Test getting decoy for file
                decoy_path = manager.get_decoy_for_file(real_file_path)
                if decoy_path == decoy_file_path:
                    print("✓ Test PASSED: Correct decoy file returned")
                else:
                    print(f"✗ Test FAILED: Expected {decoy_file_path}, got {decoy_path}")
                
                # Test getting decoy for non-existent file
                no_decoy = manager.get_decoy_for_file("non_existent_file.txt")
                if no_decoy is None:
                    print("✓ Test PASSED: No decoy returned for non-existent mapping")
                else:
                    print("✗ Test FAILED: Should return None for non-existent mapping")
                
                # Test access logging
                access_log = manager.get_access_log(limit=5)
                if len(access_log) > 0:
                    print("✓ Test PASSED: Access log recorded")
                    print(f"  Last access: {access_log[0]['timestamp']}")
                else:
                    print("✗ Test FAILED: Access log should have entries")
                
                # Test statistics
                stats = manager.get_decoy_stats()
                if stats['total_decoy_files'] > 0 and stats['total_mappings'] > 0:
                    print("✓ Test PASSED: Statistics calculated")
                    print(f"  Total decoys: {stats['total_decoy_files']}")
                    print(f"  Total mappings: {stats['total_mappings']}")
                    print(f"  Access attempts: {stats['total_access_attempts']}")
                else:
                    print("✗ Test FAILED: Statistics should show registered files")
                
                # Test convenience functions
                success = register_decoy_file(decoy_file_path)
                success2 = register_decoy_mapping(real_file_path, decoy_file_path)
                decoy_result = get_decoy_for_file(real_file_path)
                
                if success and success2 and decoy_result:
                    print("✓ Test PASSED: Convenience functions work")
                else:
                    print("✗ Test FAILED: Convenience functions should work")
                
                # Test removing mapping
                success = manager.remove_decoy_mapping(real_file_path)
                if success:
                    print("✓ Test PASSED: Decoy mapping removed")
                else:
                    print("✗ Test FAILED: Decoy mapping removal failed")
                
                print("Decoy manager tests completed")
                
        except Exception as e:
            print(f"✗ Test FAILED with error: {e}")
    
    test_decoy_manager()