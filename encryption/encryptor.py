"""
FileGuard Encryption Module
Provides AES-256-GCM encryption and decryption functionality for files.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from password using PBKDF2.
    
    Args:
        password (str): The password to derive key from
        salt (bytes): Random salt for key derivation
        
    Returns:
        bytes: 32-byte derived key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def generate_key_from_password(password: str) -> bytes:
    """
    Generate a 256-bit key from password using PBKDF2 with a default salt.
    
    Args:
        password (str): The password to derive key from
        
    Returns:
        bytes: 32-byte derived key
        
    Note:
        This function uses a fixed salt and is primarily for compatibility.
        For actual encryption/decryption, use the internal _derive_key function
        with randomly generated salts.
    """
    # Use a fixed salt for consistency (not recommended for actual encryption)
    # This is mainly for compatibility with GUI expectations
    default_salt = b'FileGuard_Salt16'  # 16 bytes
    return _derive_key(password, default_salt)


def encrypt_file(file_path: str, password: str) -> str:
    """
    Encrypt a file using AES-256-GCM encryption.
    
    Args:
        file_path (str): Path to the file to encrypt
        password (str): Password for encryption
        
    Returns:
        str: Path to the encrypted file with .fenc extension
        
    Raises:
        FileNotFoundError: If the input file doesn't exist
        PermissionError: If there are permission issues
        Exception: For other encryption errors
    """
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Generate random salt and nonce
        salt = os.urandom(16)  # 128-bit salt
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        # Derive key from password
        key = _derive_key(password, salt)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Read the file
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # Encrypt the data
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Create encrypted file path
        encrypted_file_path = file_path + '.fenc'
        
        # Write encrypted data (salt + nonce + ciphertext)
        with open(encrypted_file_path, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)
        
        return encrypted_file_path
        
    except FileNotFoundError:
        raise
    except PermissionError as e:
        raise PermissionError(f"Permission denied: {e}")
    except Exception as e:
        raise Exception(f"Encryption failed: {e}")


def decrypt_file(file_path: str, password: str) -> str:
    """
    Decrypt a file encrypted with AES-256-GCM.
    
    Args:
        file_path (str): Path to the encrypted file (.fenc extension)
        password (str): Password for decryption
        
    Returns:
        str: Path to the decrypted file (original filename without .fenc)
        
    Raises:
        FileNotFoundError: If the encrypted file doesn't exist
        ValueError: If the file format is invalid or password is wrong
        PermissionError: If there are permission issues
        Exception: For other decryption errors
    """
    try:
        # Check if encrypted file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Encrypted file not found: {file_path}")
        
        # Read the encrypted file
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check minimum file size (salt + nonce + at least some ciphertext)
        if len(data) < 16 + 12 + 16:  # salt + nonce + min GCM tag
            raise ValueError("Invalid encrypted file format")
        
        # Extract salt, nonce, and ciphertext
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]
        
        # Derive key from password
        key = _derive_key(password, salt)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Decrypt the data
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("Decryption failed - invalid password or corrupted file")
        
        # Create output directory path (same as input file)
        output_dir = os.path.dirname(file_path)
        
        # Get the base name without extension
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        
        # Further clean up the base name if needed (remove _encrypted suffix if present)
        if base_name.endswith('_encrypted'):
            base_name = base_name[:-10]
            
        # Only one output file with original name
        decrypted_file_path = os.path.join(output_dir, f"{base_name}")
        
        # Write decrypted data
        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)

        return decrypted_file_path
        
    except FileNotFoundError:
        raise
    except ValueError:
        raise
    except PermissionError as e:
        raise PermissionError(f"Permission denied: {e}")
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")


# Simple test functions
if __name__ == "__main__":
    import tempfile
    
    def test_encryption_decryption():
        """Test the encryption and decryption functions."""
        print("Testing FileGuard encryption/decryption...")
        
        try:
            # Create a temporary test file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                test_content = "This is a test file for FileGuard encryption!"
                temp_file.write(test_content)
                temp_file_path = temp_file.name
            
            print(f"Created test file: {temp_file_path}")
            
            # Test encryption
            password = "test_password_123"
            encrypted_path = encrypt_file(temp_file_path, password)
            print(f"File encrypted successfully: {encrypted_path}")
            
            # Test decryption
            decrypted_path = decrypt_file(encrypted_path, password)
            print(f"File decrypted successfully: {decrypted_path}")
            
            # Verify content
            with open(decrypted_path, 'r') as f:
                decrypted_content = f.read()
            
            if decrypted_content == test_content:
                print("✓ Test PASSED: Content matches original")
            else:
                print("✗ Test FAILED: Content doesn't match")
            
            # Test wrong password
            try:
                decrypt_file(encrypted_path, "wrong_password")
                print("✗ Test FAILED: Should have failed with wrong password")
            except ValueError:
                print("✓ Test PASSED: Correctly rejected wrong password")
            
            # Clean up
            os.unlink(temp_file_path)
            os.unlink(encrypted_path)
            os.unlink(decrypted_path)
            print("Test files cleaned up")
            
        except Exception as e:
            print(f"✗ Test FAILED with error: {e}")
    
    test_encryption_decryption()