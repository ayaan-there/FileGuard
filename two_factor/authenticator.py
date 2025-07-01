"""
FileGuard Two-Factor Authentication Module
Provides TOTP-based two-factor authentication functionality.
"""

import os
import sys
import pyotp
import qrcode
import uuid
from pathlib import Path

# Define directory for storing TOTP secrets
TOTP_SECRETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "totp_secrets")
LEGACY_SECRET_FILE = "msauth_secret.txt"

def ensure_totp_dir_exists():
    """Ensure the TOTP secrets directory exists."""
    os.makedirs(TOTP_SECRETS_DIR, exist_ok=True)
    return TOTP_SECRETS_DIR

def generate_secret():
    """Generate a new base32 secret for TOTP."""
    return pyotp.random_base32()

def get_provisioning_uri(secret, username, issuer="FileGuard"):
    """Return the provisioning URI for Microsoft Authenticator."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def save_qr_code(uri, filename):
    """Generate and save a QR code for the provisioning URI."""
    img = qrcode.make(uri)
    img.save(filename)
    return filename

def verify_code(secret, code):
    """Verify a TOTP code."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def get_secret_filename(file_path=None):
    """Generate a filename for storing the TOTP secret."""
    if file_path:
        # Use file basename without extension, with a secure prefix
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        return f"totp_{base_name}_{uuid.uuid4().hex[:8]}.secret"
    else:
        # If no file path provided, use a generic name with timestamp
        return f"totp_secret_{uuid.uuid4().hex}.secret"

def save_secret_to_file(secret, file_path=None):
    """Save TOTP secret to file in the totp_secrets directory."""
    # Ensure directory exists
    ensure_totp_dir_exists()
    
    # Generate filename for the secret
    secret_filename = get_secret_filename(file_path)
    secret_path = os.path.join(TOTP_SECRETS_DIR, secret_filename)
    
    # Save the secret to the file
    with open(secret_path, "w") as f:
        f.write(secret)
    
    # For backward compatibility, also save to legacy location
    try:
        with open(LEGACY_SECRET_FILE, "w") as f:
            f.write(secret)
    except Exception as e:
        print(f"Warning: Could not save legacy secret file: {e}")
        
    print(f"Secret saved to {secret_path}")
    return secret_path

def load_secret_from_file(file_path=None):
    """
    Load TOTP secret from file.
    
    Args:
        file_path (str, optional): Path to the encrypted file to find associated secret
        
    Returns:
        str: The TOTP secret or None if not found
    """
    # First check if there's a secret file in the totp_secrets directory
    ensure_totp_dir_exists()
    
    # If a specific file path is provided, look for a matching secret
    if file_path:
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        # Try to find secret files that match this base name
        for secret_file in os.listdir(TOTP_SECRETS_DIR):
            if secret_file.startswith(f"totp_{base_name}_") and secret_file.endswith(".secret"):
                secret_path = os.path.join(TOTP_SECRETS_DIR, secret_file)
                with open(secret_path, "r") as f:
                    return f.read().strip()
    
    # If no specific secret found, try the most recent one
    secret_files = [f for f in os.listdir(TOTP_SECRETS_DIR) if f.endswith(".secret")]
    if secret_files:
        # Get the most recently modified secret file
        latest_file = max([os.path.join(TOTP_SECRETS_DIR, f) for f in secret_files], 
                          key=os.path.getmtime)
        with open(latest_file, "r") as f:
            return f.read().strip()
    
    # Fallback to legacy location if nothing found in the totp_secrets directory
    if os.path.exists(LEGACY_SECRET_FILE):
        with open(LEGACY_SECRET_FILE, "r") as f:
            return f.read().strip()
            
    return None

def delete_secret_file(file_path=None):
    """
    Delete the TOTP secret file associated with the encrypted file.
    
    Args:
        file_path (str, optional): Path to the encrypted file to delete associated secret
    
    Returns:
        bool: True if a secret was deleted, False otherwise
    """
    deleted = False
    
    # Try to delete associated secret if file_path provided
    if file_path:
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        for secret_file in os.listdir(TOTP_SECRETS_DIR):
            if secret_file.startswith(f"totp_{base_name}_") and secret_file.endswith(".secret"):
                secret_path = os.path.join(TOTP_SECRETS_DIR, secret_file)
                try:
                    os.remove(secret_path)
                    print(f"Deleted TOTP secret: {secret_path}")
                    deleted = True
                except Exception as e:
                    print(f"Warning: Could not delete TOTP secret {secret_path}: {e}")
    
    # If requested or no specific file deleted, try to delete legacy secret
    if not file_path or not deleted:
        if os.path.exists(LEGACY_SECRET_FILE):
            try:
                os.remove(LEGACY_SECRET_FILE)
                print(f"Deleted legacy TOTP secret: {LEGACY_SECRET_FILE}")
                deleted = True
            except Exception as e:
                print(f"Warning: Could not delete legacy TOTP secret: {e}")
                
    return deleted

def cli():
    print("FileGuard Microsoft Authenticator 2FA CLI")
    print("==========================================")
    print("Options:")
    print("  1. Generate new 2FA secret and QR code")
    print("  2. Verify a 2FA code")
    print("  3. List stored secrets")
    print("  4. Delete all secrets")
    print("  5. Exit")
    while True:
        choice = input("\nSelect an option (1-5): ").strip()
        if choice == "1":
            username = input("Enter your username/email for 2FA: ").strip()
            issuer = input("Enter issuer name (default: FileGuard): ").strip() or "FileGuard"
            secret = generate_secret()
            print(f"\nYour new 2FA secret (keep this safe!): {secret}")
            secret_path = save_secret_to_file(secret)
            uri = get_provisioning_uri(secret, username, issuer)
            print(f"Provisioning URI (for Microsoft Authenticator):\n{uri}")
            qr_path = os.path.join(os.getcwd(), f"{username}_msauth_qr.png")
            save_qr_code(uri, qr_path)
            print(f"QR code saved to: {qr_path}")
            print("Scan this QR code with Microsoft Authenticator to add your account.")
            print(f"Your secret is also saved in {secret_path} for encryption.")
            print("You can now use option 2 to verify codes.")
        elif choice == "2":
            print("To verify, you need your 2FA secret (not the 6-digit code).")
            secret = load_secret_from_file()
            if secret:
                print(f"Loaded secret from TOTP secrets directory")
            else:
                secret = input("Enter your 2FA secret: ").strip()
            code = input("Enter the 6-digit code from Microsoft Authenticator: ").strip()
            if verify_code(secret, code):
                print("✓ Code is valid.")
            else:
                print("✗ Code is invalid.")
        elif choice == "3":
            # List stored secrets
            ensure_totp_dir_exists()
            secret_files = [f for f in os.listdir(TOTP_SECRETS_DIR) if f.endswith(".secret")]
            if secret_files:
                print(f"Found {len(secret_files)} TOTP secrets in {TOTP_SECRETS_DIR}:")
                for idx, secret_file in enumerate(secret_files, 1):
                    file_path = os.path.join(TOTP_SECRETS_DIR, secret_file)
                    modified_time = os.path.getmtime(file_path)
                    print(f"  {idx}. {secret_file} (modified: {modified_time})")
            else:
                print("No TOTP secrets found in the directory.")
                
            if os.path.exists(LEGACY_SECRET_FILE):
                print(f"Legacy secret file exists: {LEGACY_SECRET_FILE}")
        elif choice == "4":
            # Delete all secrets
            confirm = input("Are you sure you want to delete all TOTP secrets? (y/N): ").lower().strip()
            if confirm == 'y':
                count = 0
                ensure_totp_dir_exists()
                for secret_file in os.listdir(TOTP_SECRETS_DIR):
                    if secret_file.endswith(".secret"):
                        try:
                            os.remove(os.path.join(TOTP_SECRETS_DIR, secret_file))
                            count += 1
                        except Exception as e:
                            print(f"Error deleting {secret_file}: {e}")
                
                # Also try to delete legacy file
                if os.path.exists(LEGACY_SECRET_FILE):
                    try:
                        os.remove(LEGACY_SECRET_FILE)
                        count += 1
                        print(f"Deleted legacy secret file: {LEGACY_SECRET_FILE}")
                    except Exception as e:
                        print(f"Error deleting legacy secret: {e}")
                
                print(f"Deleted {count} secret files.")
            else:
                print("Deletion cancelled.")
        elif choice == "5":
            print("Exiting.")
            break
        else:
            print("Invalid option. Please select 1-5.")

if __name__ == "__main__":
    cli()
