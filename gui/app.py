"""
FileGuard GUI Application
Main GUI application using Tkinter for FileGuard file security.
"""

import sys
import os
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import scrolledtext

# Try to import PIL for QR code display
try:
    from PIL import Image, ImageTk
    pil_available = True
except ImportError:
    pil_available = False

from typing import Union, Any

# Add project root to path for module discovery
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

# Define fallback logger class first
class FallbackSecureLogger:
    """Fallback logger when secure_logger is not available."""
    def __init__(self, *args, **kwargs):
        pass
    
    def log_event(self, event_type: str, message: str, metadata: Any = None) -> bool:
        try:
            print(f"[{event_type}] {message}")
            return True
        except Exception as e:
            print(f"Error in fallback logger: {e}")
            return False
    
    def read_logs(self, *args, **kwargs) -> list:
        return []
    
    def verify_log_integrity(self, *args, **kwargs) -> tuple:
        return True, []

# Try to import the real SecureLogger
try:
    from fileguardlogging.secure_logger import SecureLogger as ImportedSecureLogger
    SecureLogger = ImportedSecureLogger
    logging_available = True
    print("✓ Secure logging module loaded successfully")
except ImportError as e:
    print(f"⚠ Warning: Secure logging module not available: {e}")
    SecureLogger = FallbackSecureLogger
    logging_available = False
except Exception as e:
    print(f"✗ Error loading secure logging module: {e}")
    SecureLogger = FallbackSecureLogger
    logging_available = False

# Import FileGuard modules with comprehensive error handling
try:
    from compression.compressor import compress_file, decompress_file, get_compression_info
    compression_available = True
    print("✓ Compression module loaded successfully")
except ImportError as e:
    print(f"⚠ Warning: Compression module not available: {e}")
    compression_available = False
    # Create dummy functions to match real module signatures
    def compress_file(file_path: str) -> tuple[str, float]:
        raise NotImplementedError("Compression module not available")
    def decompress_file(file_path: str) -> str:
        raise NotImplementedError("Compression module not available")
    def get_compression_info(original_file_path: str, compressed_file_path: str) -> dict:
        return {}
except Exception as e:
    print(f"✗ Error loading compression module: {e}")
    compression_available = False
    # Fallback functions with correct signatures
    def compress_file(file_path: str) -> tuple[str, float]:
        # Return dummy output path and compression ratio
        import os
        base_name = os.path.splitext(file_path)[0]
        return (f"{base_name}_compressed.fgc", 0.5)
    def decompress_file(file_path: str) -> str:
        # Return dummy decompressed file path
        import os
        base_name = os.path.splitext(file_path)[0]
        return f"{base_name}_decompressed"
    def get_compression_info(original_file_path: str, compressed_file_path: str) -> dict:
        return {"is_compressed": False, "original_extension": ".txt"}

try:
    from encryption.encryptor import encrypt_file, decrypt_file
    # Try to import generate_key_from_password if available
    try:
        from encryption.encryptor import generate_key_from_password
    except ImportError:
        # Fallback if function doesn't exist
        def generate_key_from_password(password: str) -> bytes:
            import hashlib
            return hashlib.sha256(password.encode()).digest()
    
    encryption_available = True
    print("✓ Encryption module loaded successfully")
except ImportError as e:
    print(f"⚠ Warning: Encryption module not available: {e}")
    encryption_available = False
    # Create dummy functions with correct signatures
    def encrypt_file(file_path: str, password: str) -> str:
        raise NotImplementedError("Encryption module not available")
    def decrypt_file(file_path: str, password: str) -> str:
        raise NotImplementedError("Encryption module not available")
    def generate_key_from_password(password: str) -> bytes:
        return b"dummy_key"
except Exception as e:
    print(f"✗ Error loading encryption module: {e}")
    encryption_available = False
    # Fallback functions with correct signatures
    def encrypt_file(file_path: str, password: str) -> str:
        # Return dummy encrypted file path
        import os
        base_name = os.path.splitext(file_path)[0]
        return f"{base_name}_encrypted.fge"
    def decrypt_file(file_path: str, password: str) -> str:
        # Return dummy decrypted file path
        import os
        base_name = os.path.splitext(file_path)[0]
        if base_name.endswith('_encrypted'):
            base_name = base_name[:-10]
        return f"{base_name}_decrypted"
    def generate_key_from_password(password: str) -> bytes:
        import hashlib
        return hashlib.sha256(password.encode()).digest()

try:
    from decoy.decoy_manager import (
        register_decoy_file, register_decoy_mapping, get_decoy_for_file
    )
    decoy_available = True
    print("✓ Decoy system module loaded successfully")
except ImportError as e:
    print(f"⚠ Warning: Decoy system module not available: {e}")
    decoy_available = False
    # Create dummy functions to prevent crashes   
    def register_decoy_file(decoy_path: str) -> bool: 
        return False
    
    def register_decoy_mapping(real_file: str, decoy_file: str) -> bool:
        return False
    
    def get_decoy_for_file(real_file: str) -> str | None:
        """Can return None if no decoy is found - matches real module signature."""
        return None  # No decoy available in fallback
except Exception as e:
    print(f"✗ Error loading decoy system module: {e}")
    decoy_available = False

try:
    from selfdestruct.secure_deletion import (
        secure_delete_file, configure_attempt_limit, track_failed_attempt
    )
    selfdestruct_available = True
    print("✓ Self-destruct module loaded successfully")
except ImportError as e:
    print(f"⚠ Warning: Self-destruct module not available: {e}")
    selfdestruct_available = False
    # Create dummy functions to prevent crashes    
    def secure_delete_file(file_path: str, passes: int = 3) -> bool:
        return False
    
    def configure_attempt_limit(file_path: str, max_attempts: int) -> bool:
        return False
    
    def track_failed_attempt(file_path: str) -> int | None:
        """Can return None if tracking fails - matches real module signature."""
        return 0  # No failed attempts tracked in fallback
except Exception as e:
    print(f"✗ Error loading self-destruct module: {e}")
    selfdestruct_available = False

# Import 2FA functions
try:
    from two_factor.authenticator import (
        generate_secret, get_provisioning_uri, save_qr_code,
        verify_code, save_secret_to_file, load_secret_from_file
    )
    msauth_2fa_available = True
except ImportError:
    msauth_2fa_available = False

class FileGuardApp:
    def __init__(self, root: tk.Tk):
        """
        Initialize the FileGuard application GUI.
        Args:
            root (tk.Tk): The root Tkinter window
        """
        self.root = root
        self.selected_file_path = tk.StringVar()
        self.compress_var = tk.BooleanVar()
        self.encrypt_var = tk.BooleanVar()
        self.password_var = tk.StringVar()

        # Decrypt tab variables
        self.decrypt_password_var = tk.StringVar()

        # Decoy system variables
        self.decoy_var = tk.BooleanVar()
        self.decoy_file_path = tk.StringVar()
        self.decoy_password_var = tk.StringVar()
        self.secure_delete_var = tk.BooleanVar(value=True)

        # 2FA variables
        self.ms_2fa_var = tk.BooleanVar()
        self.ms_2fa_secret = None
        self.ms_2fa_status = tk.StringVar()
        self._verified_2fa_file_path = None  # Store file path for cleanup

        # Initialize secure logger
        self.logger = SecureLogger()

        # Password attempt tracking
        self.failed_decrypt_attempts = 0
        self.max_decrypt_attempts = 3

        self._setup_window()
        self._setup_styles()
        self._create_widgets()
    
    def _setup_window(self):
        """
        Configure the main window properties.
        """
        # Window title and icon
        self.root.title("FileGuard - Secure File Manager")
        
        # Window size and position
        self.root.geometry("850x650")
        self.root.minsize(650, 500)
        
        # Center the window on screen
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        # Configure grid weight for responsiveness
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
    
    def _setup_styles(self):
        """
        Configure ttk styles for modern appearance.
        """
        self.style = ttk.Style()
        
        # Use a modern theme if available
        available_themes = self.style.theme_names()
        if 'clam' in available_themes:
            self.style.theme_use('clam')
        elif 'vista' in available_themes:
            self.style.theme_use('vista')
        elif 'xpnative' in available_themes:
            self.style.theme_use('xpnative')
          # Define color scheme
        self.colors = {
            'primary': '#2c3e50',      # Dark blue-gray
            'secondary': '#34495e',    # Medium blue-gray
            'accent': '#3498db',       # Blue
            'success': '#27ae60',      # Green
            'warning': '#f39c12',      # Orange
            'danger': '#e74c3c',       # Red
            'light': '#ecf0f1',        # Light gray
            'dark': '#2c3e50',         # Dark gray
            'white': '#ffffff',        # White
            'text': '#2c3e50'          # Text color
        }
        
        # Configure custom styles
        self.style.configure('Title.TLabel',
                           font=('Segoe UI', 18, 'bold'),
                           foreground=self.colors['primary'],
                           background=self.colors['white'])
        
        self.style.configure('Subtitle.TLabel',
                           font=('Segoe UI', 12),
                           foreground=self.colors['secondary'],
                           background=self.colors['white'])
        
        self.style.configure('Header.TFrame',
                           background=self.colors['white'],
                           relief='flat')
        
        self.style.configure('Main.TFrame',
                           background=self.colors['light'],
                           relief='flat')
        
        self.style.configure('Custom.TSeparator',
                           background=self.colors['secondary'])
    
    def _browse_file(self):
        """
        Open file dialog to select a file.
        """
        try:
            file_path = filedialog.askopenfilename(
                title="Select File",
                filetypes=[
                    ("All Files", "*.*"),
                    ("Text Files", "*.txt"),
                    ("Document Files", "*.pdf *.doc *.docx"),
                    ("Image Files", "*.jpg *.jpeg *.png *.gif *.bmp"),
                    ("Archive Files", "*.zip *.rar *.7z")                ]
            )
            if file_path:
                # Verify file exists and is accessible
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    self.selected_file_path.set(file_path)
                    if hasattr(self, 'log_message'):
                        self.log_message(f"File selected: {os.path.basename(file_path)}", "INFO")
                else:
                    messagebox.showerror("File Error", "Selected file does not exist or is not accessible.")
        except Exception as e:
            error_msg = f"Error selecting file: {str(e)}"
            print(error_msg)
            messagebox.showerror("File Selection Error", error_msg)
            if hasattr(self, 'log_message'):
                self.log_message(error_msg, "ERROR")
    
   
    def _create_decoy_panel(self, parent_frame):
        """
        Create decoy system controls panel.
        
        Args:
            parent_frame: The parent frame to add decoy controls to
        """
        # Decoy file selection frame (initially hidden)
        self.decoy_frame = ttk.LabelFrame(parent_frame, text="Decoy File Configuration", padding="10")
        
        # Decoy file selection
        decoy_file_label = ttk.Label(
            self.decoy_frame,
            text="Decoy File:",
            style='Subtitle.TLabel'
        )
        decoy_file_label.grid(row=0, column=0, padx=(0, 10), sticky="w", pady=(0, 5))
        
        self.decoy_file_entry = ttk.Entry(
            self.decoy_frame,
            textvariable=self.decoy_file_path,
            font=('Segoe UI', 10),
            state='readonly'
        )
        self.decoy_file_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10), pady=(0, 5))
        
        self.decoy_browse_button = ttk.Button(
            self.decoy_frame,
            text="Browse...",
            command=self._browse_decoy,
            width=10
        )
        self.decoy_browse_button.grid(row=0, column=2, sticky="w", pady=(0, 5))
        
        # Decoy password
        decoy_password_label = ttk.Label(
            self.decoy_frame,
            text="Decoy Password:",
            style='Subtitle.TLabel'
        )
        decoy_password_label.grid(row=1, column=0, padx=(0, 10), sticky="w", pady=(10, 5))
        
        self.decoy_password_entry = ttk.Entry(
            self.decoy_frame,
            textvariable=self.decoy_password_var,
            show="*",
            font=('Segoe UI', 10)
        )
        self.decoy_password_entry.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(10, 5))
        
        # Register decoy button
        self.register_decoy_button = ttk.Button(
            self.decoy_frame,
            text="Register Decoy",
            command=self._register_decoy,
            width=12
        )
        self.register_decoy_button.grid(row=1, column=2, sticky="w", pady=(10, 5))
        
        # Enhanced security option
        self.secure_delete_var = tk.BooleanVar(value=True)
        self.secure_delete_check = ttk.Checkbutton(
            self.decoy_frame,
            text="Enhanced Security (securely delete original file after failed attempts)",
            variable=self.secure_delete_var
        )
        self.secure_delete_check.grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 5))
        
        # Make this option only visible if the secure deletion module is available
        if not selfdestruct_available:
            self.secure_delete_check.grid_remove()
        
        # Info label
        decoy_info_label = ttk.Label(
            self.decoy_frame,
            text="The decoy file will be displayed when the wrong password is entered.",
            font=('Segoe UI', 9),
            foreground='#7f8c8d'
        )
        decoy_info_label.grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 0))
        
        # Configure grid weights
        self.decoy_frame.columnconfigure(1, weight=1)
    
    def _toggle_decoy(self):
        """
        Toggle visibility of decoy system controls based on checkbox state.
        """
        if self.decoy_var.get():
            # Show decoy panel
            self.decoy_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(10, 15))
            self.log_message("Decoy system enabled", "INFO")
        else:
            # Hide decoy panel
            self.decoy_frame.grid_remove()
            self.log_message("Decoy system disabled", "INFO")
    
    def _browse_decoy(self):
        """
        Open file dialog to select a decoy file.
        """
        try:
            file_path = filedialog.askopenfilename(
                title="Select Decoy File",
                filetypes=[
                    ("All Files", "*.*"),
                    ("Text Files", "*.txt"),
                    ("Document Files", "*.pdf *.doc *.docx"),
                    ("Image Files", "*.jpg *.jpeg *.png *.gif *.bmp"),
                    ("Video Files", "*.mp4 *.avi *.mkv *.mov")
                ]
            )
            if file_path:
                self.decoy_file_path.set(file_path)
                self.log_message(f"Decoy file selected: {os.path.basename(file_path)}", "INFO")
        except Exception as e:
            self.log_message(f"Error selecting decoy file: {str(e)}", "ERROR")
    
    def _register_decoy(self):
        """
        Register the decoy file mapping for the selected files.
        """
        try:
            # Validate inputs
            real_file = self.selected_file_path.get().strip()
            decoy_file = self.decoy_file_path.get().strip()
            decoy_password = self.decoy_password_var.get().strip()
            
            if not real_file:
                messagebox.showerror("Error", "Please select the real file first.")
                return
            
            if not decoy_file:
                messagebox.showerror("Error", "Please select a decoy file.")
                return
            
            if not decoy_password:
                messagebox.showerror("Error", "Please enter a decoy password.")
                return
            
            if not os.path.exists(real_file):
                messagebox.showerror("Error", "Real file does not exist.")
                return
            
            if not os.path.exists(decoy_file):
                messagebox.showerror("Error", "Decoy file does not exist.")
                return
            
            # Check if decoy system is available
            if not decoy_available:
                messagebox.showerror("Error", "Decoy system module not available.")
                return
            
            # Register the decoy file
            success = register_decoy_file(decoy_file)
            if not success:
                messagebox.showerror("Error", "Failed to register decoy file.")
                return
              # Create decoy mapping
            success = register_decoy_mapping(real_file, decoy_file)
            if not success:
                messagebox.showerror("Error", "Failed to create decoy mapping.")
                return
            
            # Configure secure deletion for the file
            if selfdestruct_available:
                try:
                    # Configure for secure deletion after 3 failed attempts
                    secure_delete_configured = configure_attempt_limit(real_file, self.max_decrypt_attempts)
                    if secure_delete_configured:
                        self.log_message(f"Secure deletion configured for: {os.path.basename(real_file)}", "SECURITY")
                except Exception as e:
                    self.log_message(f"Failed to configure secure deletion: {str(e)}", "WARNING")
            
            # Log the registration
            self.log_message(f"Decoy mapping registered: {os.path.basename(real_file)} -> {os.path.basename(decoy_file)}", "SUCCESS")
            
            # Show success message
            messagebox.showinfo(
                "Decoy Registered",
                f"Decoy file mapping has been registered successfully!\n\n"
                f"Real file: {os.path.basename(real_file)}\n"
                f"Decoy file: {os.path.basename(decoy_file)}\n\n"
                f"When the wrong password is entered, the decoy file will be displayed instead."            )
            
        except Exception as e:
            error_msg = f"Failed to register decoy: {str(e)}"
            self.log_message(error_msg, "ERROR")
            messagebox.showerror("Decoy Registration Error", error_msg)
    
    
    def _create_encrypt_tab(self):
        """
        Create encryption tab contents with controls.
        """
        # Main container for encryption controls
        encrypt_container = ttk.Frame(self.encrypt_frame, style='Main.TFrame', padding="20")
        encrypt_container.grid(row=0, column=0, sticky="nsew")
        encrypt_container.columnconfigure(1, weight=1)
        
        # Options section
        options_label = ttk.Label(
            encrypt_container,
            text="Security Options:",
            style='Subtitle.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        options_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))
        
        # Compression checkbox
        self.compress_check = ttk.Checkbutton(
            encrypt_container,
            text="Compress file before encryption",
            variable=self.compress_var
        )
        self.compress_check.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 5))

        # Encryption checkbox
        self.encrypt_check = ttk.Checkbutton(
            encrypt_container,
            text="Encrypt file with AES-256",
            variable=self.encrypt_var
        )
        self.encrypt_check.grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 5))


        # 2FA Option (Microsoft Authenticator) - now in encrypt tab
        self.ms_2fa_check = ttk.Checkbutton(
            encrypt_container,
            text="Enable 2FA (Microsoft Authenticator)",
            variable=self.ms_2fa_var,
            command=self._toggle_ms_2fa
        )
        self.ms_2fa_check.grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 5))

        # 2FA Controls (initially hidden, will appear below the 2FA checkbox)
        self.ms_2fa_frame = ttk.Frame(encrypt_container)
        self.ms_2fa_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 5))
        self.ms_2fa_frame.grid_remove()

        self.ms_2fa_setup_btn = ttk.Button(
            self.ms_2fa_frame, text="Setup 2FA", command=self._setup_ms_2fa
        )
        self.ms_2fa_setup_btn.grid(row=0, column=0, padx=(0, 10))

        self.ms_2fa_verify_label = ttk.Label(
            self.ms_2fa_frame, text="Enter 6-digit code:"
        )
        self.ms_2fa_verify_label.grid(row=0, column=1, padx=(0, 5))
        self.ms_2fa_code_var = tk.StringVar()
        self.ms_2fa_code_entry = ttk.Entry(
            self.ms_2fa_frame, textvariable=self.ms_2fa_code_var, width=8
        )
        self.ms_2fa_code_entry.grid(row=0, column=2, padx=(0, 5))

        self.ms_2fa_verify_btn = ttk.Button(
            self.ms_2fa_frame, text="Verify", command=self._verify_ms_2fa_code
        )
        self.ms_2fa_verify_btn.grid(row=0, column=3, padx=(0, 10))

        # Decoy system checkbox (row will shift responsively below 2FA controls)
        self.decoy_check = ttk.Checkbutton(
            encrypt_container,
            text="Enable Decoy File Protection",
            variable=self.decoy_var,
            command=self._toggle_decoy
        )
        self.decoy_check.grid(row=5, column=0, columnspan=2, sticky="w", pady=(0, 15))

        # Create decoy panel (initially hidden)
        self._create_decoy_panel(encrypt_container)

        # Password section
        password_label = ttk.Label(
            encrypt_container,
            text="Password:",
            style='Subtitle.TLabel'
        )
        password_label.grid(row=6, column=0, padx=(0, 10), sticky="w", pady=(0, 5))

        self.password_entry = ttk.Entry(
            encrypt_container,
            textvariable=self.password_var,
            show="*",
            font=('Segoe UI', 10)
        )
        self.password_entry.grid(row=6, column=1, sticky="ew", pady=(0, 5))

        # Action button
        self.start_button = ttk.Button(
            encrypt_container,
            text="Start Process",
            command=self._process_file
        )
        self.start_button.grid(row=7, column=0, columnspan=2, pady=(20, 0))
    def _verify_ms_2fa_code(self):
        """
        Verify the 2FA code entered by the user using the secret.
        """
        try:
            code = self.ms_2fa_code_var.get().strip()
            if not code:
                self.ms_2fa_status.set("Please enter the 6-digit code.")
                return
            # Use the secret from memory if available, else try to load from file
            file_path = self.selected_file_path.get().strip()
            secret = self.ms_2fa_secret
            if not secret:
                try:
                    from two_factor.authenticator import load_secret_from_file
                    # Pass the file path to find the appropriate secret
                    secret = load_secret_from_file(file_path)
                except Exception:
                    secret = None
            if not secret:
                self.ms_2fa_status.set("2FA secret not found. Please set up 2FA.")
                return
            from two_factor.authenticator import verify_code
            if verify_code(secret, code):
                self.ms_2fa_status.set("✓ Code valid.")
                self.log_message("2FA code verified successfully.", "SUCCESS")
            else:
                self.ms_2fa_status.set("✗ Invalid code.")
                self.log_message("2FA code verification failed.", "ERROR")
        except Exception as e:
            self.ms_2fa_status.set(f"2FA error: {e}")
            self.log_message(f"2FA verification error: {e}", "ERROR")

        self.ms_2fa_status_label = ttk.Label(
            self.ms_2fa_frame, textvariable=self.ms_2fa_status, foreground="blue"
        )
        self.ms_2fa_status_label.grid(row=0, column=4, padx=(0, 10))

    def _toggle_ms_2fa(self):
        """
        Toggle visibility of Microsoft Authenticator 2FA controls.
        """
        if self.ms_2fa_var.get():
            # Show 2FA controls below the 2FA checkbox
            self.ms_2fa_frame.grid()
            # Move decoy checkbox below 2FA controls
            self.decoy_check.grid_configure(row=5)
        else:
            # Hide 2FA controls
            self.ms_2fa_frame.grid_remove()
            self.ms_2fa_status.set("")
            self.ms_2fa_code_var.set("")
            self.ms_2fa_secret = None

    def _setup_ms_2fa(self):
        """
        Setup Microsoft Authenticator 2FA for the user.
        """
        if not msauth_2fa_available:
            messagebox.showerror("2FA Error", "Microsoft Authenticator 2FA module not available.")
            return
        file_path = self.selected_file_path.get()
        if not file_path:
            messagebox.showerror("2FA Error", "Please select a file first.")
            return
        username = os.path.basename(file_path)
        secret = generate_secret()
        # Save secret to file in totp_secrets directory, passing the file path for better identification
        save_secret_to_file(secret, file_path)
        self.ms_2fa_secret = secret
        uri = get_provisioning_uri(secret, username)
        qr_path = os.path.join(os.getcwd(), f"{username}_msauth_qr.png")
        save_qr_code(uri, qr_path)
        # Show QR code popup
        self._show_qr_popup(qr_path, secret, uri)
        self.ms_2fa_status.set("2FA setup complete.")

    def _show_qr_popup(self, qr_path, secret, uri):
        """
        Show a popup window with the QR code image for 2FA setup.
        """
        try:
            popup = tk.Toplevel(self.root)
            popup.title("Scan QR Code for Microsoft Authenticator")
            popup.geometry("400x500")
            popup.resizable(False, False)
            # Center the popup
            popup.transient(self.root)
            popup.grab_set()
            x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 200
            y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 250
            popup.geometry(f"400x500+{x}+{y}")

            frame = ttk.Frame(popup, padding="20")
            frame.pack(fill="both", expand=True)

            label = ttk.Label(frame, text="Scan this QR code with Microsoft Authenticator", font=('Segoe UI', 12, 'bold'))
            label.pack(pady=(0, 10))

            # Show QR code image
            if pil_available and os.path.exists(qr_path):
                from PIL import Image, ImageTk
                img = Image.open(qr_path)
                img = img.resize((250, 250))
                photo = ImageTk.PhotoImage(img)
                qr_label = ttk.Label(frame, image=photo)
                setattr(qr_label, 'image', photo)  # Keep reference to avoid garbage collection
                qr_label.pack(pady=(0, 10))
            else:
                ttk.Label(frame, text=f"QR code image not found:\n{qr_path}", foreground="red").pack(pady=(0, 10))

            # Show secret and URI for manual entry
            ttk.Label(frame, text=f"Secret: {secret}", font=('Segoe UI', 10)).pack(pady=(5, 0))
            ttk.Label(frame, text="If you can't scan, enter this secret manually in the app.", font=('Segoe UI', 9)).pack(pady=(0, 10))
            uri_box = tk.Text(frame, height=2, width=45, wrap="word")
            uri_box.insert("1.0", uri)
            uri_box.config(state="disabled")
            uri_box.pack(pady=(0, 10))

            # Function to handle popup closing and delete QR file
            def on_close():
                try:
                    if os.path.exists(qr_path):
                        os.remove(qr_path)
                        print(f"QR code file deleted: {qr_path}")
                except Exception as del_err:
                    print(f"Could not delete QR code file: {del_err}")
                finally:
                    popup.destroy()

            close_btn = ttk.Button(frame, text="Close", command=on_close)
            close_btn.pack(pady=(10, 0))
            
            # Also delete QR when popup is closed by X button
            popup.protocol("WM_DELETE_WINDOW", on_close)
        except Exception as e:
            messagebox.showerror("QR Code Error", f"Could not display QR code: {e}")

    def _create_decrypt_tab(self):
        """
        Create decryption tab contents with controls.
        """
        # Main container for decryption controls
        decrypt_container = ttk.Frame(self.decrypt_frame, style='Main.TFrame', padding="20")
        decrypt_container.grid(row=0, column=0, sticky="nsew")
        decrypt_container.columnconfigure(1, weight=1)
        
        # Instructions section
        instructions_label = ttk.Label(
            decrypt_container,
            text="Decryption & Decompression:",
            style='Subtitle.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        instructions_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))
        
        # Info text
        info_label = ttk.Label(
            decrypt_container,
            text="Enter the password used for encryption to decrypt and decompress your files.",
            style='Subtitle.TLabel',
            justify='left'
        )
        info_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 20))
        
        # Password section
        decrypt_password_label = ttk.Label(
            decrypt_container,
            text="Password:",
            style='Subtitle.TLabel'
        )
        decrypt_password_label.grid(row=2, column=0, padx=(0, 10), sticky="w", pady=(0, 5))
        
        self.decrypt_password_entry = ttk.Entry(
            decrypt_container,
            textvariable=self.decrypt_password_var,
            show="*",
            font=('Segoe UI', 10)
        )
        self.decrypt_password_entry.grid(row=2, column=1, sticky="ew", pady=(0, 5))

        # 2FA code entry for decryption (initially hidden)
        self.decrypt_2fa_frame = ttk.Frame(decrypt_container)
        self.decrypt_2fa_code_var = tk.StringVar()
        self.decrypt_2fa_status = tk.StringVar()
        self.decrypt_2fa_label = ttk.Label(self.decrypt_2fa_frame, text="Enter 2FA code:")
        self.decrypt_2fa_label.grid(row=0, column=0, padx=(0, 5))
        self.decrypt_2fa_code_entry = ttk.Entry(self.decrypt_2fa_frame, textvariable=self.decrypt_2fa_code_var, width=8)
        self.decrypt_2fa_code_entry.grid(row=0, column=1, padx=(0, 5))
        self.decrypt_2fa_verify_btn = ttk.Button(self.decrypt_2fa_frame, text="Verify", command=self._verify_decrypt_2fa_code)
        self.decrypt_2fa_verify_btn.grid(row=0, column=2, padx=(0, 10))
        self.decrypt_2fa_status_label = ttk.Label(self.decrypt_2fa_frame, textvariable=self.decrypt_2fa_status, foreground="blue")
        self.decrypt_2fa_status_label.grid(row=0, column=3, padx=(0, 10))
        self.decrypt_2fa_frame.grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 5))
        self.decrypt_2fa_frame.grid_remove()
        
        # Action button
        self.decrypt_button = ttk.Button(
            decrypt_container,
            text="Decrypt File",
            command=self._decrypt_file
        )
        self.decrypt_button.grid(row=4, column=0, columnspan=2, pady=(20, 0))
        
        # Status/result area
        self.decrypt_status_label = ttk.Label(
            decrypt_container,
            text="",
            style='Subtitle.TLabel',
            justify='center'
        )
        self.decrypt_status_label.grid(row=5, column=0, columnspan=2, pady=(20, 0))

    def _verify_decrypt_2fa_code(self):
        """
        Verify the 2FA code entered by the user for decryption.
        """
        try:
            # Get the file path for context-specific secret loading
            file_path = self.selected_file_path.get().strip()
            if not file_path:
                self.decrypt_2fa_status.set("File path not available.")
                return False
                
            code = self.decrypt_2fa_code_var.get().strip()
            if not code:
                self.decrypt_2fa_status.set("Please enter the 6-digit code.")
                return False
                
            # Use the secret from file (for decryption, always load from file)
            try:
                from two_factor.authenticator import load_secret_from_file, verify_code
                # Pass the file path to find the appropriate secret
                secret = load_secret_from_file(file_path)
            except Exception as ex:
                self.logger.log_event("2FA_ERROR", f"Error loading secret: {ex}")
                secret = None
                
            if not secret:
                self.decrypt_2fa_status.set("2FA secret not found. Please set up 2FA.")
                return False
                
            if verify_code(secret, code):
                self.decrypt_2fa_status.set("✓ Code valid.")
                self.log_message("2FA code verified for decryption.", "SUCCESS")
                # Store the verified secret for later cleanup
                self._verified_2fa_secret = secret
                self._verified_2fa_file_path = file_path
                return True
            else:
                self.decrypt_2fa_status.set("✗ Invalid code.")
                self.log_message("2FA code verification failed for decryption.", "ERROR")
                return False
        except Exception as e:
            self.decrypt_2fa_status.set(f"2FA error: {e}")
            self.log_message(f"2FA verification error (decryption): {e}", "ERROR")
            return False

    def _create_file_selection(self):
        """
        Create file selection panel with label, entry, and browse button.
        """
        # File selection frame
        self.file_frame = ttk.Frame(self.content_frame, style='Main.TFrame')
        self.file_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        self.file_frame.columnconfigure(1, weight=1)
        
        # File selection label
        self.file_label = ttk.Label(
            self.file_frame,
            text="Select File:",
            style='Subtitle.TLabel'
        )
        self.file_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
        
        # File path entry
        self.file_entry = ttk.Entry(
            self.file_frame,
            textvariable=self.selected_file_path,
            font=('Segoe UI', 10),
            state='readonly'
        )
        self.file_entry.grid(row=0, column=1, padx=(0, 10), sticky="ew")
        
        # Browse button
        self.browse_button = ttk.Button(
            self.file_frame,
            text="Browse...",
            command=self._browse_file
        )
        self.browse_button.grid(row=0, column=2, sticky="w")

    def _create_notebook_tabs(self):
        """
        Create notebook with tabs for different functionality.
        """
        # Create notebook widget
        self.notebook = ttk.Notebook(self.content_frame)
        self.notebook.grid(row=1, column=0, sticky="nsew", pady=(20, 0))
          # Create frames for each tab
        self.encrypt_frame = ttk.Frame(self.notebook, style='Main.TFrame')
        self.decrypt_frame = ttk.Frame(self.notebook, style='Main.TFrame')
        self.logs_frame = ttk.Frame(self.notebook, style='Main.TFrame')
        
        # Configure grid weights for responsive design
        self.encrypt_frame.columnconfigure(0, weight=1)
        self.encrypt_frame.rowconfigure(0, weight=1)
        self.decrypt_frame.columnconfigure(0, weight=1)
        self.decrypt_frame.rowconfigure(0, weight=1)
        self.logs_frame.columnconfigure(0, weight=1)
        self.logs_frame.rowconfigure(0, weight=1)          # Add tabs to notebook
        self.notebook.add(self.encrypt_frame, text="Encrypt & Compress")
        self.notebook.add(self.decrypt_frame, text="Decrypt & Decompress")
        self.notebook.add(self.logs_frame, text="Security Logs")
          # Create encryption tab contents
        self._create_encrypt_tab()
        
        # Create decryption tab contents
        self._create_decrypt_tab()
          # Create logs panel
        self._create_logs_panel()
    
    def _create_widgets(self):
        """
        Create and arrange the main GUI widgets.
        """
        try:
            # Main container frame
            self.main_frame = ttk.Frame(self.root, style='Main.TFrame', padding="20")
            self.main_frame.grid(row=0, column=0, sticky="nsew")
            self.main_frame.columnconfigure(0, weight=1)
            self.main_frame.rowconfigure(1, weight=1)  # Content area will expand
            
            # Header frame
            self.header_frame = ttk.Frame(self.main_frame, style='Header.TFrame', padding="0 0 0 10")
            self.header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
            self.header_frame.columnconfigure(0, weight=1)
            
            # Application title
            self.title_label = ttk.Label(
                self.header_frame,
                text="FileGuard Secure File Manager",
                style='Title.TLabel'
            )
            self.title_label.grid(row=0, column=0, sticky="w")
            
            # Subtitle
            self.subtitle_label = ttk.Label(
                self.header_frame,
                text="Advanced file encryption, compression, and security management",
                style='Subtitle.TLabel'
            )
            self.subtitle_label.grid(row=1, column=0, sticky="w", pady=(5, 0))
            
            # Horizontal separator
            self.separator = ttk.Separator(
                self.main_frame,
                orient='horizontal',
                style='Custom.TSeparator'
            )
            self.separator.grid(row=1, column=0, sticky="ew", pady=(0, 20))
            
            # Content frame
            self.content_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
            self.content_frame.grid(row=2, column=0, sticky="nsew")
            self.content_frame.columnconfigure(0, weight=1)
            self.content_frame.rowconfigure(1, weight=1)
            
            # Create file selection panel
            try:
                self._create_file_selection()
            except Exception as e:
                print(f"Error creating file selection panel: {e}")
                messagebox.showerror("GUI Error", f"Failed to create file selection panel: {str(e)}")
            
            # Create notebook with tabs
            try:
                self._create_notebook_tabs()
            except Exception as e:
                print(f"Error creating notebook tabs: {e}")
                messagebox.showerror("GUI Error", f"Failed to create application tabs: {str(e)}")
                
        except Exception as e:
            error_msg = f"Failed to create main GUI widgets: {str(e)}"
            print(error_msg)
            messagebox.showerror("GUI Creation Error", error_msg)
            raise  # Re-raise to prevent incomplete initialization
    
    def _process_file(self):
        """
        Validate inputs and start file processing in a separate thread.
        """
        try:
            # Get selected file path
            file_path = self.selected_file_path.get().strip()
            if not file_path:
                messagebox.showerror("Error", "Please select a file first.")
                return
            
            # Check if file exists
            if not os.path.exists(file_path):
                messagebox.showerror("Error", "Selected file does not exist.")
                return
            
            # Get password
            password = self.password_var.get().strip()
            if not password:
                messagebox.showerror("Error", "Please enter a password.")
                return
            
            # Check if at least one operation is selected
            if not self.compress_var.get() and not self.encrypt_var.get():
                messagebox.showerror("Error", "Please select at least one operation (compress or encrypt).")
                return
            
            # Handle decoy system registration if enabled
            if self.decoy_var.get():
                if not decoy_available:
                    messagebox.showwarning("Warning", "Decoy system module not available. Proceeding without decoy protection.")
                else:
                    decoy_file = self.decoy_file_path.get().strip()
                    decoy_password = self.decoy_password_var.get().strip()
                    
                    if decoy_file and decoy_password:
                        try:
                            register_decoy_mapping(file_path, decoy_file)
                            self.log_message(f"Decoy protection enabled for: {os.path.basename(file_path)}", "SECURITY")
                        except Exception as e:
                            messagebox.showwarning("Decoy Warning", f"Failed to register decoy mapping: {str(e)}")
                    else:
                        messagebox.showwarning("Decoy Warning", "Decoy system is enabled but decoy file or password is missing. Proceeding without decoy protection.")
            
            # Log the operation start
            self.logger.log_event("PROCESS_START", f"Starting file processing: {file_path}")
            
            # Show processing indicator
            self._show_processing_indicator()
            
            # Start processing in separate thread
            import threading
            threading.Thread(
                target=self._do_process_file,
                args=(file_path, password),
                daemon=True
            ).start()
        except Exception as e:
            self._processing_error(f"Failed to start processing: {str(e)}")
    
    def _do_process_file(self, file_path, password):
        """
        Perform the actual file processing (compression and/or encryption), ensuring only one output file is created with the correct extension.
        Args:
            file_path (str): Path to the file to process
            password (str): Password for encryption
        """
        import tempfile, shutil, os
        try:
            import tempfile
            operations_performed = []
            current_file = file_path
            prev_file = None
            with tempfile.TemporaryDirectory() as temp_dir:
                # Step 1: Compression (if enabled)
                if self.compress_var.get():
                    if compression_available:
                        try:
                            if not os.path.exists(current_file):
                                raise Exception(f"Input file not found: {current_file}")
                            result = compress_file(current_file)
                            if isinstance(result, tuple) and len(result) == 2:
                                compressed_file, compression_ratio = result
                                if compressed_file and os.path.exists(compressed_file):
                                    prev_file = current_file
                                    current_file = compressed_file
                                    operations_performed.append("Compression")
                                    try:
                                        self.logger.log_event("COMPRESSION", f"File compressed: {file_path} (ratio: {compression_ratio})")
                                    except Exception as log_e:
                                        print(f"Logging error: {log_e}")
                                    # Delete .fcomp intermediate file if not original or final
                                    if prev_file != file_path and prev_file != current_file and prev_file and (prev_file.endswith('.fcomp') or prev_file.endswith('.fenc')):
                                        try:
                                            if os.path.exists(prev_file):
                                                os.remove(prev_file)
                                        except Exception as del_e:
                                            print(f"Warning: Could not delete intermediate file {prev_file}: {del_e}")
                                else:
                                    raise Exception("Compression failed - output file not created")
                            else:
                                raise Exception("Compression failed - invalid return value")
                        except NotImplementedError:
                            raise Exception("Compression module not available")
                        except Exception as e:
                            error_msg = f"Compression failed: {str(e)}"
                            self.root.after(0, lambda: self._processing_error(error_msg))
                            return
                    else:
                        self.root.after(0, lambda: self._processing_error("Compression module not available"))
                        return
                # Step 2: Encryption (if enabled)
                if self.encrypt_var.get():
                    if encryption_available:
                        try:
                            if not os.path.exists(current_file):
                                raise Exception(f"Input file not found: {current_file}")
                            try:
                                key = generate_key_from_password(password)
                            except Exception as key_e:
                                raise Exception(f"Failed to generate encryption key: {str(key_e)}")
                            result = encrypt_file(current_file, password)
                            if isinstance(result, str) and result:
                                if os.path.exists(result):
                                    prev_file = current_file
                                    operations_performed.append("Encryption")
                                    try:
                                        self.logger.log_event("ENCRYPTION", f"File encrypted: {file_path}")
                                    except Exception as log_e:
                                        print(f"Logging error: {log_e}")
                                    current_file = result
                                    # Delete .fenc or .fcomp intermediate file if not original or final
                                    if prev_file != file_path and prev_file != current_file and prev_file and (prev_file.endswith('.fcomp') or prev_file.endswith('.fenc')):
                                        try:
                                            if os.path.exists(prev_file):
                                                os.remove(prev_file)
                                        except Exception as del_e:
                                            print(f"Warning: Could not delete intermediate file {prev_file}: {del_e}")
                                else:
                                    raise Exception("Encryption failed - output file not created")
                            else:
                                raise Exception("Encryption failed - invalid return value")
                        except NotImplementedError:
                            raise Exception("Encryption module not available")
                        except Exception as e:
                            error_msg = f"Encryption failed: {str(e)}"
                            self.root.after(0, lambda: self._processing_error(error_msg))
                            return
                    else:
                        self.root.after(0, lambda: self._processing_error("Encryption module not available"))
                        return
                # Step 3: 2FA (if enabled) - only affects output extension
                use_2fa = self.ms_2fa_var.get()
                # Determine final output extension
                base_name = os.path.splitext(os.path.basename(file_path))[0]
                if use_2fa:
                    final_ext = ".fg2c"
                else:
                    final_ext = ".fgc"
                final_output = os.path.join(os.path.dirname(file_path), f"{base_name}{final_ext}")
                # Copy the last processed file to the final output
                shutil.copy2(current_file, final_output)
                # Delete last intermediate file if not original or final output
                if current_file != file_path and current_file != final_output and (current_file.endswith('.fcomp') or current_file.endswith('.fenc')):
                    try:
                        if os.path.exists(current_file):
                            os.remove(current_file)
                    except Exception as del_e:
                        print(f"Warning: Could not delete intermediate file {current_file}: {del_e}")
                current_file = final_output
                # Schedule success callback on main thread
                self.root.after(0, lambda: self._processing_complete(current_file, operations_performed))
        except Exception as e:
            self.root.after(0, lambda: self._processing_error(f"Processing failed: {str(e)}"))
    
    def _processing_complete(self, result_path, operations):
        """
        Handle successful completion of file processing.
        
        Args:
            result_path (str): Path to the processed file
            operations (list): List of operations performed
        """
        try:
            # Hide processing indicator
            if hasattr(self, 'progress_window'):
                self.progress_window.destroy()
                delattr(self, 'progress_window')
            
            # Log completion
            operations_str = ", ".join(operations)
            self.logger.log_event("PROCESS_COMPLETE", f"File processing completed: {operations_str}")
            
            # Show success message
            message = f"File processing completed successfully!\n\n"
            message += f"Operations performed: {operations_str}\n"
            message += f"Output file: {result_path}"
            
            messagebox.showinfo("Success", message)
            
        except Exception as e:
            self._processing_error(f"Error in completion handler: {str(e)}")
    
    def _processing_error(self, error_message):
        """
        Handle processing errors.
        
        Args:
            error_message (str): Error message to display
        """
        try:
            # Hide processing indicator
            if hasattr(self, 'progress_window'):
                self.progress_window.destroy()
                delattr(self, 'progress_window')
            
            # Log error
            self.logger.log_event("PROCESS_ERROR", error_message)
            
            # Show error message
            messagebox.showerror("Processing Error", error_message)
            
        except Exception as e:
            print(f"Error in error handler: {e}")
    
    def _show_processing_indicator(self):
        """
        Show a processing indicator dialog.
        """
        try:
            # Create progress window
            self.progress_window = tk.Toplevel(self.root)
            self.progress_window.title("Processing...")
            self.progress_window.geometry("300x150")
            self.progress_window.resizable(False, False)
            
            # Center the progress window
            self.progress_window.transient(self.root)
            self.progress_window.grab_set()
            
            # Calculate position
            x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 150
            y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 75
            self.progress_window.geometry(f"300x150+{x}+{y}")
            
            # Create progress content
            progress_frame = ttk.Frame(self.progress_window, padding="20")
            progress_frame.pack(fill="both", expand=True)
            
            # Progress label
            progress_label = ttk.Label(
                progress_frame,
                text="Processing file...",
                font=('Segoe UI', 12),
                justify='center'
            )
            progress_label.pack(pady=(10, 20))
            
            # Progress bar
            self.progress_bar = ttk.Progressbar(
                progress_frame,
                mode='indeterminate',
                length=250
            )
            self.progress_bar.pack(pady=(0, 20))
            self.progress_bar.start()
              # Status label
            self.progress_status = ttk.Label(
                progress_frame,
                text="Please wait...",
                font=('Segoe UI', 10),
                justify='center'
            )
            self.progress_status.pack()
            
        except Exception as e:
            print(f"Error creating progress indicator: {e}")
    
    def _decrypt_file(self):
        """
        Validate inputs and start file decryption in a separate thread.
        """
        try:
            # Get selected file path
            file_path = self.selected_file_path.get().strip()
            if not file_path:
                messagebox.showerror("Error", "Please select a file first.")
                return
            # Check if file exists
            if not os.path.exists(file_path):
                messagebox.showerror("Error", "Selected file does not exist.")
                return
            # Check if it's a FileGuard file and if 2FA is required
            is_2fa_file = file_path.endswith('.fg2c')
            if is_2fa_file:
                # Show 2FA controls if not already visible
                self.decrypt_2fa_frame.grid()
                # Require 2FA verification before proceeding
                if not self._verify_decrypt_2fa_code():
                    messagebox.showerror("2FA Required", "Please enter and verify the correct 2FA code before decryption.")
                    return
            else:
                self.decrypt_2fa_frame.grid_remove()
            # Check if it's an encrypted file (legacy extensions)
            if not (file_path.endswith('.fg2c') or file_path.endswith('.fgc')):
                result = messagebox.askyesno(
                    "File Type Warning",
                    "The selected file doesn't appear to be a FileGuard encrypted file (.fg2c) or compressed file (.fgc).\n\n"
                    "Do you want to proceed anyway?"
                )
                if not result:
                    return
            # Get password
            password = self.decrypt_password_var.get().strip()
            if not password:
                messagebox.showerror("Error", "Please enter the password used for encryption.")
                return
            # Reset failed attempts if new file selected
            if not hasattr(self, '_last_decrypt_file') or self._last_decrypt_file != file_path:
                self.failed_decrypt_attempts = 0
                self._last_decrypt_file = file_path
            # Log the operation start
            self.logger.log_event("DECRYPT_START", f"Starting file decryption: {file_path}")
            # Show processing indicator
            self._show_processing_indicator()
            # Start decryption in separate thread
            threading.Thread(
                target=self._do_decrypt_file_with_attempts,
                args=(file_path, password),
                daemon=True
            ).start()
        except Exception as e:
            self._processing_error(f"Failed to start decryption: {str(e)}")

    def _do_decrypt_file_with_attempts(self, file_path, password):
        """
        Wrapper for decryption with password attempt logic.
        """
        def on_success(result_path, operations):
            self.failed_decrypt_attempts = 0
            self.root.after(0, lambda: self._decryption_complete(result_path, operations))

        def on_failure(error_message):
            self.failed_decrypt_attempts += 1
            
            # Track failed attempt with secure deletion module if available
            if selfdestruct_available:
                try:
                    remaining = track_failed_attempt(file_path)
                    if remaining is not None and remaining <= 0:
                        self.logger.log_event("SECURITY_ALERT", f"Auto-destruct triggered for {file_path} after repeated failed attempts")
                except Exception as track_e:
                    self.logger.log_event("SECURITY_WARNING", f"Could not track failed attempt: {track_e}")
                    
            if self.failed_decrypt_attempts < self.max_decrypt_attempts:
                self.root.after(0, lambda: self._processing_error(f"{error_message}\n\nAttempt {self.failed_decrypt_attempts} of {self.max_decrypt_attempts}."))
            else:
                # After max attempts, try to get decoy from mapping system first
                self.failed_decrypt_attempts = 0
                decoy_file = None
                try:
                    decoy_file = get_decoy_for_file(file_path)
                except Exception as e:
                    self.logger.log_event("DECOY_ERROR", f"Error looking up decoy mapping: {e}")
                # Fallback to GUI variable if mapping not found
                if not decoy_file and hasattr(self, 'decoy_file_path'):
                    gui_decoy = self.decoy_file_path.get().strip()
                    if gui_decoy:
                        decoy_file = gui_decoy
                if decoy_file and os.path.exists(decoy_file):
                    self.logger.log_event("DECOY_TRIGGERED", f"Decoy file served after {self.max_decrypt_attempts} failed attempts. Source: {'mapping' if get_decoy_for_file(file_path) else 'gui'}")
                    # Configure the secure deletion for this file if not already done
                    if selfdestruct_available:
                        try:
                            configure_attempt_limit(file_path, self.max_decrypt_attempts)
                        except Exception as config_e:
                            self.logger.log_event("SECURITY_WARNING", f"Could not configure secure deletion: {config_e}")
                    self.root.after(0, lambda: self._show_decoy_file(decoy_file))
                else:
                    self.root.after(0, lambda: self._processing_error("Maximum password attempts reached. No decoy file configured or found."))

        # Try decryption, catch password errors
        try:
            self._do_decrypt_file(file_path, password)
            # If no error, success will be handled by _decryption_complete
        except Exception as e:
            # Check if this is a password error
            msg = str(e)
            if "invalid password" in msg.lower() or "incorrect password" in msg.lower() or "decryption failed" in msg.lower():
                on_failure(msg)
            else:
                self.root.after(0, lambda: self._processing_error(f"Decryption failed: {msg}"))

    def _show_decoy_file(self, decoy_file):
        """
        Show the decoy file to the user after failed attempts and securely delete the original file.
        """
        try:
            original_file = self._last_decrypt_file
            
            # Show message about decoy file
            messagebox.showinfo(
                "Security Alert", 
                f"Maximum password attempts reached. Access denied.\n\n"
                f"For security, the original encrypted file will be securely deleted."
            )
            
            # Delete any associated 2FA secrets
            if original_file and original_file.endswith('.fg2c'):
                try:
                    from two_factor.authenticator import delete_secret_file
                    if delete_secret_file(original_file):
                        self.logger.log_event(
                            "2FA_CLEANUP", 
                            f"Deleted 2FA secret for {original_file} after failed attempts"
                        )
                except Exception as secret_err:
                    self.logger.log_event(
                        "SECURITY_WARNING", 
                        f"Could not delete 2FA secret: {secret_err}"
                    )
            
            # Attempt to securely delete the original file
            deleted = False
            if selfdestruct_available and original_file and os.path.exists(original_file):
                try:
                    # Use secure deletion with 3 passes to thoroughly remove the original file
                    deleted = secure_delete_file(original_file, passes=3)
                    if deleted:
                        self.logger.log_event(
                            "SECURITY_ACTION", 
                            f"Original file securely deleted after max password attempts: {original_file}"
                        )
                    else:
                        self.logger.log_event(
                            "SECURITY_WARNING", 
                            f"Failed to securely delete original file: {original_file}"
                        )
                except Exception as del_e:
                    self.logger.log_event(
                        "SECURITY_ERROR", 
                        f"Error during secure deletion: {del_e}"
                    )
            
            # Open the decoy file
            import subprocess
            import platform
            if platform.system() == "Windows":
                os.startfile(decoy_file)
            elif platform.system() == "Darwin":
                subprocess.call(["open", decoy_file])
            else:
                subprocess.call(["xdg-open", decoy_file])
                
            # Provide feedback about the security action
            if deleted:
                messagebox.showinfo(
                    "Security Notice", 
                    "The protected file has been securely deleted for your security."
                )
                
        except Exception as e:
            messagebox.showerror("Decoy Error", f"Failed to open decoy file: {e}")
    
    def _do_decrypt_file(self, file_path, password):
        """
        Perform the actual file decryption and decompression.
        
        Args:
            file_path (str): Path to the file to decrypt
            password (str): Password for decryption
        """
        try:
            import tempfile
            operations_performed = []
            current_file = file_path
            intermediate_files = []

            # Create temporary directory for intermediate files
            with tempfile.TemporaryDirectory() as temp_dir:
                # Step 1: Decryption (if it's an encrypted file)
                if file_path.endswith('.fge') or file_path.endswith('.fgc') or file_path.endswith('.fg2c'):
                    if encryption_available:
                        try:
                            # Generate decryption key from password
                            key = generate_key_from_password(password)
                            # Decrypt the file - now returns output_path directly
                            result = decrypt_file(current_file, password)
                            if isinstance(result, str) and result:
                                if os.path.exists(result):
                                    intermediate_files.append(current_file) if current_file != file_path else None
                                    current_file = result
                                    operations_performed.append("Decryption")
                                    self.logger.log_event("DECRYPTION", f"File decrypted: {file_path}")
                                else:
                                    # This should not happen with our updated decrypt_file function
                                    raise Exception("Decryption failed - output file not created")
                            else:
                                raise Exception("Decryption failed - invalid password or corrupted file")
                        except Exception as e:
                            error_msg = f"Decryption failed: {str(e)}"
                            raise Exception(error_msg)
                    else:
                        raise Exception("Encryption module not available")
                
                # Step 2: Decompression (if needed)
                if file_path.endswith('.fgc') or file_path.endswith('.fg2c') or current_file.endswith('.fcomp'):
                    if compression_available:
                        try:
                            # Decompress the file
                            result = decompress_file(current_file)
                            if isinstance(result, str) and result:
                                if os.path.exists(result):
                                    intermediate_files.append(current_file) if current_file != file_path else None
                                    current_file = result
                                    operations_performed.append("Decompression")
                                    self.logger.log_event("DECOMPRESSION", f"File decompressed: {file_path}")
                                else:
                                    # This should not happen with our updated decompress_file function
                                    raise Exception("Decompression failed - output file not created")
                            else:
                                raise Exception("Decompression failed - invalid return value")
                        except Exception as e:
                            # If decompression fails, we might still have a valid decrypted file
                            if "Decompression failed" in str(e) and "Decryption" in operations_performed:
                                self.logger.log_event("DECOMPRESSION_SKIP", f"File treated as not compressed: {e}")
                                pass
                            else:
                                raise Exception(f"Decompression failed: {e}")
                    else:
                        raise Exception("Compression module not available for decompression")

                # If no operations were performed (not an encrypted or compressed file)
                if not operations_performed:
                    raise Exception("File does not appear to be encrypted or compressed by FileGuard")
                
                # Clean up any intermediate files (not the original or final file)
                for ifile in intermediate_files:
                    try:
                        if os.path.exists(ifile) and ifile != file_path and ifile != current_file:
                            os.remove(ifile)
                            self.logger.log_event("CLEANUP", f"Removed intermediate file: {ifile}")
                    except Exception as e:
                        self.logger.log_event("CLEANUP_ERROR", f"Failed to remove intermediate file {ifile}: {e}")

                # Schedule success callback on main thread
                self.root.after(0, lambda: self._decryption_complete(current_file, operations_performed))

        except Exception as e:
            # Schedule error callback on main thread
            error_msg = f"Decryption failed: {str(e)}"
            raise Exception(error_msg)
    
    def _decryption_complete(self, result_path, operations):
        """
        Handle successful completion of file decryption.
        
        Args:
            result_path (str): Path to the decrypted file
            operations (list): List of operations performed
        """
        try:
            # Hide processing indicator
            if hasattr(self, 'progress_window'):
                self.progress_window.destroy()
                delattr(self, 'progress_window')
            
            # Clear the status label and show success
            self.decrypt_status_label.config(text="")
            
            # Log completion
            operations_str = ", ".join(operations)
            self.logger.log_event("DECRYPT_COMPLETE", f"File decryption completed: {operations_str}")
            
            # Delete 2FA secret if this was a 2FA-protected file
            if hasattr(self, '_verified_2fa_file_path') and self._verified_2fa_file_path:
                try:
                    from two_factor.authenticator import delete_secret_file
                    file_path = self._verified_2fa_file_path
                    if delete_secret_file(file_path):
                        self.logger.log_event("2FA_CLEANUP", f"Deleted 2FA secret for {file_path}")
                    # Clear the stored file path and secret
                    self._verified_2fa_file_path = None
                    if hasattr(self, '_verified_2fa_secret'):
                        delattr(self, '_verified_2fa_secret')
                except Exception as secret_err:
                    self.logger.log_event("2FA_ERROR", f"Error deleting 2FA secret: {secret_err}")
            
            # Show success message
            message = f"File decryption completed successfully!\n\n"
            message += f"Operations performed: {operations_str}\n"
            message += f"Output file: {result_path}\n\n"
            message += "Your file has been restored to its original state."
            
            messagebox.showinfo("Decryption Success", message)
            
            # Update status label
            self.decrypt_status_label.config(
                text=f"✓ Decryption successful - {operations_str}",
                foreground='green'
            )
            
        except Exception as e:
            self._processing_error(f"Error in decryption completion handler: {str(e)}")
    
    def _create_logs_panel(self):
        """
        Create security logs panel with display and management controls.
        """
        # Main container for logs panel
        logs_container = ttk.Frame(self.logs_frame, style='Main.TFrame', padding="20")
        logs_container.grid(row=0, column=0, sticky="nsew")
        logs_container.columnconfigure(0, weight=1)
        logs_container.rowconfigure(1, weight=1)  # Log display area will expand
        
        # Header section
        header_frame = ttk.Frame(logs_container)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header_frame.columnconfigure(2, weight=1)
        
        # Title
        logs_title = ttk.Label(
            header_frame,
            text="Security Event Logs",
            style='Subtitle.TLabel',
            font=('Segoe UI', 14, 'bold')
        )
        logs_title.grid(row=0, column=0, sticky="w")
        
        # Status indicator
        self.log_status_label = ttk.Label(
            header_frame,
            text="● Live Monitoring",
            foreground='green',
            font=('Segoe UI', 10)
        )
        self.log_status_label.grid(row=0, column=1, padx=(20, 0), sticky="w")
        
        # Control buttons frame
        controls_frame = ttk.Frame(header_frame)
        controls_frame.grid(row=0, column=3, sticky="e")
        
        # Refresh button
        refresh_button = ttk.Button(
            controls_frame,
            text="Refresh",
            command=self._update_log_display,
            width=10
        )
        refresh_button.pack(side="left", padx=(0, 5))
        
        # Clear button
        clear_button = ttk.Button(
            controls_frame,
            text="Clear",
            command=self._clear_log_display,
            width=10
        )
        clear_button.pack(side="left", padx=(0, 5))
        
        # Verify button
        verify_button = ttk.Button(
            controls_frame,
            text="Verify Integrity",
            command=self._verify_logs,
            width=12
        )
        verify_button.pack(side="left")
        
        # Log display area
        log_frame = ttk.LabelFrame(logs_container, text="Event Log", padding="10")
        log_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 20))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Scrolled text widget for log display
        self.log_display = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=('Consolas', 9),
            state='disabled',
            bg='#f8f9fa',
            fg='#2c3e50'
        )
        self.log_display.grid(row=0, column=0, sticky="nsew")
        
        # Configure text tags for different log levels
        self.log_display.tag_configure('INFO', foreground='#2c3e50')
        self.log_display.tag_configure('SUCCESS', foreground='#27ae60', font=('Consolas', 9, 'bold'))
        self.log_display.tag_configure('WARNING', foreground='#f39c12', font=('Consolas', 9, 'bold'))
        self.log_display.tag_configure('ERROR', foreground='#e74c3c', font=('Consolas', 9, 'bold'))
        self.log_display.tag_configure('SECURITY', foreground='#8e44ad', font=('Consolas', 9, 'bold'))
        self.log_display.tag_configure('TIMESTAMP', foreground='#7f8c8d', font=('Consolas', 8))
        
        # Statistics section
        stats_frame = ttk.LabelFrame(logs_container, text="Session Statistics", padding="10")
        stats_frame.grid(row=2, column=0, sticky="ew")
        stats_frame.columnconfigure(1, weight=1)
        stats_frame.columnconfigure(3, weight=1)
        stats_frame.columnconfigure(5, weight=1)
        
        # Initialize statistics variables
        self.stats = {
            'total_events': 0,
            'encryption_events': 0,
            'decryption_events': 0,
            'compression_events': 0,
            'error_events': 0
        }
        
        # Statistics labels
        ttk.Label(stats_frame, text="Total Events:", font=('Segoe UI', 9, 'bold')).grid(row=0, column=0, sticky="w")
        self.total_events_label = ttk.Label(stats_frame, text="0", foreground='#2c3e50')
        self.total_events_label.grid(row=0, column=1, sticky="w", padx=(10, 20))
        
        ttk.Label(stats_frame, text="Encryptions:", font=('Segoe UI', 9, 'bold')).grid(row=0, column=2, sticky="w")
        self.encryption_events_label = ttk.Label(stats_frame, text="0", foreground='#27ae60')
        self.encryption_events_label.grid(row=0, column=3, sticky="w", padx=(10, 20))
        
        ttk.Label(stats_frame, text="Errors:", font=('Segoe UI', 9, 'bold')).grid(row=0, column=4, sticky="w")
        self.error_events_label = ttk.Label(stats_frame, text="0", foreground='#e74c3c')
        self.error_events_label.grid(row=0, column=5, sticky="w", padx=(10, 0))
        
        # Second row of statistics
        ttk.Label(stats_frame, text="Decryptions:", font=('Segoe UI', 9, 'bold')).grid(row=1, column=0, sticky="w", pady=(5, 0))
        self.decryption_events_label = ttk.Label(stats_frame, text="0", foreground='#3498db')
        self.decryption_events_label.grid(row=1, column=1, sticky="w", padx=(10, 20), pady=(5, 0))
        
        ttk.Label(stats_frame, text="Compressions:", font=('Segoe UI', 9, 'bold')).grid(row=1, column=2, sticky="w", pady=(5, 0))
        self.compression_events_label = ttk.Label(stats_frame, text="0", foreground='#f39c12')
        self.compression_events_label.grid(row=1, column=3, sticky="w", padx=(10, 0), pady=(5, 0))
        
        # Add initial welcome message
        self.log_message("FileGuard application started", "INFO")
        self.log_message("Security logging initialized", "SUCCESS")
    
    def log_message(self, message, level="INFO"):
        """
        Log a message and display it in the log panel.
        
        Args:
            message (str): The message to log
            level (str): Log level (INFO, SUCCESS, WARNING, ERROR, SECURITY)
        """
        try:
            import datetime
            
            # Get current timestamp
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Format the log entry
            log_entry = f"[{timestamp}] [{level}] {message}\n"
            
            # Update statistics safely
            try:
                self.stats['total_events'] += 1
                
                # Update specific counters based on message content
                message_lower = message.lower()
                if 'encrypt' in message_lower and 'decrypt' not in message_lower:
                    self.stats['encryption_events'] += 1
                elif 'decrypt' in message_lower:
                    self.stats['decryption_events'] += 1
                elif 'compress' in message_lower:
                    self.stats['compression_events'] += 1
                
                if level == 'ERROR':
                    self.stats['error_events'] += 1
            except Exception as stats_e:
                print(f"Error updating statistics: {stats_e}")
            
            # Update the log display safely
            try:
                if hasattr(self, 'log_display'):
                    self.log_display.config(state='normal')
                    self.log_display.insert(tk.END, log_entry)
                    
                    # Apply appropriate tag for coloring
                    line_start = self.log_display.index("end-2c linestart")
                    timestamp_end = f"{line_start}+21c"
                    level_start = f"{line_start}+23c"
                    
                    # Color the timestamp
                    self.log_display.tag_add('TIMESTAMP', line_start, timestamp_end)
                    
                    # Color the level and message based on level
                    if level == 'SUCCESS':
                        self.log_display.tag_add('SUCCESS', level_start, "end-1c")
                    elif level == 'WARNING':
                        self.log_display.tag_add('WARNING', level_start, "end-1c")
                    elif level == 'ERROR':
                        self.log_display.tag_add('ERROR', level_start, "end-1c")
                    elif level == 'SECURITY':
                        self.log_display.tag_add('SECURITY', level_start, "end-1c")
                    else:
                        self.log_display.tag_add('INFO', level_start, "end-1c")
                    
                    # Auto-scroll to bottom
                    self.log_display.see(tk.END)
                    self.log_display.config(state='disabled')
                    
                    # Update statistics display
                    self._update_statistics_display()
            except Exception as display_e:
                print(f"Error updating log display: {display_e}")
            
            # Also log to the secure logger
            try:
                self.logger.log_event(level, message)
            except Exception as logger_e:
                print(f"Error logging to secure logger: {logger_e}")
            
        except Exception as e:
            print(f"Error in log_message: {e}")
            # Fallback - at least print to console
            print(f"[{level}] {message}")
    
    def _update_log_display(self):
        """
        Refresh the log display with latest entries from secure logger.
        """
        try:
            if not logging_available:
                self.log_message("Secure logging module not available for refresh", "WARNING")
                return
            
            # Get logs from secure logger
            logs = self.logger.read_logs()
            
            if not logs:
                self.log_message("No logs found in secure storage", "INFO")
                return
            
            # Clear current display
            self.log_display.config(state='normal')
            self.log_display.delete(1.0, tk.END)
            self.log_display.config(state='disabled')
            
            # Reset statistics
            self.stats = {key: 0 for key in self.stats}
            
            # Display recent logs (last 100 entries)
            recent_logs = logs[-100:] if len(logs) > 100 else logs
            
            for log_entry in recent_logs:
                # Extract level and message from log entry
                if isinstance(log_entry, dict):
                    level = log_entry.get('level', 'INFO')
                    message = log_entry.get('message', 'Unknown log entry')
                    timestamp = log_entry.get('timestamp', 'Unknown time')
                else:
                    # Handle string format logs
                    level = 'INFO'
                    message = str(log_entry)
                
                # Add to display without logging again (avoid recursion)
                self._add_log_entry_to_display(message, level, timestamp)
            
            self.log_message(f"Log display refreshed - {len(recent_logs)} entries loaded", "SUCCESS")
            
        except Exception as e:
            self.log_message(f"Error refreshing log display: {str(e)}", "ERROR")
    
    def _add_log_entry_to_display(self, message, level, timestamp=None):
        """
        Add a log entry to the display without logging it again.
        
        Args:
            message (str): The message to display
            level (str): Log level
            timestamp (str): Optional timestamp
        """
        try:
            if timestamp is None:
                import datetime
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Format the log entry
            log_entry = f"[{timestamp}] [{level}] {message}\n"
            
            # Update statistics
            self.stats['total_events'] += 1
            message_lower = message.lower()
            if 'encrypt' in message_lower and 'decrypt' not in message_lower:
                self.stats['encryption_events'] += 1
            elif 'decrypt' in message_lower:
                self.stats['decryption_events'] += 1
            elif 'compress' in message_lower:
                self.stats['compression_events'] += 1
            
            if level == 'ERROR':
                self.stats['error_events'] += 1
            
            # Add to display
            self.log_display.config(state='normal')
            self.log_display.insert(tk.END, log_entry)
            
            # Apply coloring (same as log_message method)
            line_start = self.log_display.index("end-2c linestart")
            timestamp_end = f"{line_start}+21c"
            level_start = f"{line_start}+23c"
            
            self.log_display.tag_add('TIMESTAMP', line_start, timestamp_end)
            
            if level == 'SUCCESS':
                self.log_display.tag_add('SUCCESS', level_start, "end-1c")
            elif level == 'WARNING':
                self.log_display.tag_add('WARNING', level_start, "end-1c")
            elif level == 'ERROR':
                self.log_display.tag_add('ERROR', level_start, "end-1c")
            elif level == 'SECURITY':
                self.log_display.tag_add('SECURITY', level_start, "end-1c")
            else:
                self.log_display.tag_add('INFO', level_start, "end-1c")
            
            self.log_display.config(state='disabled')
            
        except Exception as e:
            print(f"Error adding log entry to display: {e}")
    
    def _update_statistics_display(self):
        """
        Update the statistics display with current values.
        """
        try:
            self.total_events_label.config(text=str(self.stats['total_events']))
            self.encryption_events_label.config(text=str(self.stats['encryption_events']))
            self.decryption_events_label.config(text=str(self.stats['decryption_events']))
            self.compression_events_label.config(text=str(self.stats['compression_events']))
            self.error_events_label.config(text=str(self.stats['error_events']))
        except Exception as e:
            print(f"Error updating statistics display: {e}")
    
    def _clear_log_display(self):
        """
        Clear the log display area.
        """
        try:
            result = messagebox.askyesno(
                "Clear Log Display",
                "Are you sure you want to clear the log display?\n\n"
                "This will only clear the display, not the secure log storage."
            )
            
            if result:
                # Clear the display
                self.log_display.config(state='normal')
                self.log_display.delete(1.0, tk.END)
                self.log_display.config(state='disabled')
                
                # Reset statistics
                self.stats = {key: 0 for key in self.stats}
                self._update_statistics_display()
                
                # Add a clear message
                self.log_message("Log display cleared by user", "INFO")
        
        except Exception as e:
            self.log_message(f"Error clearing log display: {str(e)}", "ERROR")
    
    def _verify_logs(self):
        """
        Verify the integrity of stored logs.
        """
        try:
            if not logging_available:
                messagebox.showwarning(
                    "Verification Unavailable",
                    "Secure logging module is not available.\nLog integrity verification cannot be performed."
                )
                return
            
            self.log_message("Starting log integrity verification...", "SECURITY")
            
            # Perform integrity check
            is_valid, issues = self.logger.verify_log_integrity()
            
            if is_valid:
                self.log_message("✓ Log integrity verification PASSED", "SUCCESS")
                messagebox.showinfo(
                    "Verification Successful",
                    "Log integrity verification completed successfully.\n\n"
                    "All logs are authentic and have not been tampered with."
                )
            else:
                self.log_message("✗ Log integrity verification FAILED", "ERROR")
                issues_text = "\n".join(issues) if issues else "Unknown integrity issues detected"
                messagebox.showerror(
                    "Verification Failed",
                    f"Log integrity verification FAILED!\n\n"
                    f"Issues detected:\n{issues_text}\n\n"
                    "The logs may have been tampered with or corrupted."
                )
            
        except Exception as e:
            error_msg = f"Error during log verification: {str(e)}"
            self.log_message(error_msg, "ERROR")
            messagebox.showerror("Verification Error", error_msg)


def create_app():
    """
    Create and return the FileGuard application instance.
    
    Returns:
        FileGuardApp: The initialized application instance
    """
    try:
        print("Creating FileGuard application...")
        
        # Create root window with error handling
        try:
            root = tk.Tk()
            print("✓ Tkinter root window created")
        except Exception as e:
            print(f"✗ Failed to create Tkinter root window: {e}")
            raise
        
        # Initialize application with error handling
        try:
            app = FileGuardApp(root)
            print("✓ FileGuard application initialized")
        except Exception as e:
            print(f"✗ Failed to initialize FileGuard application: {e}")
            try:
                root.destroy()
            except:
                pass
            raise
        
        return app, root
        
    except Exception as e:
        print(f"✗ Error creating FileGuard application: {e}")
        import traceback
        traceback.print_exc()
        raise


def main():
    """
    Main function to run the FileGuard application.
    """
    try:
        print("=" * 50)
        print("FileGuard Secure File Manager")
        print("=" * 50)
        
        # Create the application with comprehensive error handling
        try:
            app, root = create_app()
        except Exception as e:
            print(f"\n✗ Fatal Error: Could not create application")
            print(f"Error details: {e}")
            
            # Try to show error dialog if possible
            try:
                import tkinter as tk
                from tkinter import messagebox
                temp_root = tk.Tk()
                temp_root.withdraw()
                messagebox.showerror(
                    "FileGuard Startup Error",
                    f"Failed to start FileGuard application.\n\n"
                    f"Error: {e}\n\n"
                    f"Please check the console for detailed error information."
                )
                temp_root.destroy()
            except Exception as dialog_e:
                print(f"Also failed to show error dialog: {dialog_e}")
            
            return
        
        # Configure window close event with error handling
        try:
            def on_closing():
                """Handle window close event."""
                try:
                    import tkinter.messagebox as msgbox
                    result = msgbox.askyesno(
                        "Exit FileGuard",
                        "Are you sure you want to exit FileGuard?\n\n"
                        "Any ongoing operations will be terminated."
                    )
                    if result:
                        try:
                            app.logger.log_event("APP_SHUTDOWN", "FileGuard application shutting down")
                        except:
                            pass
                        root.quit()
                        root.destroy()
                except Exception as close_e:
                    print(f"Error during application closing: {close_e}")
                    # Fallback: just close the application
                    try:
                        root.quit()
                        root.destroy()
                    except:
                        pass
            
            root.protocol("WM_DELETE_WINDOW", on_closing)
            print("✓ Window close handler configured")
            
        except Exception as e:
            print(f"⚠ Warning: Could not configure window close handler: {e}")
        
        # Start the main loop with error handling
        try:
            print("\n🚀 Starting FileGuard GUI...")
            print("   Use the interface to encrypt, decrypt, and manage your files securely.")
            print("   Check the Security Logs tab for detailed operation history.\n")
            
            root.mainloop()
            
        except KeyboardInterrupt:
            print("\n⚡ Application interrupted by user (Ctrl+C)")
        except Exception as e:
            print(f"\n✗ Error in main loop: {e}")
            import traceback
            traceback.print_exc()
            
            # Try to show error dialog
            try:
                import tkinter.messagebox as msgbox
                msgbox.showerror(
                    "Runtime Error",
                    f"An error occurred during application execution:\n\n{e}\n\n"
                    f"The application will now close."
                )
            except:
                pass
        finally:
            try:
                print("\n📋 FileGuard application session ended.")
                if hasattr(app, 'logger'):
                    app.logger.log_event("APP_SHUTDOWN", "FileGuard application session ended")
            except Exception as cleanup_e:
                print(f"Error during cleanup: {cleanup_e}")
        
    except Exception as e:
        print(f"\n💥 Fatal error in main function: {e}")
        import traceback
        traceback.print_exc()


# Test the application
if __name__ == "__main__":
    main()