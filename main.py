#!/usr/bin/env python3
"""
FileGuard Main Application Entry Point
=====================================

This is the main entry point for the FileGuard secure file management application.
Run this file to start the GUI application.

Usage:
    python main.py

Author: FileGuard Team
Version: 1.0.0
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox
import traceback

# Add project root to Python path for module discovery
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

def check_dependencies():
    """
    Check if required dependencies are available.
    
    Returns:
        bool: True if all critical dependencies are available, False otherwise
    """
    missing_dependencies = []
    
    # Check for tkinter (should be available with Python installation)
    try:
        import tkinter
        import tkinter.ttk
        import tkinter.filedialog
        import tkinter.messagebox
        import tkinter.scrolledtext
    except ImportError as e:
        missing_dependencies.append(f"tkinter: {e}")
    
    # Check for PIL (optional but recommended for QR code display)
    try:
        from PIL import Image, ImageTk
    except ImportError:
        print("Warning: PIL (Pillow) not available. QR code display will be limited.")
    
    # Check for threading support
    try:
        import threading
    except ImportError as e:
        missing_dependencies.append(f"threading: {e}")
    
    if missing_dependencies:
        print("Critical dependencies missing:")
        for dep in missing_dependencies:
            print(f"  - {dep}")
        return False
    
    return True

def setup_environment():
    """
    Setup the application environment and verify project structure.
    
    Returns:
        bool: True if environment setup successful, False otherwise
    """
    try:
        # Verify project structure
        required_dirs = ['gui', 'compression', 'encryption', 'two_factor', 'decoy', 'selfdestruct', 'fileguardlogging']
        missing_dirs = []
        
        for dir_name in required_dirs:
            dir_path = os.path.join(PROJECT_ROOT, dir_name)
            if not os.path.exists(dir_path):
                missing_dirs.append(dir_name)
        
        if missing_dirs:
            print("Warning: Some FileGuard modules directories are missing:")
            for dir_name in missing_dirs:
                print(f"  - {dir_name}/")
            print("The application will run with limited functionality.")
        
        return True
        
    except Exception as e:
        print(f"Error setting up environment: {e}")
        return False

def create_application():
    """
    Create and initialize the FileGuard application.
    
    Returns:
        tuple: (app_instance, root_window) or (None, None) if creation failed
    """
    try:
        # Import the FileGuard GUI application
        from gui.app import FileGuardApp, create_app
        
        # Create the application instance
        app, root = create_app()
        
        return app, root
        
    except ImportError as e:
        error_msg = f"Failed to import FileGuard GUI module: {e}"
        print(error_msg)
        
        # Show error dialog if tkinter is available
        try:
            root = tk.Tk()
            root.withdraw()  # Hide the root window
            messagebox.showerror(
                "Import Error",
                f"Failed to import FileGuard GUI module.\n\n"
                f"Error: {e}\n\n"
                f"Please ensure all required files are present in the gui/ directory."
            )
            root.destroy()
        except:
            pass
        
        return None, None
        
    except Exception as e:
        error_msg = f"Failed to create FileGuard application: {e}"
        print(error_msg)
        print(traceback.format_exc())
        
        # Show error dialog
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Application Error",
                f"Failed to create FileGuard application.\n\n"
                f"Error: {e}\n\n"
                f"Please check the console for more details."
            )
            root.destroy()
        except:
            pass
        
        return None, None

def configure_window_properties(root):
    """
    Configure additional window properties and event handlers.
    
    Args:
        root (tk.Tk): The root window instance
    """
    try:
        # Set window icon if available
        icon_path = os.path.join(PROJECT_ROOT, "assets", "icon.ico")
        if os.path.exists(icon_path):
            root.iconbitmap(icon_path)
        
        # Configure window close behavior
        def on_closing():
            """Handle application closing."""
            try:
                result = messagebox.askyesno(
                    "Exit FileGuard",
                    "Are you sure you want to exit FileGuard?\n\n"
                    "Any ongoing operations will be terminated."
                )
                if result:
                    root.quit()
                    root.destroy()
            except:
                # Fallback: just close the application
                root.quit()
                root.destroy()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Set minimum window size
        root.minsize(650, 500)
        
        # Make window resizable
        root.resizable(True, True)
        
    except Exception as e:
        print(f"Warning: Failed to configure window properties: {e}")

def run_application():
    """
    Main function to run the FileGuard application.
    
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        print("Starting FileGuard Secure File Manager...")
        print(f"Project root: {PROJECT_ROOT}")
        
        # Check dependencies
        if not check_dependencies():
            print("Error: Critical dependencies are missing. Cannot start application.")
            return 1
        
        # Setup environment
        if not setup_environment():
            print("Error: Failed to setup application environment.")
            return 1
        
        # Create application
        app, root = create_application()
        if app is None or root is None:
            print("Error: Failed to create application instance.")
            return 1
        
        # Configure window properties
        configure_window_properties(root)
        
        print("FileGuard application initialized successfully.")
        print("Starting GUI main loop...")
        
        # Start the main event loop
        root.mainloop()
        
        print("FileGuard application closed.")
        return 0
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user (Ctrl+C)")
        return 0
        
    except Exception as e:
        error_msg = f"Unexpected error occurred: {e}"
        print(error_msg)
        print(traceback.format_exc())
        
        # Try to show error dialog
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Unexpected Error",
                f"An unexpected error occurred:\n\n{e}\n\n"
                f"Please check the console for detailed error information."
            )
            root.destroy()
        except:
            pass
        
        return 1

def show_help():
    """Display help information about the application."""
    help_text = """
FileGuard Secure File Manager
============================

A comprehensive file security application providing:
- File encryption with AES-256
- File compression with multiple algorithms
- Two-factor authentication (2FA) support
- Decoy file protection against coercion
- Self-destruct capabilities for sensitive files
- Secure audit logging with integrity verification

Usage:
    python main.py              # Start the GUI application
    python main.py --help       # Show this help message
    python main.py --version    # Show version information

Requirements:
- Python 3.7 or higher
- tkinter (included with Python)
- PIL/Pillow (optional, for QR code display)

For more information, visit: https://github.com/fileguard/fileguard
"""
    print(help_text)

def show_version():
    """Display version information."""
    version_info = """
FileGuard Secure File Manager
Version: 1.0.0
Build: Release
Python: {python_version}
Platform: {platform}

Components:
- GUI Application
- Encryption Module
- Compression Module  
- Two-Factor Authentication
- Decoy System
- Self-Destruct Module
- Secure Logging
""".format(
        python_version=sys.version.split()[0],
        platform=sys.platform
    )
    print(version_info)

if __name__ == "__main__":
    # Handle command line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ['--help', '-h', 'help']:
            show_help()
            sys.exit(0)
        elif arg in ['--version', '-v', 'version']:
            show_version()
            sys.exit(0)
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Use --help for usage information.")
            sys.exit(1)
    
    # Run the application
    exit_code = run_application()
    sys.exit(exit_code)
