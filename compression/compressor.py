"""
FileGuard Compression Module
Provides file compression and decompression functionality using zlib.
"""

import os
import zlib


def compress_file(file_path: str) -> tuple[str, float]:
    """
    Compress a file using zlib compression.
    
    Args:
        file_path (str): Path to the file to compress
        
    Returns:
        tuple[str, float]: Tuple containing (compressed_file_path, compression_ratio)
        
    Raises:
        FileNotFoundError: If the input file doesn't exist
        PermissionError: If there are permission issues
        Exception: For other compression errors
    """
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read the file
        with open(file_path, 'rb') as f:
            original_data = f.read()
        
        # Get original file size
        original_size = len(original_data)
        
        if original_size == 0:
            raise ValueError("Cannot compress empty file")
        
        # Compress the data using zlib with maximum compression level
        compressed_data = zlib.compress(original_data, level=9)
        
        # Calculate compression ratio
        compressed_size = len(compressed_data)
        compression_ratio = (1 - compressed_size / original_size) * 100
        
        # Create compressed file path
        compressed_file_path = file_path + '.fcomp'
        
        # Write compressed data
        with open(compressed_file_path, 'wb') as f:
            f.write(compressed_data)
        
        return compressed_file_path, compression_ratio
        
    except FileNotFoundError:
        raise
    except PermissionError as e:
        raise PermissionError(f"Permission denied: {e}")
    except ValueError:
        raise
    except Exception as e:
        raise Exception(f"Compression failed: {e}")


def decompress_file(file_path: str) -> str:
    """
    Decompress a file compressed with zlib.
    
    Args:
        file_path (str): Path to the compressed file (.fcomp extension)
        
    Returns:
        str: Path to the decompressed file (original filename without .fcomp)
        
    Raises:
        FileNotFoundError: If the compressed file doesn't exist
        ValueError: If the file format is invalid or corrupted
        PermissionError: If there are permission issues
        Exception: For other decompression errors
    """
    try:
        # Check if compressed file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Compressed file not found: {file_path}")

        # Read the compressed file
        with open(file_path, 'rb') as f:
            compressed_data = f.read()

        if len(compressed_data) == 0:
            raise ValueError("Compressed file is empty")

        # Decompress the data
        try:
            decompressed_data = zlib.decompress(compressed_data)
        except zlib.error as e:
            raise ValueError(f"Decompression failed - invalid or corrupted file: {e}")

        # Create output directory path (same as input file)
        output_dir = os.path.dirname(file_path)
        
        # Get the base name without extension
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        
        # Further clean up the base name if needed (remove _compressed suffix if present)
        if base_name.endswith('_compressed'):
            base_name = base_name[:-11]
            
        # Try to detect original file extension - for now we'll use .txt as a fallback
        # A more sophisticated approach would be to store the original extension in the compressed file
        original_ext = ""
        
        # Create only one output file with the original name
        decompressed_file_path = os.path.join(output_dir, f"{base_name}{original_ext}")
        
        # Write decompressed data
        with open(decompressed_file_path, 'wb') as f:
            f.write(decompressed_data)

        return decompressed_file_path

    except FileNotFoundError:
        raise
    except ValueError:
        raise
    except PermissionError as e:
        raise PermissionError(f"Permission denied: {e}")
    except Exception as e:
        raise Exception(f"Decompression failed: {e}")


def get_compression_info(original_file_path: str, compressed_file_path: str) -> dict:
    """
    Get compression statistics for comparison.
    
    Args:
        original_file_path (str): Path to the original file
        compressed_file_path (str): Path to the compressed file
        
    Returns:
        dict: Dictionary containing compression statistics
        
    Raises:
        FileNotFoundError: If either file doesn't exist
    """
    try:
        if not os.path.exists(original_file_path):
            raise FileNotFoundError(f"Original file not found: {original_file_path}")
        
        if not os.path.exists(compressed_file_path):
            raise FileNotFoundError(f"Compressed file not found: {compressed_file_path}")
        
        original_size = os.path.getsize(original_file_path)
        compressed_size = os.path.getsize(compressed_file_path)
        
        if original_size == 0:
            compression_ratio = 0.0
            space_saved = 0
        else:
            compression_ratio = (1 - compressed_size / original_size) * 100
            space_saved = original_size - compressed_size
        
        return {
            'original_size': original_size,
            'compressed_size': compressed_size,
            'compression_ratio': round(compression_ratio, 2),
            'space_saved': space_saved,
            'size_reduction': f"{original_size} -> {compressed_size} bytes"
        }
        
    except FileNotFoundError:
        raise
    except Exception as e:
        raise Exception(f"Failed to get compression info: {e}")


# Simple test functions
if __name__ == "__main__":
    import tempfile
    
    def test_compression_decompression():
        """Test the compression and decompression functions."""
        print("Testing FileGuard compression/decompression...")
        
        try:
            # Create a temporary test file with repetitive content (compresses well)
            test_content = "This is a test file for FileGuard compression! " * 100
            test_content += "FileGuard is awesome! " * 50
            test_content += "Compression testing in progress... " * 75
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                temp_file.write(test_content)
                temp_file_path = temp_file.name
            
            print(f"Created test file: {temp_file_path}")
            print(f"Original file size: {os.path.getsize(temp_file_path)} bytes")
            
            # Test compression
            compressed_path, compression_ratio = compress_file(temp_file_path)
            print(f"File compressed successfully: {compressed_path}")
            print(f"Compression ratio: {compression_ratio:.2f}%")
            print(f"Compressed file size: {os.path.getsize(compressed_path)} bytes")
            
            # Test decompression
            decompressed_path = decompress_file(compressed_path)
            print(f"File decompressed successfully: {decompressed_path}")
            print(f"Decompressed file size: {os.path.getsize(decompressed_path)} bytes")
            
            # Verify content
            with open(decompressed_path, 'r') as f:
                decompressed_content = f.read()
            
            if decompressed_content == test_content:
                print("✓ Test PASSED: Content matches original")
            else:
                print("✗ Test FAILED: Content doesn't match")
            
            # Test compression info
            info = get_compression_info(temp_file_path, compressed_path)
            print(f"Compression info: {info}")
            
            # Test with corrupted data
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.fcomp') as corrupt_file:
                    corrupt_file.write(b"This is not compressed data")
                    corrupt_file_path = corrupt_file.name
                
                decompress_file(corrupt_file_path)
                print("✗ Test FAILED: Should have failed with corrupted data")
            except ValueError:
                print("✓ Test PASSED: Correctly rejected corrupted data")
            
            # Clean up
            os.unlink(temp_file_path)
            os.unlink(compressed_path)
            os.unlink(decompressed_path)
            os.unlink(corrupt_file_path)
            print("Test files cleaned up")
            
        except Exception as e:
            print(f"✗ Test FAILED with error: {e}")
    
    test_compression_decompression()