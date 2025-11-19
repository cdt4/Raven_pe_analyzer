"""
Handles loading and basic PE file information extraction.
"""
import os
import pefile
import hashlib
from datetime import datetime
from colorama import Fore, Style, init

init()


def load_pe_file(file_path):
    """Open and parse a PE file."""
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()
        return pe
    except Exception as e:
        print(f"{Fore.RED}Error loading PE file: {e}{Style.RESET_ALL}")
        return None


def get_basic_info(pe, file_path):
    """Extract fundamental PE file information."""
    timestamp = pe.FILE_HEADER.TimeDateStamp
    try:
        compile_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except:
        compile_time = f"Invalid timestamp (0x{timestamp:X})"
    
    return {
        'filename': os.path.basename(file_path),
        'file_size': os.path.getsize(file_path),
        'architecture': 'x64' if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 'x86',
        'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'image_base': pe.OPTIONAL_HEADER.ImageBase,
        'section_count': len(pe.sections),
        'compilation_timestamp': timestamp,
        'compilation_time': compile_time,
        'checksum': pe.OPTIONAL_HEADER.CheckSum,
        'subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'is_dll': bool(pe.FILE_HEADER.Characteristics & 0x2000),
        'is_driver': bool(pe.FILE_HEADER.Characteristics & 0x1000)
    }


def calculate_file_hashes(file_path):
    """Generate hash values for the file."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        hashes = {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }
        
        # Try ssdeep if available
        try:
            import ssdeep
            hashes['ssdeep'] = ssdeep.hash(data)
        except ImportError:
            hashes['ssdeep'] = "ssdeep not installed (pip install ssdeep)"
        except Exception as e:
            hashes['ssdeep'] = f"Error: {str(e)}"
        
        return hashes
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not calculate hashes: {e}{Style.RESET_ALL}")
        return {}
