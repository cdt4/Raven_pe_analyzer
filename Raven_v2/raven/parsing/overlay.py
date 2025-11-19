"""
Detects and analyzes overlay data appended to PE files.
"""
import os
from colorama import Fore, Style


def check_for_overlay(pe, file_path):
    """Look for extra data appended after the PE file ends."""
    try:
        # Calculate where the PE file should end
        pe_end = pe.OPTIONAL_HEADER.SizeOfHeaders
        for section in pe.sections:
            pe_end = max(pe_end, section.PointerToRawData + section.SizeOfRawData)
        
        actual_file_size = os.path.getsize(file_path)
        
        if actual_file_size > pe_end:
            overlay_size = actual_file_size - pe_end
            overlay_info = {
                'size': overlay_size,
                'offset': pe_end,
                'message': f"Found {overlay_size} bytes of overlay data"
            }
            
            # Check if the overlay contains another PE file
            with open(file_path, 'rb') as f:
                f.seek(pe_end)
                overlay_sample = f.read(min(overlay_size, 4096))
                
                if b'MZ' in overlay_sample:
                    overlay_info['contains_pe'] = True
                    overlay_info['message'] += " (may contain embedded PE file)"
            
            return overlay_info
        
        return None
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Error checking overlay: {e}{Style.RESET_ALL}")
        return None
