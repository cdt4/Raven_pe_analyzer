"""
Parses PE file sections and analyzes their characteristics.
"""
import re
from raven.core.entropy import calculate_entropy
from colorama import Fore, Style


def parse_sections(pe):
    """Extract detailed info about each section in the PE file."""
    sections = []
    previous_end = 0
    
    for i, section in enumerate(pe.sections):
        try:
            section_data = section.get_data()
            entropy = calculate_entropy(section_data)
            
            # Look for weird stuff
            anomalies = []
            
            # Zero raw size but has virtual size
            if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                anomalies.append("Empty on disk but present in memory")
            
            # Section goes past end of file
            section_end = section.PointerToRawData + section.SizeOfRawData
            if section_end > len(pe.__data__):
                anomalies.append("Extends beyond file boundary")
            
            # Overlapping sections
            section_start = section.PointerToRawData
            if section_start < previous_end and i > 0:
                anomalies.append(f"Overlaps previous section")
            previous_end = section.PointerToRawData + section.SizeOfRawData
            
            # Unusual section name
            section_name = section.Name.decode().strip('\x00')
            if not re.match(r'^[.a-zA-Z0-9_]+$', section_name):
                anomalies.append("Non-standard section name")
            
            # Writable and executable (security issue)
            if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
                anomalies.append("Both writable AND executable (W^X violation)")
            
            section_info = {
                'name': section_name,
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_address': section.PointerToRawData,
                'raw_size': section.SizeOfRawData,
                'characteristics': section.Characteristics,
                'characteristics_human': decode_section_flags(section.Characteristics),
                'entropy': entropy,
                'is_suspicious': entropy > 7.8,
                'anomalies': anomalies
            }
            
            sections.append(section_info)
            
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Error analyzing section: {e}{Style.RESET_ALL}")
    
    return sections


def decode_section_flags(characteristics):
    """Convert section permission flags to readable text."""
    flags = []
    
    flag_meanings = {
        0x00000020: 'CODE',
        0x00000040: 'INITIALIZED_DATA',
        0x00000080: 'UNINITIALIZED_DATA',
        0x04000000: 'NOT_CACHED',
        0x08000000: 'NOT_PAGED',
        0x10000000: 'SHARED',
        0x20000000: 'EXECUTE',
        0x40000000: 'READ',
        0x80000000: 'WRITE'
    }
    
    for flag, name in flag_meanings.items():
        if characteristics & flag:
            flags.append(name)
    
    return ' | '.join(flags) if flags else 'NONE'
