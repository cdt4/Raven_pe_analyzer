"""
Handles parsing of import and export tables.
"""
from collections import defaultdict
from raven.core.string_analyzer import SUSPICIOUS_APIS
from colorama import Fore, Style


def parse_imports(pe):
    """Extract all imported DLLs and their functions."""
    imports = defaultdict(list)
    suspicious_imports = []
    
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return imports, suspicious_imports
    
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode().lower()
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode()
                    imports[dll].append(func_name)
                    
                    # Check if this is a suspicious API
                    for suspicious_dll, apis in SUSPICIOUS_APIS.items():
                        if dll == suspicious_dll.lower() and func_name in apis:
                            suspicious_imports.append({
                                'type': 'suspicious_import',
                                'dll': dll,
                                'function': func_name,
                                'message': f"Suspicious API: {dll}!{func_name}"
                            })
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Error parsing imports: {e}{Style.RESET_ALL}")
    
    return dict(imports), suspicious_imports


def parse_exports(pe):
    """Extract exported functions from the PE file."""
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return {}
    
    try:
        export_dir = pe.DIRECTORY_ENTRY_EXPORT
        exports = {
            'base': export_dir.struct.Base if hasattr(export_dir.struct, 'Base') else 0,
            'count': export_dir.struct.NumberOfFunctions,
            'names_count': export_dir.struct.NumberOfNames,
            'functions': []
        }
        
        for exp in export_dir.symbols:
            if exp.name:
                exports['functions'].append({
                    'name': exp.name.decode(),
                    'address': exp.address,
                    'ordinal': exp.ordinal
                })
        
        return exports
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Error parsing exports: {e}{Style.RESET_ALL}")
        return {}
