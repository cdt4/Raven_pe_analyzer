"""
Detects if an executable has been packed or obfuscated.
"""


# Known packer signatures to look for
PACKER_SIGNATURES = {
    b'UPX!': 'UPX',
    b'!EP': 'PECompact',
    b'MPRESS1': 'MPRESS',
    b'MEW': 'MEW',
    b'NsPacK': 'NsPacK',
    b'ASPack': 'ASPack',
    b'FSG!': 'FSG',
    b'RLPack': 'RLPack',
    b'PEC2TO': 'PEC2',
    b'PEC2': 'PEC2',
    b'PELOCK': 'PELock',
    b'Themida': 'Themida',
    b'VMProtect': 'VMProtect',
    b'.aspack': 'ASPack',
    b'.packed': 'Generic Packer',
    b'WinUpack': 'Upack',
    b'PEBundle': 'PEBundle',
    b'Petite': 'Petite',
    b'kkrunchy': 'kkrunchy',
    b'Yoda\'s Crypter': 'Yoda',
    b'ACProtect': 'ACProtect',
    b'EXECryptor': 'EXECryptor',
    b'Obsidium': 'Obsidium',
    b'tElock': 'tElock',
    b'Armadillo': 'Armadillo',
    b'Enigma': 'Enigma Protector'
}


# Patterns often seen at the entry point of packed executables
ENTRY_PATTERNS = {
    b'\x60\xE8\x00\x00\x00\x00\x5D': 'UPX',
    b'\xE8\x00\x00\x00\x00\xE9\xEB': 'PECompact',
    b'\xFC\x68': 'FSG',
    b'\xEB\x10\x5A\x4A\x33\xC9': 'ASPack',
    b'\xBE\x00\x00\x00\x00\x8D\xBE': 'UPX',
    b'\x60\xBE\x00\x00\x00\x00\x8D\xBE': 'UPX',
    b'\xE8\x00\x00\x00\x00\x58': 'Generic Unpacking Stub'
}


def find_packer_signatures(file_data):
    """Scan the binary for known packer signatures."""
    found = []
    for signature, name in PACKER_SIGNATURES.items():
        if signature in file_data:
            found.append(name)
    return found


def check_entry_point_patterns(entry_point_code):
    """Check if the entry point code matches known packer patterns."""
    matches = []
    for pattern, name in ENTRY_PATTERNS.items():
        if entry_point_code.startswith(pattern):
            matches.append(name)
    return matches


def check_section_weirdness(sections):
    """Look for suspicious section characteristics that might indicate packing."""
    issues = []
    
    # Normal section names we expect to see
    normal_names = {'.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.reloc', '.bss'}
    
    for section in sections:
        name = section['name']
        
        # Weird section name
        if name not in normal_names and not name.startswith('/'):
            issues.append(f"Unusual section name: {name}")
        
        # Section that's both writable and executable (bad practice)
        flags = section['characteristics']
        if (flags & 0x20000000) and (flags & 0x80000000):
            issues.append(f"Section {name} is both writable and executable")
        
        # Empty on disk but not in memory (unpacking indicator)
        if section['raw_size'] == 0 and section['virtual_size'] > 0:
            issues.append(f"Section {name} has no data on disk but will exist in memory")
    
    return issues


def check_entropy_issues(sections):
    """High entropy in multiple sections is a strong packing indicator."""
    problems = []
    high_entropy_count = 0
    
    for section in sections:
        entropy = section['entropy']
        if entropy > 7.5:
            high_entropy_count += 1
            problems.append(f"Very high entropy in {section['name']}: {entropy:.2f}")
    
    if high_entropy_count >= 2:
        problems.append(f"Multiple high entropy sections ({high_entropy_count}) - likely packed")
    
    return problems
