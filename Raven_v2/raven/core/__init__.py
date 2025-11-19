"""Core analysis functionality."""

from .entropy import calculate_entropy, get_entropy_color
from .string_analyzer import (
    classify_string, 
    extract_ascii_strings, 
    extract_unicode_strings,
    SUSPICIOUS_APIS
)
from .risk_assessment import calculate_risk_level
from .packer_detection import (
    find_packer_signatures,
    check_entry_point_patterns,
    check_section_weirdness,
    check_entropy_issues
)

__all__ = [
    'calculate_entropy',
    'get_entropy_color',
    'classify_string',
    'extract_ascii_strings',
    'extract_unicode_strings',
    'SUSPICIOUS_APIS',
    'calculate_risk_level',
    'find_packer_signatures',
    'check_entry_point_patterns',
    'check_section_weirdness',
    'check_entropy_issues'
]
