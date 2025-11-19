"""
Calculates entropy for binary data to detect packing/encryption.
"""
import math
from collections import defaultdict
from colorama import Fore


def calculate_entropy(data):
    """Shannon entropy calculation for any chunk of bytes."""
    if not data:
        return 0.0
    
    frequency_map = defaultdict(int)
    for byte in data:
        frequency_map[byte] += 1
    
    total_bytes = len(data)
    entropy_value = 0.0
    
    for count in frequency_map.values():
        if count > 0:
            probability = count / total_bytes
            entropy_value -= probability * math.log2(probability)
    
    return entropy_value


def get_entropy_color(entropy):
    """Returns color based on how suspicious the entropy level is."""
    if entropy > 7.5:
        return Fore.RED
    elif entropy > 6.5:
        return Fore.YELLOW
    else:
        return Fore.GREEN
