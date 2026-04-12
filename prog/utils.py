"""
Utility functions for PE security analysis.
Contains helper functions for hashing, entropy calculation, and file operations.
"""

import hashlib
from collections import Counter
from typing import Dict


def calculate_hashes(filepath: str) -> Dict[str, str]:
    """
    Calculate file hashes (MD5, SHA1, SHA256).
    
    Args:
        filepath: Path to the file to hash
        
    Returns:
        Dictionary with 'md5', 'sha1', and 'sha256' keys
    """
    hashes = {'md5': '', 'sha1': '', 'sha256': ''}
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        print(f"Error calculating hashes: {e}")
    return hashes


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    
    Args:
        data: Bytes to calculate entropy for
        
    Returns:
        Entropy value (0-8 scale)
    """
    if not data:
        return 0.0
    
    import math
    
    # Count byte frequencies
    counter = Counter(data)
    entropy = 0.0
    length = len(data)
    
    # Calculate Shannon entropy: H = -sum(p(x) * log2(p(x)))
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy  # Already in 0-8 scale (8 bits max)


def log_message(message: str, verbose: bool = False):
    """
    Print verbose message if verbose mode is enabled.
    
    Args:
        message: Message to log
        verbose: Whether to print the message
    """
    if verbose:
        print(f"  [DEBUG] {message}")