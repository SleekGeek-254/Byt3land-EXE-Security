#!/usr/bin/env python3
"""
Byt3land PE Security Analyzer - Standalone Entry Point
Comprehensive Windows PE (.exe) file security analysis tool.

Author: Byt3land Security Team
Version: 2.0.0

Usage: python byt3land_pe_security_analyzer.py <file.exe>
"""

import sys
import os

# Add the package directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

# Import and run the main module
from prog.main import main

if __name__ == '__main__':
    main()