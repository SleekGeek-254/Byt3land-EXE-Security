"""
Base analyzer class for PE security analysis.
Provides common functionality for all analyzers.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

import sys

try:
    import pefile
except ImportError:
    print("ERROR: pefile library is required. Install it with: pip install pefile")
    sys.exit(1)

from ..models import Finding, MitigationResult
from ..utils import log_message


class BaseAnalyzer(ABC):
    """
    Abstract base class for all PE analyzers.
    Provides common functionality like PE loading and error handling.
    """

    def __init__(self, filepath: str, verbose: bool = False):
        """
        Initialize base analyzer.
        
        Args:
            filepath: Path to PE file
            verbose: Enable verbose logging
        """
        self.filepath = filepath
        self.verbose = verbose
        self.pe = None
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.findings: List[Finding] = []

    def log(self, message: str):
        """Log verbose message."""
        log_message(message, self.verbose)

    def load_pe(self) -> bool:
        """
        Load and parse the PE file.
        
        Returns:
            True if PE loaded successfully, False otherwise
        """
        try:
            self.pe = pefile.PE(self.filepath)
            self.log(f"PE file loaded successfully: {self.filepath}")
            return True
        except pefile.PEFormatError as e:
            self.errors.append(f"Invalid PE file format: {e}")
            return False
        except FileNotFoundError:
            self.errors.append(f"File not found: {self.filepath}")
            return False
        except PermissionError:
            self.errors.append(f"Permission denied: {self.filepath}")
            return False
        except Exception as e:
            self.errors.append(f"Error loading PE file: {e}")
            return False

    def is_pe_loaded(self) -> bool:
        """
        Check if PE file is loaded.
        
        Returns:
            True if PE is loaded, False otherwise
        """
        return self.pe is not None

    def get_findings(self) -> List[Finding]:
        """
        Get all findings generated during analysis.
        
        Returns:
            List of Finding objects
        """
        return self.findings

    def get_errors(self) -> List[str]:
        """
        Get all errors encountered during analysis.
        
        Returns:
            List of error messages
        """
        return self.errors

    def get_warnings(self) -> List[str]:
        """
        Get all warnings generated during analysis.
        
        Returns:
            List of warning messages
        """
        return self.warnings

    @abstractmethod
    def analyze(self):
        """
        Perform the analysis. Must be implemented by subclasses.
        """
        pass