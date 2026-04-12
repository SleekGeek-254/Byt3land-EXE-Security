"""
String analyzer.
Scans for unsafe C/C++ functions and sensitive strings in the binary.
"""

import re
from typing import List

from ..models import UnsafeCFunctionInfo, SensitiveStringInfo, Finding, SeverityLevel
from ..constants import UNSAFE_C_FUNCTIONS, SENSITIVE_STRING_PATTERNS


class StringAnalyzer:
    """
    Analyzer for strings in PE files.
    Detects unsafe C/C++ functions and sensitive data patterns.
    """

    def __init__(self, pe, filepath: str, findings_list: list, verbose: bool = False):
        """
        Initialize string analyzer.
        
        Args:
            pe: Loaded PEFile object
            filepath: Path to PE file
            findings_list: List to append findings to
            verbose: Enable verbose logging
        """
        self.pe = pe
        self.filepath = filepath
        self.findings = findings_list
        self.verbose = verbose

    def log(self, message: str):
        """Log verbose message."""
        if self.verbose:
            print(f"  [DEBUG] {message}")

    def check_unsafe_c_functions(self) -> List[UnsafeCFunctionInfo]:
        """
        Scan the Import Address Table (IAT) for historically unsafe C/C++ runtime functions.
        
        Returns:
            List of UnsafeCFunctionInfo objects
        """
        unsafe_functions = []

        if not self.pe:
            return unsafe_functions

        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                self.log("No imports found - IAT analysis skipped")
                return unsafe_functions

            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else str(entry.dll)

                try:
                    for imp in entry.imports:
                        func_name = ""
                        if imp.name:
                            func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else str(imp.name)
                        else:
                            continue

                        # Check if function is in unsafe list
                        if func_name in UNSAFE_C_FUNCTIONS:
                            unsafe_info = UnsafeCFunctionInfo(
                                function_name=func_name,
                                dll_name=dll_name,
                                reason=UNSAFE_C_FUNCTIONS[func_name]
                            )
                            unsafe_functions.append(unsafe_info)

                except:
                    pass

            # Add findings for unsafe functions
            if unsafe_functions:
                self.findings.append(Finding(
                    category="Unsafe C/C++ Functions",
                    title=f"Found {len(unsafe_functions)} unsafe C/C++ function(s) in IAT",
                    description="Historically unsafe runtime functions detected that may lead to buffer overflows.",
                    severity=str(SeverityLevel.HIGH.value),
                    recommendation="Replace with safe alternatives (e.g., strcpy -> strncpy with proper null-termination)"
                ))

                # Add individual findings for severe functions
                for func in unsafe_functions:
                    if func.function_name in ['gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf']:
                        self.findings.append(Finding(
                            category="Unsafe C/C++ Functions",
                            title=f"Severe: {func.function_name}",
                            description=f"Imported from {func.dll_name}. {func.reason}",
                            severity=str(SeverityLevel.HIGH.value),
                            recommendation=f"Replace {func.function_name} with safe alternative"
                        ))

            else:
                self.log("Import Table looks clean - no unsafe C/C++ functions found")

        except Exception as e:
            self.log(f"Error checking unsafe C functions: {e}")

        return unsafe_functions

    def extract_sensitive_strings(self) -> List[SensitiveStringInfo]:
        """
        Extract potentially sensitive strings from the binary file using regex patterns.
        
        Returns:
            List of SensitiveStringInfo objects
        """
        sensitive_strings = []

        try:
            # Read raw bytes from file
            with open(self.filepath, 'rb') as f:
                data = f.read()

            self.log(f"Extracting sensitive strings from {len(data):,} bytes")

            # Track found strings to avoid duplicates
            seen_strings = {}

            # Pattern: API Keys, connection strings, etc.
            for pattern_name, pattern in SENSITIVE_STRING_PATTERNS.items():
                try:
                    for match in re.finditer(pattern.encode() if isinstance(pattern, str) else pattern, data, re.IGNORECASE):
                        match_bytes = match.group()
                        # Try to decode as UTF-8, fallback to latin-1
                        try:
                            match_str = match_bytes.decode('utf-8', errors='ignore').strip('\x00')
                        except:
                            match_str = match_bytes.decode('latin-1', errors='ignore').strip('\x00')

                        # Filter out very short or obviously non-text matches
                        if len(match_str) < 10:
                            continue

                        # Create unique key for deduplication
                        key = f"{pattern_name}:{match_str[:50]}"
                        if key not in seen_strings:
                            seen_strings[key] = True
                            sensitive_strings.append(SensitiveStringInfo(
                                string_type=pattern_name,
                                value=match_str,
                                offset=match.start()
                            ))

                except Exception as e:
                    self.log(f"Error matching pattern '{pattern_name}': {e}")

            # Remove duplicates by string type and value
            unique_strings = []
            seen = {}
            for s in sensitive_strings:
                key = f"{s.string_type}:{s.value[:100]}"
                if key not in seen:
                    seen[key] = True
                    unique_strings.append(s)

            sensitive_strings = unique_strings

            # Add findings for sensitive strings
            if sensitive_strings:
                # Group by type
                by_type = {}
                for s in sensitive_strings:
                    if s.string_type not in by_type:
                        by_type[s.string_type] = []
                    by_type[s.string_type].append(s)

                # Add findings for each type found
                for string_type, strings in by_type.items():
                    self.findings.append(Finding(
                        category="Sensitive Data",
                        title=f"{string_type}: {len(strings)} occurrence(s)",
                        description="Found potentially sensitive strings in binary. Review if these are legitimate.",
                        severity=str(SeverityLevel.CRITICAL.value) if "Key" in string_type or "Connection" in string_type else str(SeverityLevel.HIGH.value),
                        recommendation="Remove hardcoded credentials and use secure credential management"
                    ))

                self.log(f"Found {len(sensitive_strings)} sensitive strings across {len(by_type)} categories")
            else:
                self.log("No sensitive strings found")

        except Exception as e:
            self.log(f"Error extracting sensitive strings: {e}")

        return sensitive_strings