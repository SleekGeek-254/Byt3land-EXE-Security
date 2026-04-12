"""
Section analyzer.
Analyzes PE sections for suspicious characteristics, entropy, and permissions.
"""

from typing import List

from ..models import SectionInfo, Finding, SeverityLevel
from ..utils import calculate_entropy


class SectionAnalyzer:
    """
    Analyzer for PE sections.
    Detects high entropy sections, W+X violations, and suspicious section names.
    """

    def __init__(self, pe, findings_list: list, verbose: bool = False):
        """
        Initialize section analyzer.
        
        Args:
            pe: Loaded PEFile object
            findings_list: List to append findings to
            verbose: Enable verbose logging
        """
        self.pe = pe
        self.findings = findings_list
        self.verbose = verbose

    def log(self, message: str):
        """Log verbose message."""
        if self.verbose:
            print(f"  [DEBUG] {message}")

    def get_sections(self) -> List[SectionInfo]:
        """
        Analyze PE sections for suspicious characteristics.
        
        Returns:
            List of SectionInfo objects
        """
        sections = []

        if not self.pe:
            return sections

        try:
            for section in self.pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')

                # Calculate entropy
                try:
                    section_data = self.pe.get_data(section.PointerToRawData, section.SizeOfRawData)
                    entropy = calculate_entropy(section_data)
                except:
                    entropy = 0.0

                # Parse characteristics
                chars = section.Characteristics
                is_executable = bool(chars & 0x20000000)
                is_writable = bool(chars & 0x80000000)
                is_readable = bool(chars & 0x40000000)

                # Check for suspicious characteristics
                is_suspicious = False
                suspicion_reason = ""

                # Packed section detection
                if entropy > 6.5 and name not in ['.rsrc', '.reloc']:
                    is_suspicious = True
                    suspicion_reason = f"High entropy ({entropy:.2f}) suggests packing/encryption"

                # Writable + Executable
                if is_writable and is_executable:
                    is_suspicious = True
                    suspicion_reason = "Section is both writable and executable (W^X violation)"

                # Unusual section names
                suspicious_names = ['.upack', '.aspack', '.petite', '.pec1', 'vmp', 'themida', 'upx']
                if any(sn in name.lower() for sn in suspicious_names):
                    is_suspicious = True
                    suspicion_reason = f"Section name '{name}' suggests known packer"

                section_info = SectionInfo(
                    name=name,
                    virtual_address=f"0x{section.VirtualAddress:08X}",
                    virtual_size=f"0x{section.Misc_VirtualSize:08X}",
                    raw_size=f"0x{section.SizeOfRawData:08X}",
                    characteristics=f"0x{chars:08X}",
                    entropy=round(entropy, 2),
                    is_executable=is_executable,
                    is_writable=is_writable,
                    is_readable=is_readable,
                    is_suspicious=is_suspicious,
                    suspicion_reason=suspicion_reason
                )

                sections.append(section_info)

                # Add findings
                if entropy > 7.0:
                    self.findings.append(Finding(
                        category="Packing",
                        title=f"High Entropy Section: {name}",
                        description=f"Section entropy of {entropy:.2f} suggests encryption or packing",
                        severity=str(SeverityLevel.MEDIUM.value),
                        recommendation="Investigate if packing is legitimate"
                    ))

                if is_writable and is_executable:
                    self.findings.append(Finding(
                        category="Code Integrity",
                        title=f"W+X Section: {name}",
                        description="Section allows both writing and executing code",
                        severity=str(SeverityLevel.HIGH.value),
                        recommendation="Separate code and data sections (W^X principle)"
                    ))

        except Exception as e:
            self.log(f"Error analyzing sections: {e}")

        return sections