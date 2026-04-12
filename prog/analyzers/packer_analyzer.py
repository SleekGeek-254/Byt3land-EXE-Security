"""
Packer & Obfuscation analyzer.
Detects packed binaries, known packers, and obfuscation techniques.
"""

import os
import re
import struct
from typing import List, Tuple, Optional
from dataclasses import asdict

from ..models import (
    SectionEntropyInfo,
    PackerSignatureInfo,
    OverlayInfo,
    ResourceAnomalyInfo,
    PackerAnalysisInfo,
    Finding,
    SeverityLevel
)
from ..utils import calculate_entropy


class PackerAnalyzer:
    """
    Analyzer for packer and obfuscation detection.
    Performs comprehensive packer analysis including entropy analysis,
    signature detection, overlay detection, and resource anomalies.
    """

    # Known packer signatures (byte patterns)
    PACKER_SIGNATURES = {
        'UPX': [
            b'UPX!',
            b'UPX0',
            b'UPX1',
            b'UPX2',
            b'UPX3'
        ],
        'Themida': [
            b'Themida',
            b'WinLicence'
        ],
        'VMProtect': [
            b'VMProtect',
            b'.vmp0',
            b'.vmp1',
            b'.vmp2'
        ],
        'ASPack': [
            b'ASPack',
            b'.aspack'
        ],
        'PECompact': [
            b'PECompact',
            b'PECompact2',
            b'PECompact3'
        ],
        'Armadillo': [
            b'Armadillo',
            b'Silicone'
        ],
        'NSPack': [
            b'NSPack',
            b'nspack'
        ],
        'FSG': [
            b'FSG',
            b'.fsg'
        ],
        'MEW': [
            b'MEW',
            b'.mew'
        ],
        'PEtite': [
            b'PEtite',
            b'.petite'
        ],
        'PELock': [
            b'PELock',
            b'PELockNT'
        ],
        'DotNetZ': [
            b'DotNetZ',
            b'.NETZ'
        ],
        'Obsidium': [
            b'Obsidium'
        ],
        'Enigma': [
            b'Enigma',
            b'Enigma VB'
        ],
        'Telock': [
            b'Telock'
        ],
        'YodaCrypt': [
            b'Yoda',
            b'YodaCrypt'
        ],
        'WinUpack': [
            b'WinUpack'
        ],
        'RLPack': [
            b'RLPack'
        ],
        'EXE32Pack': [
            b'EXE32Pack'
        ],
        'PESpin': [
            b'PESpin',
            b'PESpin0'
        ],
        'ASProtect': [
            b'ASProtect',
            b'ASProtect 2'
        ]
    }

    # Packer section names
    PACKER_SECTION_NAMES = [
        'upx', 'aspack', 'pecompact', 'fsg', 'mew', 'petite',
        'themida', 'vmprotect', 'nspack', 'pelock', 'obsidium',
        'enigma', 'telock', 'yoda', 'winupack', 'rlpack', 'pespin',
        'asprotect', 'mpress', 'kkrunchy'
    ]

    # Suspicious section name patterns
    SUSPICIOUS_SECTION_PATTERNS = [
        r'\.[0-9]+$',  # Sections like .0, .1, .2
        r'^p[a-z]*$',  # Sections starting with 'p'
        r'^v[a-z]*$',  # Sections starting with 'v'
        r'^\.vmp',    # VMProtect sections
        r'^\.themida', # Themida sections
        r'^\.enigma',  # Enigma sections
        r'^\.aspack',  # ASPack sections
    ]

    def __init__(self, pe, filepath: str, findings_list: list, verbose: bool = False):
        """
        Initialize packer analyzer.
        
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
            print(f"  [PackerAnalyzer] {message}")

    def analyze_packer(self) -> PackerAnalysisInfo:
        """
        Perform comprehensive packer analysis.
        
        Returns:
            PackerAnalysisInfo object with all packer detection results
        """
        self.log("Starting packer analysis...")
        
        # Analyze entropy distribution
        entropy_distribution = self.analyze_entropy_distribution()
        
        # Check for packer signatures
        packer_signatures = self.check_packer_signatures()
        
        # Detect overlay
        overlay = self.detect_overlay()
        
        # Check resource anomalies
        resource_anomalies = self.check_resource_anomalies()
        
        # Collect all packer indicators
        packer_indicators = self._collect_packer_indicators(
            entropy_distribution,
            packer_signatures,
            overlay,
            resource_anomalies
        )
        
        # Determine if packed and identify packer
        is_packed, packer_name, packer_confidence = self._determine_packer(
            entropy_distribution,
            packer_signatures,
            overlay,
            resource_anomalies
        )
        
        # Calculate total entropy
        total_entropy = self._calculate_total_entropy(entropy_distribution)
        
        # Identify high entropy sections
        high_entropy_sections = [
            e.section_name for e in entropy_distribution 
            if e.average_entropy > 6.5
        ]
        
        result = PackerAnalysisInfo(
            is_packed=is_packed,
            packer_name=packer_name,
            packer_confidence=packer_confidence,
            total_entropy=round(total_entropy, 2),
            high_entropy_sections=high_entropy_sections,
            entropy_distribution=entropy_distribution,
            packer_signatures=packer_signatures,
            overlay=overlay,
            resource_anomalies=resource_anomalies,
            packer_indicators=packer_indicators
        )
        
        self.log(f"Packer analysis completed. Packed: {is_packed}, Packer: {packer_name}")
        
        # Add findings
        self._add_findings(result)
        
        return result

    def analyze_entropy_distribution(self, block_size: int = 4096) -> List[SectionEntropyInfo]:
        """
        Analyze entropy distribution per section in blocks.
        
        Args:
            block_size: Size of each block for entropy calculation (default: 4KB)
            
        Returns:
            List of SectionEntropyInfo objects
        """
        self.log("Analyzing entropy distribution...")
        entropy_results = []
        
        if not self.pe:
            return entropy_results
        
        try:
            for section in self.pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                
                try:
                    # Get section data
                    section_data = self.pe.get_data(
                        section.PointerToRawData, 
                        section.SizeOfRawData
                    )
                    
                    if not section_data:
                        continue
                    
                    # Calculate entropy per block
                    num_blocks = max(1, len(section_data) // block_size)
                    entropy_per_block = []
                    high_entropy_blocks = 0
                    
                    for i in range(num_blocks):
                        start = i * block_size
                        end = start + block_size
                        block_data = section_data[start:end]
                        
                        if block_data:
                            block_entropy = calculate_entropy(block_data)
                            entropy_per_block.append(block_entropy)
                            
                            if block_entropy > 6.5:
                                high_entropy_blocks += 1
                    
                    # Calculate overall section entropy
                    overall_entropy = calculate_entropy(section_data)
                    
                    # Calculate average block entropy
                    avg_entropy = sum(entropy_per_block) / len(entropy_per_block) if entropy_per_block else 0
                    
                    entropy_info = SectionEntropyInfo(
                        section_name=section_name,
                        entropy=round(overall_entropy, 2),
                        entropy_per_block=[round(e, 2) for e in entropy_per_block],
                        block_size=block_size,
                        num_blocks=num_blocks,
                        high_entropy_blocks=high_entropy_blocks,
                        average_entropy=round(avg_entropy, 2)
                    )
                    
                    entropy_results.append(entropy_info)
                    
                except Exception as e:
                    self.log(f"Error analyzing entropy for section {section_name}: {e}")
                    
        except Exception as e:
            self.log(f"Error in entropy distribution analysis: {e}")
        
        return entropy_results

    def check_packer_signatures(self) -> List[PackerSignatureInfo]:
        """
        Check for known packer signatures in the binary.
        
        Returns:
            List of PackerSignatureInfo objects
        """
        self.log("Checking for packer signatures...")
        signatures_found = []
        
        if not self.pe:
            return signatures_found
        
        try:
            # Read the entire file
            with open(self.filepath, 'rb') as f:
                file_data = f.read()
            
            # Check for each packer signature
            for packer_name, signatures in self.PACKER_SIGNATURES.items():
                for signature in signatures:
                    if signature in file_data:
                        # Calculate confidence based on match
                        confidence = self._calculate_signature_confidence(packer_name, file_data)
                        
                        sig_info = PackerSignatureInfo(
                            packer_name=packer_name,
                            signature=signature.decode('utf-8', errors='ignore'),
                            confidence=confidence,
                            description=f"Detected {packer_name} packer signature"
                        )
                        
                        signatures_found.append(sig_info)
                        self.log(f"Found {packer_name} signature: {signature}")
                        
                        # Don't add duplicate packer names
                        break
                        
        except Exception as e:
            self.log(f"Error checking packer signatures: {e}")
        
        return signatures_found

    def _calculate_signature_confidence(self, packer_name: str, file_data: bytes) -> str:
        """
        Calculate confidence level for packer detection.
        
        Args:
            packer_name: Name of the packer
            file_data: File binary data
            
        Returns:
            Confidence string (High, Medium, Low)
        """
        confidence = "Medium"
        
        try:
            # Count occurrences
            signatures = self.PACKER_SIGNATURES.get(packer_name, [])
            total_matches = 0
            
            for sig in signatures:
                total_matches += file_data.count(sig)
            
            # Check section names
            if self.pe:
                section_names = [
                    s.Name.decode('utf-8', errors='ignore').rstrip('\x00').lower()
                    for s in self.pe.sections
                ]
                
                if any(packer_name.lower() in name for name in section_names):
                    confidence = "High"
            
            # High confidence if multiple signatures found
            if total_matches > 2:
                confidence = "High"
            elif total_matches == 1:
                confidence = "Medium"
            else:
                confidence = "Low"
                
        except Exception as e:
            self.log(f"Error calculating signature confidence: {e}")
        
        return confidence

    def detect_overlay(self) -> OverlayInfo:
        """
        Detect overlay data (data appended after PE structure).
        
        Returns:
            OverlayInfo object with overlay details
        """
        self.log("Detecting overlay...")
        
        overlay_info = OverlayInfo(
            has_overlay=False,
            offset=0,
            size=0,
            entropy=0.0,
            likely_type="None"
        )
        
        if not self.pe:
            return overlay_info
        
        try:
            # Get the file size
            file_size = os.path.getsize(self.filepath)
            
            # Calculate the end of PE structure
            if hasattr(self.pe, 'OPTIONAL_HEADER'):
                # Find the last section
                last_section = None
                last_end = 0
                
                for section in self.pe.sections:
                    section_end = section.PointerToRawData + section.SizeOfRawData
                    if section_end > last_end:
                        last_end = section_end
                        last_section = section
                
                # Check if there's data after the last section
                if last_end < file_size:
                    overlay_size = file_size - last_end
                    
                    # Read overlay data
                    with open(self.filepath, 'rb') as f:
                        f.seek(last_end)
                        overlay_data = f.read(overlay_size)
                    
                    # Calculate overlay entropy
                    overlay_entropy = calculate_entropy(overlay_data)
                    
                    # Determine likely type
                    likely_type = self._classify_overlay(overlay_data, overlay_entropy)
                    
                    overlay_info = OverlayInfo(
                        has_overlay=True,
                        offset=last_end,
                        size=overlay_size,
                        entropy=round(overlay_entropy, 2),
                        likely_type=likely_type
                    )
                    
                    self.log(f"Overlay detected: {overlay_size} bytes at offset {last_end}")
                    
        except Exception as e:
            self.log(f"Error detecting overlay: {e}")
        
        return overlay_info

    def _classify_overlay(self, overlay_data: bytes, entropy: float) -> str:
        """
        Classify overlay data based on content and entropy.
        
        Args:
            overlay_data: Overlay binary data
            entropy: Calculated entropy
            
        Returns:
            Likely type string
        """
        if entropy > 7.0:
            return "Encrypted or Compressed"
        elif overlay_data.startswith(b'PK\x03\x04'):
            return "ZIP Archive"
        elif overlay_data.startswith(b'Rar!'):
            return "RAR Archive"
        elif b'<html' in overlay_data.lower()[:100] or b'<body' in overlay_data.lower()[:100]:
            return "HTML Content"
        elif b'%PDF' in overlay_data[:4]:
            return "PDF Document"
        elif len(overlay_data) < 100:
            return "Small Data"
        else:
            return "Unknown Data"

    def check_resource_anomalies(self) -> List[ResourceAnomalyInfo]:
        """
        Check for anomalies in the resource section.
        
        Returns:
            List of ResourceAnomalyInfo objects
        """
        self.log("Checking for resource anomalies...")
        anomalies = []
        
        if not self.pe:
            return anomalies
        
        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                return anomalies
            
            # Analyze resource sections
            for section in self.pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                
                if section_name == '.rsrc':
                    # Get resource section data
                    try:
                        section_data = self.pe.get_data(
                            section.PointerToRawData,
                            section.SizeOfRawData
                        )
                        
                        # Calculate resource section entropy
                        resource_entropy = calculate_entropy(section_data)
                        
                        # Check for suspicious resource entropy
                        if resource_entropy > 6.5:
                            anomaly = ResourceAnomalyInfo(
                                anomaly_type="High Entropy",
                                description=f"Resource section has high entropy ({resource_entropy:.2f})",
                                resource_type=".rsrc",
                                details=f"Entropy: {resource_entropy:.2f} suggests packed or encrypted resources",
                                severity="HIGH"
                            )
                            anomalies.append(anomaly)
                            self.log(f"High entropy resource section detected: {resource_entropy:.2f}")
                        
                        # Check for unusually large resources
                        if section.SizeOfRawData > 10 * 1024 * 1024:  # > 10MB
                            anomaly = ResourceAnomalyInfo(
                                anomaly_type="Large Resource",
                                description=f"Resource section is unusually large ({section.SizeOfRawData / 1024 / 1024:.2f} MB)",
                                resource_type=".rsrc",
                                details=f"Size: {section.SizeOfRawData} bytes",
                                severity="MEDIUM"
                            )
                            anomalies.append(anomaly)
                            self.log(f"Large resource section detected: {section.SizeOfRawData} bytes")
                        
                        # Check for suspicious resource types
                        suspicious_resources = self._check_suspicious_resource_types()
                        anomalies.extend(suspicious_resources)
                        
                    except Exception as e:
                        self.log(f"Error analyzing resource section: {e}")
                    
                    break
                    
        except Exception as e:
            self.log(f"Error checking resource anomalies: {e}")
        
        return anomalies

    def _check_suspicious_resource_types(self) -> List[ResourceAnomalyInfo]:
        """
        Check for suspicious resource types.
        
        Returns:
            List of ResourceAnomalyInfo objects
        """
        anomalies = []
        
        try:
            # Known suspicious resource types used by packers/malware
            suspicious_types = {
                'RT_RCDATA': 'Raw data often used by packers',
                'RT_BITMAP': 'Large bitmaps may hide payloads',
                'RT_ICON': 'Icons may contain embedded payloads',
                'RT_VERSION': 'Version info may be fake in packed binaries'
            }
            
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        if hasattr(entry, 'directory'):
                            for sub_entry in entry.directory.entries:
                                # Check for suspicious resource characteristics
                                if hasattr(sub_entry, 'directory'):
                                    for resource_entry in sub_entry.directory.entries:
                                        if hasattr(resource_entry.data.struct, 'Size'):
                                            size = resource_entry.data.struct.Size
                                            
                                            # Very large resources are suspicious
                                            if size > 5 * 1024 * 1024:  # > 5MB
                                                res_type = str(entry.id) if hasattr(entry, 'id') else str(entry.name)
                                                anomaly = ResourceAnomalyInfo(
                                                    anomaly_type="Large Resource Entry",
                                                    description=f"Resource {res_type} is very large ({size / 1024 / 1024:.2f} MB)",
                                                    resource_type=res_type,
                                                    details=f"Size: {size} bytes",
                                                    severity="MEDIUM"
                                                )
                                                anomalies.append(anomaly)
                                                self.log(f"Large resource entry detected: {res_type}")
                                            
                    except Exception as e:
                        self.log(f"Error checking resource type: {e}")
                        
        except Exception as e:
            self.log(f"Error checking suspicious resource types: {e}")
        
        return anomalies

    def _collect_packer_indicators(
        self,
        entropy_distribution: List[SectionEntropyInfo],
        packer_signatures: List[PackerSignatureInfo],
        overlay: OverlayInfo,
        resource_anomalies: List[ResourceAnomalyInfo]
    ) -> List[str]:
        """
        Collect all packer indicators.
        
        Args:
            entropy_distribution: Entropy analysis results
            packer_signatures: Packer signatures found
            overlay: Overlay information
            resource_anomalies: Resource anomalies found
            
        Returns:
            List of indicator strings
        """
        indicators = []
        
        # Entropy indicators
        high_entropy_sections = [
            e.section_name for e in entropy_distribution 
            if e.average_entropy > 6.5
        ]
        if high_entropy_sections:
            indicators.append(f"High entropy sections: {', '.join(high_entropy_sections)}")
        
        # Packer signature indicators
        if packer_signatures:
            packer_names = list(set(s.packer_name for s in packer_signatures))
            indicators.append(f"Packer signatures detected: {', '.join(packer_names)}")
        
        # Overlay indicators
        if overlay.has_overlay:
            if overlay.entropy > 7.0:
                indicators.append(f"High entropy overlay detected (entropy: {overlay.entropy:.2f})")
            else:
                indicators.append(f"Overlay detected (type: {overlay.likely_type})")
        
        # Resource anomaly indicators
        if resource_anomalies:
            for anomaly in resource_anomalies:
                indicators.append(f"Resource anomaly: {anomaly.anomaly_type}")
        
        # Section name indicators
        if self.pe:
            section_names = [
                s.Name.decode('utf-8', errors='ignore').rstrip('\x00').lower()
                for s in self.pe.sections
            ]
            suspicious_found = []
            for pattern in self.SUSPICIOUS_SECTION_PATTERNS:
                for name in section_names:
                    if re.match(pattern, name):
                        suspicious_found.append(name)
            
            if suspicious_found:
                indicators.append(f"Suspicious section names: {', '.join(set(suspicious_found))}")
        
        return indicators

    def _determine_packer(
        self,
        entropy_distribution: List[SectionEntropyInfo],
        packer_signatures: List[PackerSignatureInfo],
        overlay: OverlayInfo,
        resource_anomalies: List[ResourceAnomalyInfo]
    ) -> Tuple[bool, str, str]:
        """
        Determine if binary is packed and identify packer.
        
        Args:
            entropy_distribution: Entropy analysis results
            packer_signatures: Packer signatures found
            overlay: Overlay information
            resource_anomalies: Resource anomalies found
            
        Returns:
            Tuple of (is_packed, packer_name, confidence)
        """
        is_packed = False
        packer_name = "Unknown"
        confidence = "Low"
        
        # High confidence: Packer signatures found
        if packer_signatures:
            is_packed = True
            # Get packer name with highest confidence
            high_conf_sigs = [s for s in packer_signatures if s.confidence == "High"]
            if high_conf_sigs:
                packer_name = high_conf_sigs[0].packer_name
                confidence = "High"
            else:
                packer_name = packer_signatures[0].packer_name
                confidence = "Medium"
        else:
            # No signatures, use heuristic analysis
            
            # Check for high entropy sections
            high_entropy_count = sum(1 for e in entropy_distribution if e.average_entropy > 6.5)
            
            # Check for suspicious section names
            if self.pe:
                section_names = [
                    s.Name.decode('utf-8', errors='ignore').rstrip('\x00').lower()
                    for s in self.pe.sections
                ]
                has_suspicious_name = any(
                    any(packer in name for name in section_names for packer in self.PACKER_SECTION_NAMES)
                    for name in section_names
                )
                
                if has_suspicious_name:
                    # Find which packer name is in section names
                    for packer in self.PACKER_SECTION_NAMES:
                        for name in section_names:
                            if packer in name:
                                packer_name = packer.upper()
                                break
            
            # Determine based on indicators
            if high_entropy_count >= 2 or overlay.entropy > 7.5:
                is_packed = True
                confidence = "Medium"
            elif high_entropy_count == 1 or len(resource_anomalies) > 0:
                is_packed = True
                confidence = "Low"
            
            # Adjust confidence based on section names
            if packer_name != "Unknown":
                is_packed = True
                confidence = "Medium"
        
        return is_packed, packer_name, confidence

    def _calculate_total_entropy(self, entropy_distribution: List[SectionEntropyInfo]) -> float:
        """
        Calculate total file entropy based on section entropies.
        
        Args:
            entropy_distribution: Entropy analysis results
            
        Returns:
            Total entropy value
        """
        if not entropy_distribution:
            return 0.0
        
        # Weighted average of section entropies
        total = 0.0
        count = 0
        
        for e in entropy_distribution:
            total += e.entropy
            count += 1
        
        return total / count if count > 0 else 0.0

    def _add_findings(self, packer_info: PackerAnalysisInfo):
        """
        Add security findings based on packer analysis.
        
        Args:
            packer_info: Packer analysis results
        """
        if packer_info.is_packed:
            self.findings.append(Finding(
                category="Packing",
                title="Binary is Packed or Obfuscated",
                description=f"Detected packer: {packer_info.packer_name} (Confidence: {packer_info.packer_confidence})",
                severity=str(SeverityLevel.HIGH.value),
                recommendation="Unpack the binary to analyze its true contents"
            ))
        
        if packer_info.total_entropy > 6.5:
            self.findings.append(Finding(
                category="Packing",
                title="High Total File Entropy",
                description=f"Total file entropy: {packer_info.total_entropy:.2f} (threshold: 6.5)",
                severity=str(SeverityLevel.MEDIUM.value),
                recommendation="High entropy may indicate packing, encryption, or compression"
            ))
        
        if packer_info.overlay.has_overlay:
            severity = SeverityLevel.MEDIUM.value
            if packer_info.overlay.entropy > 7.0:
                severity = SeverityLevel.HIGH.value
            
            self.findings.append(Finding(
                category="Packing",
                title="Overlay Detected",
                description=f"Overlay of {packer_info.overlay.size} bytes found (type: {packer_info.overlay.likely_type})",
                severity=str(severity),
                recommendation="Extract and analyze overlay data"
            ))
        
        for anomaly in packer_info.resource_anomalies:
            self.findings.append(Finding(
                category="Packing",
                title=f"Resource Anomaly: {anomaly.anomaly_type}",
                description=anomaly.description,
                severity=anomaly.severity,
                recommendation="Investigate suspicious resources"
            ))