"""
Data models for PE security analysis.
Contains all dataclass definitions for analysis results.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class SeverityLevel(Enum):
    """Security finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a security finding."""
    category: str
    title: str
    description: str
    severity: str
    recommendation: str = ""


@dataclass
class PEInfo:
    """Comprehensive PE file information."""
    filepath: str
    filesize: int
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    architecture: str = ""
    subsystem: str = ""
    compilation_timestamp: str = ""
    entry_point: str = ""
    image_base: str = ""
    section_count: int = 0
    import_count: int = 0
    export_count: int = 0
    resource_count: int = 0
    is_dll: bool = False
    is_signed: bool = False
    is_stripped: bool = False


@dataclass
class MitigationResult:
    """Security mitigation check result."""
    name: str
    passed: Optional[bool]
    message: str
    flag_value: int = 0
    recommendation: str = ""


@dataclass
class ImportInfo:
    """DLL import information."""
    dll_name: str
    functions: List[str]
    is_local: bool = False
    is_suspicious: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)


@dataclass
class ExportInfo:
    """DLL export information."""
    function_name: str
    ordinal: int
    address: int


@dataclass
class DelayLoadImportInfo:
    """Delay load import information."""
    dll_name: str
    attributes: int
    module_handle_rva: int
    import_address_table_rva: int
    import_name_table_rva: int
    bound_import_address_table_rva: int
    unload_information_table_rva: int
    time_date_stamp: int
    functions: List[str] = field(default_factory=list)


@dataclass
class BoundImportInfo:
    """Bound import information."""
    dll_name: str
    time_date_stamp: int
    offset_module_name: int
    number_of_module_forwarder_refs: int


@dataclass
class ImportHashInfo:
    """Import hash (imphash) information."""
    imphash: str
    algorithm: str = "pefile"
    description: str = "Fingerprint of imported functions for malware identification"


@dataclass
class ExportAnomalyInfo:
    """Export function anomaly information."""
    function_name: str
    ordinal: int
    address: int
    anomaly_type: str
    description: str
    severity: str = "LOW"


@dataclass
class ImportOrdinalInfo:
    """Import ordinal usage information."""
    dll_name: str
    total_imports: int
    ordinal_imports: int
    ordinal_percentage: float
    ordinal_details: List[tuple] = field(default_factory=list)  # (ordinal, hint, name)


@dataclass
class SectionInfo:
    """Section information."""
    name: str
    virtual_address: str
    virtual_size: str
    raw_size: str
    characteristics: str
    entropy: float
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = True
    is_suspicious: bool = False
    suspicion_reason: str = ""


@dataclass
class UnsafeCFunctionInfo:
    """Information about unsafe C/C++ runtime function."""
    function_name: str
    dll_name: str
    reason: str


@dataclass
class SensitiveStringInfo:
    """Information about sensitive string found in binary."""
    string_type: str
    value: str
    offset: int


@dataclass
class CertificateInfo:
    """Digital certificate information."""
    issuer: str = ""
    subject: str = ""
    thumbprint: str = ""
    valid_from: str = ""
    valid_to: str = ""
    is_valid: bool = False
    is_expired: bool = False
    is_self_signed: bool = False
    timestamp_server: str = ""
    company_name: str = ""


@dataclass
class VersionInfo:
    """Version information from PE resources."""
    file_version: str = ""
    product_version: str = ""
    company_name: str = ""
    product_name: str = ""
    copyright: str = ""
    original_filename: str = ""
    internal_name: str = ""
    file_description: str = ""
    trademark: str = ""
    private_build: str = ""
    special_build: str = ""
    comments: str = ""


@dataclass
class IconInfo:
    """Information about extracted icon."""
    index: int = 0
    width: int = 0
    height: int = 0
    bit_depth: int = 0
    size_bytes: int = 0
    data: bytes = b""


@dataclass
class ManifestInfo:
    """Application manifest information."""
    execution_level: str = ""
    ui_access: bool = False
    requested_execution_level: str = ""
    compatibility_modes: List[str] = field(default_factory=list)
    is_manifest_embedded: bool = False
    manifest_xml: str = ""


@dataclass
class LoadConfigInfo:
    """Load configuration directory information."""
    security_cookie_enabled: bool = False
    security_cookie_address: int = 0
    seh_handler_count: int = 0
    seh_handler_table_address: int = 0
    guard_cf_enabled: bool = False
    guard_flags: int = 0
    guard_cf_check_function_pointer: int = 0
    guard_cf_function_table_count: int = 0
    guard_cf_function_table_address: int = 0
    guard_export_suppression_enabled: bool = False
    guard_export_suppression_table_count: int = 0
    process_heap_flags: int = 0
    heap_protection_enabled: bool = False


@dataclass
class SectionEntropyInfo:
    """Detailed entropy information for a section."""
    section_name: str
    entropy: float
    entropy_per_block: List[float]
    block_size: int
    num_blocks: int
    high_entropy_blocks: int
    average_entropy: float


@dataclass
class PackerSignatureInfo:
    """Known packer signature information."""
    packer_name: str
    signature: str
    confidence: str
    description: str


@dataclass
class OverlayInfo:
    """Overlay (data appended after PE structure) information."""
    has_overlay: bool
    offset: int
    size: int
    entropy: float
    likely_type: str


@dataclass
class ResourceAnomalyInfo:
    """Resource section anomaly information."""
    anomaly_type: str
    description: str
    resource_type: str
    details: str
    severity: str = "MEDIUM"


@dataclass
class PackerAnalysisInfo:
    """Comprehensive packer analysis results."""
    is_packed: bool
    packer_name: str
    packer_confidence: str
    total_entropy: float
    high_entropy_sections: List[str]
    entropy_distribution: List[SectionEntropyInfo]
    packer_signatures: List[PackerSignatureInfo]
    overlay: OverlayInfo
    resource_anomalies: List[ResourceAnomalyInfo]
    packer_indicators: List[str]


@dataclass
class AnalysisReport:
    """Complete analysis report."""
    pe_info: Dict[str, Any]
    mitigations: List[Dict[str, Any]]
    imports: List[Dict[str, Any]]
    exports: List[Dict[str, Any]]
    sections: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    summary: Dict[str, Any]
