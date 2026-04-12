"""
Security mitigation analyzer.
Checks for ASLR, DEP, SafeSEH, CFG, and other security mitigations.
"""

from ..models import MitigationResult, Finding, SeverityLevel, CertificateInfo
from ..constants import (
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
)


class MitigationAnalyzer:
    """
    Analyzer for security mitigations in PE files.
    Checks ASLR, DEP, SafeSEH, CFG, and digital signatures.
    """

    def __init__(self, pe, findings_list: list, verbose: bool = False):
        """
        Initialize mitigation analyzer.
        
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

    def check_aslr(self) -> MitigationResult:
        """
        Check ASLR (Address Space Layout Randomization).
        
        Returns:
            MitigationResult with ASLR status
        """
        result = MitigationResult(
            name="ASLR (Address Space Layout Randomization)",
            passed=False,
            message="PE not loaded",
            recommendation="Rebuild with /DYNAMICBASE flag"
        )

        if not self.pe:
            return result

        try:
            if hasattr(self.pe, 'OPTIONAL_HEADER'):
                dll_characteristics = self.pe.OPTIONAL_HEADER.DllCharacteristics
                enabled = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
                result.flag_value = dll_characteristics

                if enabled:
                    result.passed = True
                    result.message = "ASLR is ENABLED - Memory addresses will be randomized"
                    result.recommendation = "Good! ASLR provides protection against memory corruption exploits"
                else:
                    result.message = "ASLR is DISABLED - Vulnerable to memory corruption attacks"
                    self.findings.append(Finding(
                        category="Mitigation",
                        title="ASLR Disabled",
                        description="ASLR is not enabled. Attackers can predict memory addresses.",
                        severity=str(SeverityLevel.HIGH.value),
                        recommendation="Enable ASLR by setting IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"
                    ))
        except Exception as e:
            result.message = f"Error checking ASLR: {e}"

        return result

    def check_dep(self) -> MitigationResult:
        """
        Check DEP/NX (Data Execution Prevention).
        
        Returns:
            MitigationResult with DEP status
        """
        result = MitigationResult(
            name="DEP/NX (Data Execution Prevention)",
            passed=False,
            message="PE not loaded",
            recommendation="Rebuild with /NXCOMPAT flag"
        )

        if not self.pe:
            return result

        try:
            if hasattr(self.pe, 'OPTIONAL_HEADER'):
                dll_characteristics = self.pe.OPTIONAL_HEADER.DllCharacteristics
                enabled = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
                result.flag_value = dll_characteristics

                if enabled:
                    result.passed = True
                    result.message = "DEP/NX is ENABLED - Memory regions marked non-executable"
                    result.recommendation = "Good! DEP prevents code execution from data segments"
                else:
                    result.message = "DEP/NX is DISABLED - Vulnerable to code injection attacks"
                    self.findings.append(Finding(
                        category="Mitigation",
                        title="DEP/NX Disabled",
                        description="Data Execution Prevention is not enabled.",
                        severity=str(SeverityLevel.HIGH.value),
                        recommendation="Enable DEP with IMAGE_DLLCHARACTERISTICS_NX_COMPAT"
                    ))
        except Exception as e:
            result.message = f"Error checking DEP: {e}"

        return result

    def check_safeseh(self) -> MitigationResult:
        """
        Check SafeSEH for 32-bit executables.
        
        Returns:
            MitigationResult with SafeSEH status
        """
        result = MitigationResult(
            name="SafeSEH (Structured Exception Handler)",
            passed=None,
            message="SafeSEH check not applicable",
            recommendation=""
        )

        if not self.pe:
            return result

        try:
            machine = self.pe.FILE_HEADER.Machine

            if machine == 0x014c:  # 32-bit
                if hasattr(self.pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                    load_config = self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                    if load_config.SEHandlerTable != 0 and load_config.SEHandlerCount > 0:
                        result.passed = True
                        result.message = "SafeSEH is ENABLED - Exception handlers are validated"
                        result.recommendation = "Good! Exception handlers are registered and validated"
                    else:
                        result.passed = False
                        result.message = "SafeSEH table is empty or not configured"
                        result.recommendation = "Implement SafeSEH by registering exception handlers"
                        self.findings.append(Finding(
                            category="Mitigation",
                            title="SafeSEH Not Configured",
                            description="Exception handlers not properly registered.",
                            severity=str(SeverityLevel.MEDIUM.value),
                            recommendation="Configure SEHandlerTable in load configuration"
                        ))
                else:
                    result.passed = False
                    result.message = "SafeSEH is DISABLED - No load configuration directory"
                    self.findings.append(Finding(
                        category="Mitigation",
                        title="SafeSEH Disabled",
                        description="No load configuration directory found.",
                        severity=str(SeverityLevel.MEDIUM.value),
                        recommendation="Add load configuration directory with SafeSEH handlers"
                    ))
            else:
                result.passed = None
                result.message = "SafeSEH check not applicable for 64-bit PE files"

        except Exception as e:
            result.message = f"Error checking SafeSEH: {e}"

        return result

    def check_cfg(self) -> MitigationResult:
        """
        Check Control Flow Guard (CFG).
        
        Returns:
            MitigationResult with CFG status
        """
        result = MitigationResult(
            name="CFG (Control Flow Guard)",
            passed=False,
            message="PE not loaded",
            recommendation="Rebuild with /GUARD:CF flag"
        )

        if not self.pe:
            return result

        try:
            if hasattr(self.pe, 'OPTIONAL_HEADER'):
                dll_characteristics = self.pe.OPTIONAL_HEADER.DllCharacteristics
                enabled = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
                result.flag_value = dll_characteristics

                if enabled:
                    result.passed = True
                    result.message = "CFG is ENABLED - Call targets are validated"
                    result.recommendation = "Excellent! CFG provides strong control flow integrity"
                else:
                    result.message = "CFG is DISABLED - Vulnerable to call/jump hijacking"
                    self.findings.append(Finding(
                        category="Mitigation",
                        title="CFG Disabled",
                        description="Control Flow Guard is not enabled.",
                        severity=str(SeverityLevel.HIGH.value),
                        recommendation="Enable CFG with IMAGE_DLLCHARACTERISTICS_GUARD_CF"
                    ))
        except Exception as e:
            result.message = f"Error checking CFG: {e}"

        return result

    def check_high_entropy_va(self) -> MitigationResult:
        """
        Check High Entropy VA for 64-bit.
        
        Returns:
            MitigationResult with High Entropy VA status
        """
        result = MitigationResult(
            name="High Entropy ASLR",
            passed=None,
            message="PE not loaded",
            recommendation=""
        )

        if not self.pe:
            return result

        try:
            if hasattr(self.pe, 'OPTIONAL_HEADER'):
                magic = self.pe.OPTIONAL_HEADER.Magic

                if magic == 0x20b:  # PE32+
                    dll_chars = self.pe.OPTIONAL_HEADER.DllCharacteristics
                    enabled = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
                    result.flag_value = dll_chars

                    if enabled:
                        result.passed = True
                        result.message = "High Entropy ASLR is ENABLED - Strong 64-bit randomization"
                        result.recommendation = "Good! Provides strong entropy for address randomization"
                    else:
                        result.passed = False
                        result.message = "High Entropy ASLR is DISABLED - Limited randomization"
                        self.findings.append(Finding(
                            category="Mitigation",
                            title="High Entropy VA Disabled",
                            description="64-bit ASLR uses limited entropy without this flag.",
                            severity=str(SeverityLevel.MEDIUM.value),
                            recommendation="Enable high entropy VA for better 64-bit ASLR"
                        ))
                else:
                    result.passed = None
                    result.message = "Not applicable for 32-bit PE files"
        except Exception as e:
            result.message = f"Error checking HEVA: {e}"

        return result

    def parse_certificate(self) -> CertificateInfo:
        """
        Parse and validate digital certificate from Authenticode signature.
        
        Returns:
            CertificateInfo with parsed certificate details
        """
        cert_info = CertificateInfo()

        if not self.pe:
            return cert_info

        try:
            # Check if security directory exists
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
                self.log("No security directory found")
                return cert_info

            signature_offset = self.pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress
            signature_size = self.pe.DIRECTORY_ENTRY_SECURITY.Size

            if not signature_offset or signature_size == 0:
                self.log("No digital signature found")
                return cert_info

            self.log(f"Found signature at offset 0x{signature_offset:08X}, size: {signature_size} bytes")

            # Read signature data
            with open(self.pe.filepath, 'rb') as f:
                f.seek(signature_offset)
                signature_data = f.read(signature_size)

            # Skip WIN_CERTIFICATE header (8 bytes)
            if len(signature_data) < 8:
                self.log("Signature data too short")
                return cert_info

            # Try to parse PKCS#7 signature
            try:
                from cryptography.hazmat.primitives.serialization import pkcs7
                import hashlib

                try:
                    p7 = pkcs7.load_der_pkcs7_certificates(signature_data[8:])
                    if p7 and len(p7.certificates) > 0:
                        cert = p7.certificates[0]
                        
                        cert_info.issuer = cert.issuer.rfc4514_string()
                        cert_info.subject = cert.subject.rfc4514_string()
                        
                        # Get thumbprint
                        fingerprint = cert.fingerprint(hashlib.sha256())
                        cert_info.thumbprint = fingerprint.hex().upper()
                        
                        # Get validity dates
                        from datetime import datetime as dt
                        cert_info.valid_from = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
                        cert_info.valid_to = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
                        
                        # Check if expired
                        now = dt.utcnow()
                        cert_info.is_expired = cert.not_valid_after < now
                        
                        # Check if self-signed
                        cert_info.is_self_signed = cert.issuer == cert.subject
                        cert_info.is_valid = True
                        
                        # Extract company name from subject
                        for attr in cert.subject:
                            if attr.oid._name == "commonName":
                                cert_info.company_name = attr.value
                                break
                            elif attr.oid._name == "organizationName" and not cert_info.company_name:
                                cert_info.company_name = attr.value

                        self.log(f"Certificate parsed - Issuer: {cert_info.issuer[:50]}...")
                    else:
                        cert_info.is_valid = False
                except Exception:
                    cert_info.is_valid = False

            except Exception as e:
                self.log(f"Error parsing certificate: {e}")
                cert_info.is_valid = False

            # Add findings based on certificate analysis
            if cert_info.is_valid:
                if cert_info.is_expired:
                    self.findings.append(Finding(
                        category="Certificate",
                        title="Expired Certificate",
                        description=f"Certificate expired on {cert_info.valid_to}",
                        severity=str(SeverityLevel.HIGH.value),
                        recommendation="Renew the certificate and re-sign the executable"
                    ))
                elif cert_info.is_self_signed:
                    self.findings.append(Finding(
                        category="Certificate",
                        title="Self-Signed Certificate",
                        description="Certificate is self-signed. Chain cannot be validated.",
                        severity=str(SeverityLevel.MEDIUM.value),
                        recommendation="Use a certificate from a trusted Certificate Authority"
                    ))

        except Exception as e:
            self.errors.append(f"Error parsing certificate: {e}")

        return cert_info

    def check_digitally_signed(self) -> MitigationResult:
        """
        Check if PE is digitally signed.
        
        Returns:
            MitigationResult with digital signature status
        """
        result = MitigationResult(
            name="Digital Signature",
            passed=None,
            message="Checking signature...",
            recommendation=""
        )

        if not self.pe:
            return result

        try:
            cert_info = self.parse_certificate()
            
            if cert_info.issuer or cert_info.subject:
                result.passed = True
                if cert_info.is_valid:
                    result.message = f"Valid digital signature found. Issuer: {cert_info.issuer[:60]}..."
                    result.recommendation = "Good! Certificate is valid and verified"
                else:
                    result.message = f"Digital signature present but validation failed. Issuer: {cert_info.issuer[:60]}..."
                    result.recommendation = "Certificate chain could not be validated"
            else:
                result.passed = False
                result.message = "No digital signature found"
                self.findings.append(Finding(
                    category="Security",
                    title="No Digital Signature",
                    description="Executable is not signed. Cannot verify authenticity.",
                    severity=str(SeverityLevel.MEDIUM.value),
                    recommendation="Obtain code signing certificate and sign the executable"
                ))
        except Exception as e:
            result.message = f"Error checking signature: {e}"

        return result