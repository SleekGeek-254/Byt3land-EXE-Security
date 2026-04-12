"""
Load Configuration Analyzer.
Analyzes the load configuration directory for security features.
"""

from ..models import LoadConfigInfo, Finding, SeverityLevel
from ..constants import (
    IMAGE_GUARD_CF_INSTRUMENTED,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT,
    HEAP_TAIL_CHECKING_ENABLED,
    HEAP_FREE_CHECKING_ENABLED,
    HEAP_GROWABLE
)


class LoadConfigAnalyzer:
    """
    Analyzer for load configuration directory in PE files.
    Checks security cookie, SEH handler table, Guard flags, and heap protection.
    """

    def __init__(self, pe, findings_list: list, verbose: bool = False):
        """
        Initialize load configuration analyzer.
        
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

    def analyze_load_config(self) -> LoadConfigInfo:
        """
        Analyze the load configuration directory.
        
        Returns:
            LoadConfigInfo with load configuration details
        """
        load_config = LoadConfigInfo()

        if not self.pe:
            return load_config

        try:
            # Check if load configuration directory exists
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                self.log("No load configuration directory found")
                self.findings.append(Finding(
                    category="Load Configuration",
                    title="No Load Configuration Directory",
                    description="The PE file does not have a load configuration directory.",
                    severity=str(SeverityLevel.INFO.value),
                    recommendation="Load configuration directory is optional but recommended for security features"
                ))
                return load_config

            config = self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            self.log("Load configuration directory found")

            # Check Security Cookie (/GS)
            self._analyze_security_cookie(config, load_config)

            # Check SEH Handler Table
            self._analyze_seh_handlers(config, load_config)

            # Check Guard Flags
            self._analyze_guard_flags(config, load_config)

            # Check Process Heap Flags
            self._analyze_heap_flags(config, load_config)

        except Exception as e:
            self.log(f"Error analyzing load configuration: {e}")
            self.findings.append(Finding(
                category="Load Configuration",
                title="Load Configuration Analysis Error",
                description=f"Error analyzing load configuration: {e}",
                severity=str(SeverityLevel.LOW.value),
                recommendation="The PE file may be corrupt or malformed"
            ))

        return load_config

    def _analyze_security_cookie(self, config, load_config: LoadConfigInfo):
        """
        Analyze security cookie implementation (/GS flag).
        
        Args:
            config: Load configuration structure
            load_config: LoadConfigInfo to update
        """
        try:
            # SecurityCookie is at offset 0x14 (20) in IMAGE_LOAD_CONFIG_DIRECTORY
            if hasattr(config, 'SecurityCookie'):
                security_cookie = config.SecurityCookie
                
                if security_cookie != 0 and security_cookie != 0x00002B9924021234:
                    # 0x00002B9924021234 is a known default cookie value
                    load_config.security_cookie_enabled = True
                    load_config.security_cookie_address = security_cookie
                    self.log(f"Security cookie enabled at 0x{security_cookie:016X}")
                    
                    # Check if it's the default cookie value (insecure)
                    if security_cookie == 0xBB40E64E:
                        self.findings.append(Finding(
                            category="Load Configuration",
                            title="Default Security Cookie Value",
                            description="Security cookie uses default value, may be bypassed.",
                            severity=str(SeverityLevel.MEDIUM.value),
                            recommendation="Ensure security cookie is properly randomized at runtime"
                        ))
                else:
                    load_config.security_cookie_enabled = False
                    self.log("Security cookie not enabled")
                    
                    self.findings.append(Finding(
                        category="Load Configuration",
                        title="Security Cookie Not Enabled (/GS)",
                        description="Buffer security check (/GS) is not enabled. Stack-based buffer overflows are possible.",
                        severity=str(SeverityLevel.HIGH.value),
                        recommendation="Compile with /GS flag to enable stack canary protection"
                    ))
            else:
                load_config.security_cookie_enabled = False
                self.log("Security cookie field not found in load config")

        except Exception as e:
            self.log(f"Error analyzing security cookie: {e}")

    def _analyze_seh_handlers(self, config, load_config: LoadConfigInfo):
        """
        Analyze SEH (Structured Exception Handler) table.
        
        Args:
            config: Load configuration structure
            load_config: LoadConfigInfo to update
        """
        try:
            # SEHandlerTable is at offset 0x40 (64)
            # SEHandlerCount is at offset 0x48 (72)
            if hasattr(config, 'SEHandlerTable') and hasattr(config, 'SEHandlerCount'):
                seh_table = config.SEHandlerTable
                seh_count = config.SEHandlerCount
                
                load_config.seh_handler_table_address = seh_table
                load_config.seh_handler_count = seh_count
                
                self.log(f"SEH Handler Table: 0x{seh_table:016X}, Count: {seh_count}")
                
                if seh_count > 0:
                    self.findings.append(Finding(
                        category="Load Configuration",
                        title="SEH Handler Table Present",
                        description=f"Structured Exception Handler table contains {seh_count} handlers.",
                        severity=str(SeverityLevel.INFO.value),
                        recommendation="Good! SEH handlers are registered for validation"
                    ))
                else:
                    self.findings.append(Finding(
                        category="Load Configuration",
                        title="SEH Handler Table Empty",
                        description="No SEH handlers registered in the load configuration.",
                        severity=str(SeverityLevel.MEDIUM.value),
                        recommendation="Consider registering SEH handlers for better exception handling security"
                    ))
            else:
                self.log("SEH handler table fields not found (may not be applicable)")

        except Exception as e:
            self.log(f"Error analyzing SEH handlers: {e}")

    def _analyze_guard_flags(self, config, load_config: LoadConfigInfo):
        """
        Analyze Control Flow Guard flags.
        
        Args:
            config: Load configuration structure
            load_config: LoadConfigInfo to update
        """
        try:
            # GuardFlags is at offset 0x90 (144)
            if hasattr(config, 'GuardFlags'):
                guard_flags = config.GuardFlags
                load_config.guard_flags = guard_flags
                
                self.log(f"Guard flags: 0x{guard_flags:08X}")
                
                # Check if Control Flow Guard is enabled
                if guard_flags & IMAGE_GUARD_CF_INSTRUMENTED:
                    load_config.guard_cf_enabled = True
                    self.log("Control Flow Guard (CFG) is ENABLED in load config")
                    
                    # Get CF function table info
                    if hasattr(config, 'GuardCFCheckFunctionPointer'):
                        load_config.guard_cf_check_function_pointer = config.GuardCFCheckFunctionPointer
                        self.log(f"  CF check function pointer: 0x{config.GuardCFCheckFunctionPointer:016X}")
                    
                    if hasattr(config, 'GuardCFFunctionTable'):
                        load_config.guard_cf_function_table_address = config.GuardCFFunctionTable
                        self.log(f"  CF function table: 0x{config.GuardCFFunctionTable:016X}")
                    
                    if hasattr(config, 'GuardCFFunctionCount'):
                        load_config.guard_cf_function_table_count = config.GuardCFFunctionCount
                        self.log(f"  CF function count: {config.GuardCFFunctionCount}")
                    
                    # Check for export suppression
                    if guard_flags & IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION:
                        load_config.guard_export_suppression_enabled = True
                        
                        if hasattr(config, 'GuardAddressTakenIatEntryTable'):
                            load_config.guard_export_suppression_table_count = len(
                                [x for x in self.pe.get_data(config.GuardAddressTakenIatEntryTable, 
                                                              self.pe.OPTIONAL_HEADER.DataDirectory[
                                                                  self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.index
                                                              ].Size) if x != 0]
                            )
                        
                        self.findings.append(Finding(
                            category="Load Configuration",
                            title="Export Suppression Enabled",
                            description="Control Flow Guard export suppression is active. Only exports can be called from outside the module.",
                            severity=str(SeverityLevel.INFO.value),
                            recommendation="Good! Export suppression enhances CFG protection"
                        ))
                    
                    # Check for function table presence
                    if guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT:
                        self.findings.append(Finding(
                            category="Load Configuration",
                            title="CF Function Table Present",
                            description="Control Flow Guard function table is present for validating indirect calls.",
                            severity=str(SeverityLevel.INFO.value),
                            recommendation="Good! CF function table provides strong control flow validation"
                        ))
                    
                    # Check for delay load IAT protection
                    if guard_flags & IMAGE_GUARD_PROTECT_DELAYLOAD_IAT:
                        self.findings.append(Finding(
                            category="Load Configuration",
                            title="Delay Load IAT Protection",
                            description="Delay load import address table is protected by Control Flow Guard.",
                            severity=str(SeverityLevel.INFO.value),
                            recommendation="Good! Delay load IAT protection prevents certain attack vectors"
                        ))
                    
                    # Check if security cookie is unused (suspicious)
                    if guard_flags & IMAGE_GUARD_SECURITY_COOKIE_UNUSED:
                        self.findings.append(Finding(
                            category="Load Configuration",
                            title="Security Cookie Marked Unused",
                            description="Guard flags indicate security cookie is not used despite CFG being enabled.",
                            severity=str(SeverityLevel.MEDIUM.value),
                            recommendation="Enable security cookie (/GS) alongside CFG for comprehensive protection"
                        ))
                else:
                    load_config.guard_cf_enabled = False
                    self.log("Control Flow Guard not enabled in load config")
            else:
                self.log("Guard flags field not found (older PE format)")

        except Exception as e:
            self.log(f"Error analyzing guard flags: {e}")

    def _analyze_heap_flags(self, config, load_config: LoadConfigInfo):
        """
        Analyze process heap protection flags.
        
        Args:
            config: Load configuration structure
            load_config: LoadConfigInfo to update
        """
        try:
            # ProcessHeapFlags is at offset 0x48 (72)
            if hasattr(config, 'ProcessHeapFlags'):
                heap_flags = config.ProcessHeapFlags
                load_config.process_heap_flags = heap_flags
                
                self.log(f"Process heap flags: 0x{heap_flags:08X}")
                
                # Check for heap protection features
                protection_features = []
                
                if heap_flags & HEAP_TAIL_CHECKING_ENABLED:
                    protection_features.append("tail checking")
                    load_config.heap_protection_enabled = True
                    
                if heap_flags & HEAP_FREE_CHECKING_ENABLED:
                    protection_features.append("free checking")
                    load_config.heap_protection_enabled = True
                
                if heap_flags & HEAP_GROWABLE:
                    protection_features.append("growable heap")
                
                if protection_features:
                    self.log(f"Heap protection features: {', '.join(protection_features)}")
                    
                    if load_config.heap_protection_enabled:
                        self.findings.append(Finding(
                            category="Load Configuration",
                            title="Heap Protection Enabled",
                            description=f"Process heap has protection features: {', '.join(protection_features)}.",
                            severity=str(SeverityLevel.INFO.value),
                            recommendation="Good! Heap protection helps detect heap corruption"
                        ))
                else:
                    self.log("No heap protection flags set")
                    self.findings.append(Finding(
                        category="Load Configuration",
                        title="Limited Heap Protection",
                        description="Process heap flags suggest limited or no heap corruption protection.",
                        severity=str(SeverityLevel.MEDIUM.value),
                        recommendation="Enable heap protection features (tail checking, free checking) for better security"
                    ))
            else:
                self.log("Process heap flags field not found")

        except Exception as e:
            self.log(f"Error analyzing heap flags: {e}")

    def get_load_config_summary(self) -> dict:
        """
        Get a summary of load configuration analysis.
        
        Returns:
            Dictionary with load configuration summary
        """
        load_config = self.analyze_load_config()
        
        return {
            "security_cookie_enabled": load_config.security_cookie_enabled,
            "security_cookie_address": f"0x{load_config.security_cookie_address:016X}" if load_config.security_cookie_address else "N/A",
            "seh_handler_count": load_config.seh_handler_count,
            "guard_cf_enabled": load_config.guard_cf_enabled,
            "guard_flags": f"0x{load_config.guard_flags:08X}",
            "guard_function_count": load_config.guard_cf_function_table_count,
            "export_suppression_enabled": load_config.guard_export_suppression_enabled,
            "heap_protection_enabled": load_config.heap_protection_enabled,
            "process_heap_flags": f"0x{load_config.process_heap_flags:08X}"
        }