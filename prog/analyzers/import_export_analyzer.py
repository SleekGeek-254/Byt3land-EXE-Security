"""
Import/Export analyzer.
Analyzes imported and exported DLLs and functions.
"""

import os
import hashlib
from typing import List
import re

from ..models import (
    ImportInfo, ExportInfo, Finding, SeverityLevel,
    DelayLoadImportInfo, BoundImportInfo, ImportHashInfo,
    ExportAnomalyInfo, ImportOrdinalInfo
)
from ..constants import SUSPICIOUS_APIS, SUSPICIOUS_DLLS


class ImportExportAnalyzer:
    """
    Analyzer for DLL imports and exports.
    Detects suspicious APIs and DLL loading issues.
    """

    def __init__(self, pe, findings_list: list, verbose: bool = False):
        """
        Initialize import/export analyzer.
        
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

    def get_imports(self) -> List[ImportInfo]:
        """
        Get all imported DLLs and functions.
        
        Returns:
            List of ImportInfo objects
        """
        imports = []

        if not self.pe:
            return imports

        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                self.log("No import directory found")
                return imports

            cwd = os.getcwd()

            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else str(entry.dll)

                # Extract function names
                functions = []
                suspicious_funcs = []

                try:
                    for imp in entry.imports:
                        func_name = ""
                        if imp.name:
                            func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else str(imp.name)
                        else:
                            func_name = f"Ordinal:{imp.ordinal}"

                        functions.append(func_name)

                        # Check for suspicious APIs
                        if func_name in SUSPICIOUS_APIS:
                            suspicious_funcs.append((func_name, SUSPICIOUS_APIS[func_name]))
                except:
                    pass

                # Check if DLL is loaded from local path
                is_local = os.path.exists(os.path.join(cwd, dll_name)) or not os.path.isabs(dll_name)

                # Check if DLL is suspicious
                is_suspicious_dll = dll_name.lower() in [d.lower() for d in SUSPICIOUS_DLLS]

                import_info = ImportInfo(
                    dll_name=dll_name,
                    functions=functions,
                    is_local=is_local,
                    is_suspicious=is_suspicious_dll or len(suspicious_funcs) > 0,
                    suspicious_reasons=[reason for _, reason in suspicious_funcs]
                )

                imports.append(import_info)

                # Add findings for suspicious imports
                if is_local:
                    self.findings.append(Finding(
                        category="DLL Loading",
                        title="Local DLL Loading",
                        description=f"DLL '{dll_name}' loaded from current directory",
                        severity=str(SeverityLevel.HIGH.value),
                        recommendation="Move to system DLLs or verify DLL location"
                    ))

                if is_suspicious_dll:
                    self.findings.append(Finding(
                        category="Suspicious Behavior",
                        title=f"Suspicious DLL: {dll_name}",
                        description="This DLL is commonly used by malware for code execution",
                        severity=str(SeverityLevel.MEDIUM.value),
                        recommendation="Verify this DLL is required for the application"
                    ))

                for func_name, reason in suspicious_funcs:
                    self.findings.append(Finding(
                        category="Suspicious API",
                        title=f"Suspicious API: {func_name}",
                        description=reason,
                        severity=str(SeverityLevel.LOW.value),
                        recommendation=f"Review usage of {func_name}"
                    ))

        except Exception as e:
            self.log(f"Error reading imports: {e}")

        return imports

    def get_exports(self) -> List[ExportInfo]:
        """
        Get all exported functions.
        
        Returns:
            List of ExportInfo objects
        """
        exports = []

        if not self.pe:
            return exports

        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                self.log("No export directory found")
                return exports

            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = ExportInfo(
                    function_name=exp.name.decode('utf-8') if exp.name else f"Ordinal:{exp.ordinal}",
                    ordinal=exp.ordinal,
                    address=exp.address
                )
                exports.append(export_info)

        except Exception as e:
            self.log(f"Error reading exports: {e}")

        return exports

    def get_delay_load_imports(self) -> List[DelayLoadImportInfo]:
        """
        Analyze delay load imports (DLLs loaded at runtime).
        Delay load imports are commonly used by packers to hide imports.
        
        Returns:
            List of DelayLoadImportInfo objects
        """
        delay_loads = []

        if not self.pe:
            return delay_loads

        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                self.log("No delay load import directory found")
                return delay_loads

            self.log(f"Found {len(self.pe.DIRECTORY_ENTRY_DELAY_IMPORT)} delay load imports")

            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else str(entry.dll)

                # Extract function names from delay load
                functions = []
                try:
                    for imp in entry.imports:
                        func_name = ""
                        if imp.name:
                            func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else str(imp.name)
                        else:
                            func_name = f"Ordinal:{imp.ordinal}"
                        functions.append(func_name)
                except:
                    pass

                delay_info = DelayLoadImportInfo(
                    dll_name=dll_name,
                    attributes=getattr(entry, 'attributes', 0),
                    module_handle_rva=getattr(entry, 'struct', {}).get('ModuleHandleRVA', 0),
                    import_address_table_rva=getattr(entry, 'struct', {}).get('ImportAddressTableRVA', 0),
                    import_name_table_rva=getattr(entry, 'struct', {}).get('ImportNameTableRVA', 0),
                    bound_import_address_table_rva=getattr(entry, 'struct', {}).get('BoundImportAddressTableRVA', 0),
                    unload_information_table_rva=getattr(entry, 'struct', {}).get('UnloadInformationTableRVA', 0),
                    time_date_stamp=getattr(entry, 'struct', {}).get('TimeDateStamp', 0),
                    functions=functions
                )

                delay_loads.append(delay_info)

            # Add finding for delay load imports
            if delay_loads:
                self.findings.append(Finding(
                    category="Packer Detection",
                    title="Delay Load Imports Detected",
                    description=f"Found {len(delay_loads)} delay-loaded DLL(s). This is commonly used by packers to hide imports.",
                    severity=str(SeverityLevel.MEDIUM.value),
                    recommendation="Investigate if delay loading is legitimate or used for obfuscation"
                ))

        except Exception as e:
            self.log(f"Error reading delay load imports: {e}")

        return delay_loads

    def get_bound_imports(self) -> List[BoundImportInfo]:
        """
        Check for bound imports directory.
        Bound imports can indicate pre-linked DLLs or packer activity.
        
        Returns:
            List of BoundImportInfo objects
        """
        bound_imports = []

        if not self.pe:
            return bound_imports

        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
                self.log("No bound import directory found")
                return bound_imports

            self.log("Found bound import directory")

            for desc in self.pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                dll_name = desc.name.decode('utf-8') if isinstance(desc.name, bytes) else str(desc.name)

                bound_info = BoundImportInfo(
                    dll_name=dll_name,
                    time_date_stamp=desc.time_date_stamp,
                    offset_module_name=desc.offset_module_name,
                    number_of_module_forwarder_refs=desc.number_of_module_forwarder_refs
                )

                bound_imports.append(bound_info)

            # Add finding for bound imports
            self.findings.append(Finding(
                category="DLL Loading",
                title="Bound Imports Detected",
                description=f"Found {len(bound_imports)} bound import(s). Bound imports can indicate pre-linked DLLs or modified binaries.",
                severity=str(SeverityLevel.LOW.value),
                recommendation="Verify bound imports are legitimate and not modified"
            ))

        except Exception as e:
            self.log(f"Error reading bound imports: {e}")

        return bound_imports

    def get_import_hash(self) -> ImportHashInfo:
        """
        Calculate import hash (imphash) for malware identification.
        Imphash creates a fingerprint of imported functions.
        
        Returns:
            ImportHashInfo object with imphash value
        """
        if not self.pe:
            return ImportHashInfo(imphash="")

        try:
            # Use pefile's built-in imphash calculation if available
            if hasattr(self.pe, 'get_imphash'):
                imphash = self.pe.get_imphash()
                self.log(f"Calculated imphash: {imphash}")
                
                return ImportHashInfo(
                    imphash=imphash,
                    algorithm="pefile",
                    description="Fingerprint of imported functions for malware identification"
                )
            
            # Fallback: manually calculate imphash
            imphash = self._calculate_manual_imphash()
            return ImportHashInfo(
                imphash=imphash,
                algorithm="manual",
                description="Fingerprint of imported functions for malware identification (manual calculation)"
            )

        except Exception as e:
            self.log(f"Error calculating imphash: {e}")
            return ImportHashInfo(imphash="")

    def _calculate_manual_imphash(self) -> str:
        """
        Manually calculate imphash when pefile's method is unavailable.
        
        Returns:
            MD5 hash string
        """
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return ""

        import_list = []

        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else str(entry.dll)
                dll_name_lower = dll_name.lower()

                # Extract and sort function names
                func_list = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else str(imp.name)
                        func_list.append(func_name)
                    else:
                        func_list.append(f"ord{imp.ordinal}")

                func_list.sort()

                # Create import string: dll:function,dll:function
                for func in func_list:
                    import_list.append(f"{dll_name_lower}.{func.lower()}")

            # Sort all imports and create string
            import_list.sort()
            import_string = ",".join(import_list)

            # Calculate MD5 hash
            if import_string:
                md5_hash = hashlib.md5(import_string.encode('utf-8')).hexdigest()
                return md5_hash

        except Exception as e:
            self.log(f"Error in manual imphash calculation: {e}")

        return ""

    def detect_export_anomalies(self) -> List[ExportAnomalyInfo]:
        """
        Detect export function anomalies.
        Look for unusual export patterns, suspicious exports, etc.
        
        Returns:
            List of ExportAnomalyInfo objects
        """
        anomalies = []

        if not self.pe:
            return anomalies

        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                self.log("No export directory found")
                return anomalies

            exports = list(self.pe.DIRECTORY_ENTRY_EXPORT.symbols)
            export_count = len(exports)

            # Suspicious export patterns
            suspicious_patterns = [
                (r'^loadlibr[a-z]*$', 'LoadLibrary-like export'),
                (r'^getproc[a-z]*$', 'GetProcAddress-like export'),
                (r'^virtual[a-z]*$', 'VirtualAlloc-like export'),
                (r'^writeproc[a-z]*$', 'WriteProcessMemory-like export'),
                (r'^createproc[a-z]*$', 'CreateProcess-like export'),
                (r'^create.*thread$', 'Thread creation export'),
                (r'^openprocess$', 'OpenProcess export'),
            ]

            # Check for exports with unusual names
            for exp in exports:
                exp_name = exp.name.decode('utf-8') if exp.name else f"Ordinal:{exp.ordinal}"
                
                # Check against suspicious patterns
                for pattern, description in suspicious_patterns:
                    if re.match(pattern, exp_name.lower()):
                        anomalies.append(ExportAnomalyInfo(
                            function_name=exp_name,
                            ordinal=exp.ordinal,
                            address=exp.address,
                            anomaly_type="Suspicious Export Name",
                            description=f"Export matches suspicious pattern: {description}",
                            severity=str(SeverityLevel.MEDIUM.value)
                        ))

                # Check for single-character exports (obfuscation)
                if exp.name and len(exp.name) == 1:
                    anomalies.append(ExportAnomalyInfo(
                        function_name=exp_name,
                        ordinal=exp.ordinal,
                        address=exp.address,
                        anomaly_type="Obfuscated Export",
                        description="Single-character export name, possible obfuscation",
                        severity=str(SeverityLevel.LOW.value)
                    ))

                # Check for exports at ordinal 1 (unusual for legitimate software)
                if exp.ordinal == 1:
                    anomalies.append(ExportAnomalyInfo(
                        function_name=exp_name,
                        ordinal=exp.ordinal,
                        address=exp.address,
                        anomaly_type="Low Ordinal Export",
                        description="Export at ordinal 1, unusual for legitimate software",
                        severity=str(SeverityLevel.LOW.value)
                    ))

            # Check for too few exports for a DLL
            if export_count > 0 and export_count < 3:
                self.findings.append(Finding(
                    category="Export Analysis",
                    title=f"Low Export Count: {export_count}",
                    description="Very low number of exports for a DLL, possibly a packed binary or stub",
                    severity=str(SeverityLevel.MEDIUM.value),
                    recommendation="Investigate if this is a legitimate DLL or a packed binary"
                ))

            # Check for only ordinal exports (no names)
            ordinal_only_count = sum(1 for exp in exports if exp.name is None)
            if ordinal_only_count > 0 and ordinal_only_count == export_count:
                anomalies.append(ExportAnomalyInfo(
                    function_name="ALL",
                    ordinal=0,
                    address=0,
                    anomaly_type="Ordinal-Only Exports",
                    description=f"All {export_count} exports are ordinal-only (no names), common in packed binaries",
                    severity=str(SeverityLevel.HIGH.value)
                ))
                self.findings.append(Finding(
                    category="Export Analysis",
                    title="Ordinal-Only Exports Detected",
                    description="All exports use ordinals without names, common in packed binaries",
                    severity=str(SeverityLevel.HIGH.value),
                    recommendation="This is a strong indicator of packing or obfuscation"
                ))

        except Exception as e:
            self.log(f"Error detecting export anomalies: {e}")

        return anomalies

    def analyze_import_ordinals(self) -> List[ImportOrdinalInfo]:
        """
        Analyze import ordinal usage.
        High ordinal usage can indicate obfuscation.
        
        Returns:
            List of ImportOrdinalInfo objects
        """
        ordinal_info_list = []

        if not self.pe:
            return ordinal_info_list

        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                self.log("No import directory found")
                return ordinal_info_list

            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else str(entry.dll)
                
                total_imports = 0
                ordinal_imports = 0
                ordinal_details = []

                try:
                    for imp in entry.imports:
                        total_imports += 1
                        
                        if imp.name is None:
                            # Import by ordinal
                            ordinal_imports += 1
                            ordinal_details.append((imp.ordinal, imp.hint, f"Ordinal:{imp.ordinal}"))
                        else:
                            func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else str(imp.name)
                            ordinal_details.append((imp.ordinal, imp.hint, func_name))

                except:
                    pass

                if total_imports > 0:
                    ordinal_percentage = (ordinal_imports / total_imports) * 100
                    
                    ordinal_info = ImportOrdinalInfo(
                        dll_name=dll_name,
                        total_imports=total_imports,
                        ordinal_imports=ordinal_imports,
                        ordinal_percentage=ordinal_percentage,
                        ordinal_details=ordinal_details
                    )
                    
                    ordinal_info_list.append(ordinal_info)

                    # Flag high ordinal usage
                    if ordinal_percentage > 50:
                        severity = SeverityLevel.HIGH
                    elif ordinal_percentage > 25:
                        severity = SeverityLevel.MEDIUM
                    elif ordinal_percentage > 10:
                        severity = SeverityLevel.LOW
                    else:
                        continue  # Skip if ordinal usage is low

                    self.findings.append(Finding(
                        category="Import Analysis",
                        title=f"High Ordinal Usage: {dll_name}",
                        description=f"{ordinal_imports} of {total_imports} imports ({ordinal_percentage:.1f}%) use ordinals instead of names. High ordinal usage can indicate obfuscation.",
                        severity=str(severity.value),
                        recommendation="Investigate if ordinal imports are legitimate or used for obfuscation"
                    ))

        except Exception as e:
            self.log(f"Error analyzing import ordinals: {e}")

        return ordinal_info_list
