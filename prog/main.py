#!/usr/bin/env python3
"""
Byt3land PE Security Analyzer - Main Entry Point
Comprehensive Windows PE (.exe) file security analysis tool.

Author: Byt3land Security Team
Version: 2.0.0
"""

import sys
import os
import argparse
from datetime import datetime
from dataclasses import asdict
from typing import List, Dict, Any

try:
    import pefile
except ImportError:
    print("ERROR: pefile library is required. Install it with: pip install pefile")
    sys.exit(1)

# Handle both module and direct execution
try:
    # Try relative imports first (module execution)
    from .models import (
        PEInfo, AnalysisReport, Finding
    )
    from .constants import (
        MACHINE_TYPES, SUBSYSTEM_TYPES
    )
    from .utils import calculate_hashes, log_message
    from .analyzers import (
        MitigationAnalyzer,
        ImportExportAnalyzer,
        SectionAnalyzer,
        ResourceAnalyzer,
        StringAnalyzer,
        LoadConfigAnalyzer,
        PackerAnalyzer
    )
    from .formatters import (
        TextFormatter,
        JSONFormatter,
        CSVFormatter
    )
except ImportError:
    # Running directly, add parent to path
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    
    from byt3land_pe_security.models import (
        PEInfo, AnalysisReport, Finding
    )
    from byt3land_pe_security.constants import (
        MACHINE_TYPES, SUBSYSTEM_TYPES
    )
    from byt3land_pe_security.utils import calculate_hashes, log_message
    from byt3land_pe_security.analyzers import (
        MitigationAnalyzer,
        ImportExportAnalyzer,
        SectionAnalyzer,
        ResourceAnalyzer,
        StringAnalyzer,
        LoadConfigAnalyzer,
        PackerAnalyzer
    )
    from byt3land_pe_security.formatters import (
        TextFormatter,
        JSONFormatter,
        CSVFormatter
    )


class PEAnalyzer:
    """
    Main PE security analyzer orchestrator.
    Coordinates all analyzers and generates comprehensive reports.
    """

    def __init__(self, filepath: str, verbose: bool = False):
        """
        Initialize PE analyzer.
        
        Args:
            filepath: Path to PE file
            verbose: Enable verbose logging
        """
        self.filepath = filepath
        self.verbose = verbose
        self.pe = None
        self.findings: List[Finding] = []
        self.errors: List[str] = []
        self.file_hash = {
            'md5': '',
            'sha1': '',
            'sha256': ''
        }

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
            self.file_hash = calculate_hashes(self.filepath)
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

    def extract_pe_info(self) -> PEInfo:
        """
        Extract basic PE information.
        
        Returns:
            PEInfo object with file details
        """
        info = PEInfo(
            filepath=self.filepath,
            filesize=os.path.getsize(self.filepath)
        )
        info.md5 = self.file_hash['md5']
        info.sha1 = self.file_hash['sha1']
        info.sha256 = self.file_hash['sha256']

        if not self.pe:
            return info

        try:
            # Machine type
            machine = self.pe.FILE_HEADER.Machine
            info.architecture = MACHINE_TYPES.get(machine, f"Unknown (0x{machine:04x})")

            # Subsystem
            if hasattr(self.pe, 'OPTIONAL_HEADER'):
                subsystem = self.pe.OPTIONAL_HEADER.Subsystem
                info.subsystem = SUBSYSTEM_TYPES.get(subsystem, f"Unknown ({subsystem})")

                # Entry point
                info.entry_point = f"0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}"

                # Image base
                info.image_base = f"0x{self.pe.OPTIONAL_HEADER.ImageBase:016X}"

            # Compilation timestamp
            timestamp = self.pe.FILE_HEADER.TimeDateStamp
            info.compilation_timestamp = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

            # Section count
            info.section_count = self.pe.FILE_HEADER.NumberOfSections

            # Is DLL?
            info.is_dll = bool(self.pe.FILE_HEADER.Characteristics & 0x2000)

            # Import count
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                info.import_count = len(self.pe.DIRECTORY_ENTRY_IMPORT)

            # Export count
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                info.export_count = len(self.pe.DIRECTORY_ENTRY_EXPORT.symbols)

            # Resource count
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                info.resource_count = len(self.pe.DIRECTORY_ENTRY_RESOURCE.entries)

            # Check if debug info is stripped
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG'):
                info.is_stripped = True

        except Exception as e:
            self.errors.append(f"Error extracting PE info: {e}")

        return info

    def analyze(self) -> AnalysisReport:
        """
        Run comprehensive analysis on the PE file.
        
        Returns:
            Complete AnalysisReport
        """
        # Initialize report
        report = AnalysisReport(
            pe_info={},
            mitigations=[],
            imports=[],
            exports=[],
            sections=[],
            findings=[],
            metadata={},
            summary={}
        )

        # Load PE file
        if not self.load_pe():
            report.metadata["errors"] = self.errors
            return report

        self.log("PE file loaded successfully")

        # Get PE information
        pe_info = self.extract_pe_info()
        report.pe_info = asdict(pe_info)
        self.log("PE information extracted")

        # Initialize analyzers
        mitigation_analyzer = MitigationAnalyzer(self.pe, self.findings, self.verbose)
        import_export_analyzer = ImportExportAnalyzer(self.pe, self.findings, self.verbose)
        section_analyzer = SectionAnalyzer(self.pe, self.findings, self.verbose)
        resource_analyzer = ResourceAnalyzer(self.pe, self.findings, self.verbose)
        string_analyzer = StringAnalyzer(self.pe, self.filepath, self.findings, self.verbose)
        load_config_analyzer = LoadConfigAnalyzer(self.pe, self.findings, self.verbose)
        packer_analyzer = PackerAnalyzer(self.pe, self.filepath, self.findings, self.verbose)

        # Run mitigation checks
        mitigations = [
            mitigation_analyzer.check_aslr(),
            mitigation_analyzer.check_dep(),
            mitigation_analyzer.check_safeseh(),
            mitigation_analyzer.check_cfg(),
            mitigation_analyzer.check_high_entropy_va(),
            mitigation_analyzer.check_digitally_signed()
        ]
        report.mitigations = [asdict(m) for m in mitigations]
        self.log("Mitigation checks completed")

        # Get imports
        imports = import_export_analyzer.get_imports()
        report.imports = [
            {
                "dll_name": i.dll_name,
                "functions": i.functions,
                "is_local": i.is_local,
                "is_suspicious": i.is_suspicious,
                "suspicious_reasons": i.suspicious_reasons
            }
            for i in imports
        ]
        self.log(f"Found {len(imports)} imported DLLs")

        # Get exports
        exports = import_export_analyzer.get_exports()
        report.exports = [asdict(e) for e in exports]
        self.log(f"Found {len(exports)} exported functions")

        # Advanced Import/Export Analysis
        delay_loads = import_export_analyzer.get_delay_load_imports()
        report.metadata["delay_load_imports"] = [asdict(d) for d in delay_loads]
        self.log(f"Delay load imports: {len(delay_loads)} found")

        bound_imports = import_export_analyzer.get_bound_imports()
        report.metadata["bound_imports"] = [asdict(b) for b in bound_imports]
        self.log(f"Bound imports: {len(bound_imports)} found")

        import_hash = import_export_analyzer.get_import_hash()
        report.metadata["import_hash"] = asdict(import_hash)
        self.log(f"Import hash (imphash): {import_hash.imphash}")

        export_anomalies = import_export_analyzer.detect_export_anomalies()
        report.metadata["export_anomalies"] = [asdict(a) for a in export_anomalies]
        self.log(f"Export anomalies: {len(export_anomalies)} found")

        import_ordinals = import_export_analyzer.analyze_import_ordinals()
        report.metadata["import_ordinals"] = [asdict(o) for o in import_ordinals]
        self.log(f"Import ordinal analysis: {len(import_ordinals)} DLL(s) analyzed")

        # Get sections
        sections = section_analyzer.get_sections()
        report.sections = [asdict(s) for s in sections]
        self.log(f"Analyzed {len(sections)} sections")

        # Extract resources
        cert_info = mitigation_analyzer.parse_certificate()
        report.metadata["certificate_info"] = asdict(cert_info)
        self.log(f"Certificate analysis completed")

        version_info = resource_analyzer.extract_version_info()
        report.metadata["version_info"] = asdict(version_info)
        self.log(f"Version info extraction completed")

        icons = resource_analyzer.extract_icons()
        report.metadata["icons"] = [asdict(i) for i in icons]
        self.log(f"Icon extraction completed: {len(icons)} icon(s)")

        manifest = resource_analyzer.parse_manifest()
        report.metadata["manifest_info"] = asdict(manifest)
        self.log(f"Manifest parsing completed")

        # Check for unsafe C/C++ functions
        unsafe_functions = string_analyzer.check_unsafe_c_functions()
        report.metadata["unsafe_c_functions"] = [asdict(f) for f in unsafe_functions]
        self.log(f"Checked for unsafe C/C++ functions: {len(unsafe_functions)} found")

        # Extract sensitive strings
        sensitive_strings = string_analyzer.extract_sensitive_strings()
        report.metadata["sensitive_strings"] = [asdict(s) for s in sensitive_strings]
        self.log(f"Sensitive strings extraction: {len(sensitive_strings)} found")

        # Load Configuration Analysis
        load_config = load_config_analyzer.analyze_load_config()
        report.metadata["load_config"] = asdict(load_config)
        load_config_summary = load_config_analyzer.get_load_config_summary()
        report.metadata["load_config_summary"] = load_config_summary
        self.log(f"Load configuration analysis completed")

        # Packer & Obfuscation Detection
        packer_analysis = packer_analyzer.analyze_packer()
        report.metadata["packer_analysis"] = asdict(packer_analysis)
        self.log(f"Packer analysis completed. Packed: {packer_analysis.is_packed}")

        # Additional metadata
        report.metadata["tls_callbacks"] = self._check_tls_callbacks()
        report.metadata["rich_header"] = self._check_rich_header()
        report.metadata["resources"] = self._check_resources()

        # Compile findings
        report.findings = [asdict(f) for f in self.findings]

        # Generate summary
        pass_count = sum(1 for m in mitigations if m.passed == True)
        fail_count = sum(1 for m in mitigations if m.passed == False)
        na_count = sum(1 for m in mitigations if m.passed is None)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1

        local_dll_count = sum(1 for i in imports if i.is_local)
        suspicious_api_count = sum(len(i.suspicious_reasons) for i in imports)

        report.summary = {
            "total_mitigations": len(mitigations),
            "passed": pass_count,
            "failed": fail_count,
            "not_applicable": na_count,
            "total_findings": len(self.findings),
            "findings_by_severity": severity_counts,
            "imported_dlls": len(imports),
            "local_dlls": local_dll_count,
            "suspicious_apis": suspicious_api_count,
            "exported_functions": len(exports),
            "sections": len(sections),
            "suspicious_sections": sum(1 for s in sections if s.is_suspicious)
        }

        report.metadata["errors"] = self.errors

        return report

    def _check_tls_callbacks(self) -> List[str]:
        """Check for TLS callbacks."""
        callbacks = []

        if not self.pe:
            return callbacks

        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_TLS'):
                tls = self.pe.DIRECTORY_ENTRY_TLS.struct
                callbacks.append(f"TLS Callback registered at 0x{tls.StartAddressOfRawData:08X}")
        except:
            pass

        return callbacks

    def _check_rich_header(self) -> Dict[str, Any]:
        """Analyze Rich header."""
        rich_info = {"present": False, "builds": []}

        if not self.pe:
            return rich_info

        try:
            if hasattr(self.pe, 'RICH_HEADER'):
                rich_info["present"] = True
                rich_info["builds"] = [
                    {
                        "build_id": r["build_id"],
                        "offset_id": r["offset_id"],
                        "count": r["count"]
                    }
                    for r in self.pe.RICH_HEADER.builds
                ]
        except:
            pass

        return rich_info

    def _check_resources(self) -> List[Dict[str, Any]]:
        """Extract resource information."""
        resources = []

        if not self.pe:
            return resources

        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                return resources

            for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    if hasattr(entry, 'directory'):
                        for sub_entry in entry.directory.entries:
                            resource_type = str(entry.id) if hasattr(entry, 'id') else entry.name
                            resource_info = {
                                "type": resource_type,
                                "id": sub_entry.id if hasattr(sub_entry, 'id') else "unknown"
                            }
                            resources.append(resource_info)
                except:
                    pass
        except:
            pass

        return resources


def analyze_directory(dirpath: str, verbose: bool = False) -> List[AnalysisReport]:
    """
    Analyze all PE files in a directory.
    
    Args:
        dirpath: Path to directory
        verbose: Enable verbose logging
        
    Returns:
        List of AnalysisReport objects
    """
    reports = []

    for root, _, files in os.walk(dirpath):
        for file in files:
            filepath = os.path.join(root, file)
            # Check if it's a PE file (basic check)
            try:
                with open(filepath, 'rb') as f:
                    header = f.read(2)
                    if header == b'MZ':  # DOS header magic
                        print(f"\nAnalyzing: {filepath}")
                        analyzer = PEAnalyzer(filepath, verbose)
                        report = analyzer.analyze()
                        reports.append(report)
            except:
                pass

    return reports


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Byt3land PE Security Analysis Tool - Modular Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Features:
  - Security mitigation checks (ASLR, DEP, SafeSEH, CFG, etc.)
  - DLL import analysis and search path hijacking detection
  - Section entropy analysis and packer detection
  - Packer & Obfuscation detection (entropy distribution, signatures, overlays)
  - Suspicious API function detection
  - Digital signature verification
  - TLS callback detection
  - Export/Import function analysis
  - Load configuration analysis (Security cookie, SEH, Guard flags, Heap protection)
  - Multiple output formats (text, JSON, CSV)

Examples:
  python byt3land_pe_security.py program.exe
  python byt3land_pe_security.py malicious.exe --format json --output report.json
  python byt3land_pe_security.py sample.dll --verbose
  python byt3land_pe_security.py directory/ --batch
        """
    )

    parser.add_argument('filepath', help='Path to PE file or directory')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'csv'],
                        default='text', help='Output format (default: text)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-b', '--batch', action='store_true', help='Batch mode for directories')

    args = parser.parse_args()

    # Validate path
    if not os.path.exists(args.filepath):
        print(f"Error: Path not found: {args.filepath}")
        sys.exit(1)

    # Batch mode
    if args.batch and os.path.isdir(args.filepath):
        reports = analyze_directory(args.filepath, args.verbose)

        if args.output:
            if args.format == 'json':
                all_reports = [asdict(r) for r in reports]
                import json
                with open(args.output, 'w') as f:
                    json.dump(all_reports, f, indent=2, default=str)
                print(f"\nReport saved to: {args.output}")
            else:
                print(f"\nBatch mode only supports JSON output")

        print(f"\nAnalyzed {len(reports)} PE files")
        return

    # Single file analysis
    analyzer = PEAnalyzer(args.filepath, args.verbose)
    report = analyzer.analyze()

    # Format and output
    if args.format == 'json':
        output = JSONFormatter.to_json(report)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Report saved to: {args.output}")
        else:
            print(output)
    elif args.format == 'csv':
        output = CSVFormatter.to_csv(report)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Report saved to: {args.output}")
        else:
            print(output)
    else:
        TextFormatter.print_report(report)


if __name__ == '__main__':
    main()