"""
Text formatter for analysis reports.
Generates human-readable text output.
"""

from ..models import AnalysisReport


class TextFormatter:
    """Formats analysis reports in human-readable text format."""

    @staticmethod
    def print_report(report: AnalysisReport):
        """Print report in human-readable text format."""
        print("\n" + "=" * 80)
        print("                  COMPREHENSIVE PE SECURITY ANALYSIS REPORT")
        print("=" * 80)

        if report.metadata.get("errors"):
            print("\n[FATAL ERROR] Unable to analyze PE file")
            for error in report.metadata["errors"]:
                print(f"              - {error}")
            return

        # PE Information
        print("\n" + "-" * 80)
        print("                              FILE INFORMATION")
        print("-" * 80)
        pe_info = report.pe_info
        print(f"\n  File Path:         {pe_info.get('filepath', 'N/A')}")
        print(f"  File Size:         {pe_info.get('filesize', 0):,} bytes")
        print(f"  Architecture:     {pe_info.get('architecture', 'N/A')}")
        print(f"  Subsystem:         {pe_info.get('subsystem', 'N/A')}")
        print(f"  Entry Point:       {pe_info.get('entry_point', 'N/A')}")
        print(f"  Image Base:        {pe_info.get('image_base', 'N/A')}")
        print(f"  Compiled:          {pe_info.get('compilation_timestamp', 'N/A')}")
        print(f"  Is DLL:            {'Yes' if pe_info.get('is_dll') else 'No'}")
        print(f"  Is Signed:         {'Yes' if pe_info.get('is_signed') else 'No'}")
        print(f"  Is Stripped:      {'Yes' if pe_info.get('is_stripped') else 'No'}")

        print(f"\n  MD5:    {pe_info.get('md5', 'N/A')}")
        print(f"  SHA1:   {pe_info.get('sha1', 'N/A')}")
        print(f"  SHA256: {pe_info.get('sha256', 'N/A')}")

        # Digital Certificate Information
        print("\n" + "-" * 80)
        print("                       DIGITAL CERTIFICATE")
        print("-" * 80)
        
        cert_info = report.metadata.get('certificate_info', {})
        if not cert_info.get('issuer'):
            print("\n  \033[93mNo certificate information available\033[0m")
        else:
            print(f"\n  Issuer:           {cert_info.get('issuer', 'N/A')}")
            print(f"  Subject:           {cert_info.get('subject', 'N/A')}")
            print(f"  Company Name:      {cert_info.get('company_name', 'N/A')}")
            print(f"  Thumbprint:        {cert_info.get('thumbprint', 'N/A')}")
            print(f"  Valid From:        {cert_info.get('valid_from', 'N/A')}")
            print(f"  Valid To:          {cert_info.get('valid_to', 'N/A')}")
            print(f"  Is Valid:          {'\033[92mYes\033[0m' if cert_info.get('is_valid') else '\033[91mNo\033[0m'}")
            print(f"  Is Expired:        {'\033[91mYes\033[0m' if cert_info.get('is_expired') else '\033[92mNo\033[0m'}")
            print(f"  Is Self-Signed:   {'\033[93mYes\033[0m' if cert_info.get('is_self_signed') else '\033[92mNo\033[0m'}")

        # Version Information
        print("\n" + "-" * 80)
        print("                       VERSION INFORMATION")
        print("-" * 80)
        
        version_info = report.metadata.get('version_info', {})
        if not version_info.get('file_version'):
            print("\n  \033[93mNo version information found\033[0m")
        else:
            print(f"\n  Product Name:      {version_info.get('product_name', 'N/A')}")
            print(f"  File Version:      {version_info.get('file_version', 'N/A')}")
            print(f"  Product Version:   {version_info.get('product_version', 'N/A')}")
            print(f"  Company Name:      {version_info.get('company_name', 'N/A')}")
            print(f"  File Description:  {version_info.get('file_description', 'N/A')}")
            print(f"  Internal Name:     {version_info.get('internal_name', 'N/A')}")
            print(f"  Original Filename: {version_info.get('original_filename', 'N/A')}")
            print(f"  Copyright:          {version_info.get('copyright', 'N/A')}")

        # Icons
        print("\n" + "-" * 80)
        print("                          ICONS")
        print("-" * 80)
        
        icons = report.metadata.get('icons', [])
        if not icons:
            print("\n  \033[93mNo icons found\033[0m")
        else:
            print(f"\n  Found {len(icons)} icon(s):")
            for icon in icons:
                print(f"\n  Icon #{icon['index'] + 1}")
                print(f"    Width:      {icon['width'] if icon['width'] < 256 else '256'}x{icon['height'] if icon['height'] < 256 else '256'}")
                print(f"    Bit Depth:  {icon['bit_depth']} bits")
                print(f"    Size:        {icon['size_bytes']:,} bytes")

        # Manifest
        print("\n" + "-" * 80)
        print("                       APPLICATION MANIFEST")
        print("-" * 80)
        
        manifest = report.metadata.get('manifest_info', {})
        if not manifest.get('is_manifest_embedded'):
            print("\n  \033[93mNo manifest embedded\033[0m")
        else:
            print(f"\n  Execution Level:   {manifest.get('execution_level', 'N/A')}")
            print(f"  UI Access:        {'\033[92mYes\033[0m' if manifest.get('ui_access') else '\033[92mNo\033[0m'}")
            print(f"  Requested Level: {manifest.get('requested_execution_level', 'N/A')}")
            if manifest.get('compatibility_modes'):
                print(f"  Compatibility:    {', '.join(manifest['compatibility_modes'][:3])}")
                if len(manifest['compatibility_modes']) > 3:
                    print(f"                     ... and {len(manifest['compatibility_modes']) - 3} more")

        # Security Mitigations
        print("\n" + "-" * 80)
        print("                         SECURITY MITIGATIONS")
        print("-" * 80)

        for m in report.mitigations:
            passed = m['passed']
            if passed == True:
                status = "\033[92m[PASS]\033[0m"
            elif passed is None:
                status = "\033[93m[N/A]\033[0m"
            else:
                status = "\033[91m[FAIL]\033[0m"

            print(f"\n  {status} {m['name']}")
            print(f"         {m['message']}")
            if m['recommendation']:
                print(f"         Recommendation: {m['recommendation']}")

        # Imports
        print("\n" + "-" * 80)
        print("                           IMPORTED DLLS")
        print("-" * 80)

        if not report.imports:
            print("\n  No imports found.")
        else:
            for i, imp in enumerate(report.imports, 1):
                local_marker = ""
                if imp['is_local']:
                    local_marker = " \033[91m[LOCAL PATH]\033[0m"
                if imp['is_suspicious']:
                    local_marker += " \033[93m[SUSPICIOUS]\033[0m"

                print(f"\n  {i}. {imp['dll_name']}{local_marker}")
                if imp['functions']:
                    print(f"     Functions ({len(imp['functions'])}): {', '.join(imp['functions'][:5])}")
                    if len(imp['functions']) > 5:
                        print(f"     ... and {len(imp['functions']) - 5} more")
                if imp['suspicious_reasons']:
                    print(f"     \033[93mSuspicious APIs:\033[0m")
                    for reason in imp['suspicious_reasons']:
                        print(f"       - {reason}")

        # Advanced Import/Export Analysis
        print("\n" + "-" * 80)
        print("                 ADVANCED IMPORT/EXPORT ANALYSIS")
        print("-" * 80)

        # Import Hash (imphash)
        import_hash = report.metadata.get('import_hash', {})
        if import_hash.get('imphash'):
            print(f"\n  Import Hash (imphash):")
            print(f"    Value:       {import_hash['imphash']}")
            print(f"    Algorithm:   {import_hash.get('algorithm', 'N/A')}")
            print(f"    Description: {import_hash.get('description', 'N/A')}")
        else:
            print("\n  \033[93mNo import hash calculated\033[0m")

        # Delay Load Imports
        delay_loads = report.metadata.get('delay_load_imports', [])
        if delay_loads:
            print(f"\n  Delay Load Imports (\033[93m{len(delay_loads)} found\033[0m):")
            for dl in delay_loads:
                print(f"\n    DLL: {dl['dll_name']}")
                print(f"      Functions ({len(dl.get('functions', []))}): {', '.join(dl.get('functions', [])[:5])}")
                if len(dl.get('functions', [])) > 5:
                    print(f"      ... and {len(dl.get('functions', [])) - 5} more")
        else:
            print("\n  \033[92mNo delay load imports found\033[0m")

        # Bound Imports
        bound_imports = report.metadata.get('bound_imports', [])
        if bound_imports:
            print(f"\n  Bound Imports (\033[93m{len(bound_imports)} found\033[0m):")
            for bi in bound_imports:
                print(f"\n    DLL: {bi['dll_name']}")
                print(f"      Timestamp:      {bi['time_date_stamp']}")
                print(f"      Offset:         0x{bi['offset_module_name']:08X}")
                print(f"      Forwarder Refs: {bi['number_of_module_forwarder_refs']}")
        else:
            print("\n  \033[92mNo bound imports found\033[0m")

        # Import Ordinals Analysis
        import_ordinals = report.metadata.get('import_ordinals', [])
        if import_ordinals:
            print(f"\n  Import Ordinal Usage (\033[93m{len(import_ordinals)} DLL(s) analyzed\033[0m):")
            for io in import_ordinals:
                if io['ordinal_percentage'] > 0:
                    marker = ""
                    if io['ordinal_percentage'] > 50:
                        marker = " \033[91m[HIGH]\033[0m"
                    elif io['ordinal_percentage'] > 25:
                        marker = " \033[93m[MEDIUM]\033[0m"
                    elif io['ordinal_percentage'] > 10:
                        marker = " \033[94m[LOW]\033[0m"
                    
                    print(f"\n    {io['dll_name']}:")
                    print(f"      Total Imports:   {io['total_imports']}")
                    print(f"      Ordinal Imports: {io['ordinal_imports']} ({io['ordinal_percentage']:.1f}%){marker}")
        else:
            print("\n  \033[92mNo high ordinal usage detected\033[0m")

        # Export Anomalies
        export_anomalies = report.metadata.get('export_anomalies', [])
        if export_anomalies:
            print(f"\n  Export Anomalies (\033[93m{len(export_anomalies)} found\033[0m):")
            for ea in export_anomalies:
                severity_marker = ""
                if ea['severity'] == 'HIGH':
                    severity_marker = " \033[91m[HIGH]\033[0m"
                elif ea['severity'] == 'MEDIUM':
                    severity_marker = " \033[93m[MEDIUM]\033[0m"
                elif ea['severity'] == 'LOW':
                    severity_marker = " \033[94m[LOW]\033[0m"
                
                print(f"\n    Function: {ea['function_name']}")
                print(f"      Type:       {ea['anomaly_type']}")
                print(f"      Description: {ea['description']}{severity_marker}")
        else:
            print("\n  \033[92mNo export anomalies detected\033[0m")

        # Sections
        print("\n" + "-" * 80)
        print("                             SECTIONS")
        print("-" * 80)

        for s in report.sections:
            sus_marker = ""
            if s['is_suspicious']:
                sus_marker = f" \033[91m[WARN: {s['suspicion_reason']}]\033[0m"

            perms = []
            if s['is_readable']: perms.append('R')
            if s['is_writable']: perms.append('W')
            if s['is_executable']: perms.append('X')
            perms_str = ''.join(perms)

            print(f"\n  {s['name']:<10} VA: {s['virtual_address']:<12} VSize: {s['virtual_size']:<12} "
                  f"Entropy: {s['entropy']:.2f} [{perms_str}]{sus_marker}")

        # Unsafe C/C++ Functions
        print("\n" + "-" * 80)
        print("                    UNSAFE C/C++ RUNTIME FUNCTIONS")
        print("-" * 80)

        unsafe_functions = report.metadata.get('unsafe_c_functions', [])
        if not unsafe_functions:
            print("\n  \033[92mImport Table looks clean - no unsafe C/C++ functions found.\033[0m")
        else:
            print(f"\n  Found {len(unsafe_functions)} unsafe C/C++ runtime function(s):")
            for func in unsafe_functions:
                print(f"\n  - \033[91m{func['function_name']}\033[0m")
                print(f"    DLL:     {func['dll_name']}")
                print(f"    Reason:  {func['reason']}")

        # Sensitive Strings
        print("\n" + "-" * 80)
        print("                       SENSITIVE STRINGS FOUND")
        print("-" * 80)

        sensitive_strings = report.metadata.get('sensitive_strings', [])
        if not sensitive_strings:
            print("\n  \033[92mNo sensitive strings found.\033[0m")
        else:
            # Group by type
            by_type = {}
            for s in sensitive_strings:
                if s['string_type'] not in by_type:
                    by_type[s['string_type']] = []
                by_type[s['string_type']].append(s)

            print(f"\n  Found {len(sensitive_strings)} sensitive string(s) across {len(by_type)} categories:")
            for string_type, strings in by_type.items():
                severity = "\033[91m[CRITICAL]\033[0m" if "Key" in string_type or "Connection" in string_type else "\033[93m[HIGH]\033[0m"
                print(f"\n  {severity} {string_type}: {len(strings)} occurrence(s)")
                # Show first 5 strings
                for i, s in enumerate(strings[:5], 1):
                    # Truncate long strings for display
                    display_value = s['value'][:100] + "..." if len(s['value']) > 100 else s['value']
                    print(f"    {i}. Offset 0x{s['offset']:08X}: {display_value}")
                if len(strings) > 5:
                    print(f"    ... and {len(strings) - 5} more")

        # Security Findings
        if report.findings:
            print("\n" + "-" * 80)
            print("                         SECURITY FINDINGS")
            print("-" * 80)

            for f in report.findings:
                severity = f['severity']
                if severity == "CRITICAL":
                    sev_str = "\033[91m[CRITICAL]\033[0m"
                elif severity == "HIGH":
                    sev_str = "\033[91m[HIGH]\033[0m"
                elif severity == "MEDIUM":
                    sev_str = "\033[93m[MEDIUM]\033[0m"
                elif severity == "LOW":
                    sev_str = "\033[94m[LOW]\033[0m"
                else:
                    sev_str = "\033[90m[INFO]\033[0m"

                print(f"\n  {sev_str} {f['category']}: {f['title']}")
                print(f"           {f['description']}")
                if f['recommendation']:
                    print(f"           Recommendation: {f['recommendation']}")

        # Summary
        print("\n" + "-" * 80)
        print("                              SUMMARY")
        print("-" * 80)

        summary = report.summary
        print(f"\n  Security Mitigations:")
        print(f"    Passed:          {summary['passed']}")
        print(f"    Failed:          {summary['failed']}")
        print(f"    Not Applicable:   {summary['not_applicable']}")

        print(f"\n  Dependencies:")
        print(f"    Imported DLLs:   {summary['imported_dlls']}")
        print(f"    Local DLLs:      {summary['local_dlls']}")
        print(f"    Suspicious APIs: {summary['suspicious_apis']}")

        print(f"\n  Sections:")
        print(f"    Total Sections:   {summary['sections']}")
        print(f"    Suspicious:      {summary['suspicious_sections']}")

        if summary['total_findings'] > 0:
            print(f"\n  Findings by Severity:")
            sev_counts = summary['findings_by_severity']
            for sev, count in sev_counts.items():
                if count > 0:
                    print(f"    {sev}: {count}")

        # Overall Assessment
        print("\n" + "=" * 80)
        severity_counts = summary['findings_by_severity']
        if severity_counts['CRITICAL'] > 0 or severity_counts['HIGH'] > 3:
            assessment = "\033[91mCRITICAL RISK\033[0m"
        elif severity_counts['HIGH'] > 0 or summary['failed'] > 2:
            assessment = "\033[91mHIGH RISK\033[0m"
        elif severity_counts['MEDIUM'] > 0 or summary['failed'] > 0:
            assessment = "\033[93mMODERATE RISK\033[0m"
        else:
            assessment = "\033[92mLOW RISK\033[0m"

        print(f"  OVERALL ASSESSMENT: {assessment}")
        print("=" * 80 + "\n")