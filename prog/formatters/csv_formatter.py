"""
CSV formatter for analysis reports.
Generates CSV structured output.
"""

from datetime import datetime
from ..models import AnalysisReport


class CSVFormatter:
    """Formats analysis reports in CSV format."""

    @staticmethod
    def to_csv(report: AnalysisReport) -> str:
        """
        Convert report to CSV string.
        
        Args:
            report: AnalysisReport object
            
        Returns:
            CSV string representation
        """
        lines = []
        lines.append("# PE Security Analysis Report")
        lines.append(f"# Generated: {datetime.now().isoformat()}")
        lines.append(f"# File: {report.pe_info.get('filepath', 'N/A')}")
        lines.append("")

        # Mitigations
        lines.append("# Security Mitigations")
        lines.append("Mitigation,Status,Message")
        for m in report.mitigations:
            status = "PASS" if m['passed'] == True else ("N/A" if m['passed'] is None else "FAIL")
            lines.append(f'"{m["name"]}","{status}","{m["message"]}"')
        lines.append("")

        # Imports
        lines.append("# Imported DLLs")
        lines.append("DLL,Functions,IsLocal,IsSuspicious")
        for imp in report.imports:
            funcs = "|".join(imp['functions'][:10])
            lines.append(f'"{imp["dll_name"]}","{funcs}",{imp["is_local"]},{imp["is_suspicious"]}')
        lines.append("")

        # Findings
        if report.findings:
            lines.append("# Security Findings")
            lines.append("Category,Severity,Title,Description")
            for f in report.findings:
                lines.append(f'"{f["category"]}","{f["severity"]}","{f["title"]}","{f["description"]}"')

        return "\n".join(lines)