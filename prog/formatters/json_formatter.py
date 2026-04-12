"""
JSON formatter for analysis reports.
Generates JSON structured output.
"""

import json
from dataclasses import asdict
from typing import Any
from ..models import AnalysisReport


class JSONFormatter:
    """Formats analysis reports in JSON format."""

    @staticmethod
    def to_json(report: AnalysisReport) -> str:
        """
        Convert report to JSON string.
        
        Args:
            report: AnalysisReport object
            
        Returns:
            JSON string representation
        """
        return json.dumps(asdict(report), indent=2, default=str)