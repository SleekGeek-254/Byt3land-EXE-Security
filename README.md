# Byt3land PE Security Analyzer

A modular, comprehensive Windows PE (.exe) file security analysis toolkit.

## Overview

This tool analyzes Windows PE files for security mitigations, vulnerabilities, suspicious patterns, and provides detailed reports. The original monolithic `pe_security_analyzer.py` has been refactored into a clean, modular architecture for better maintainability and extensibility.

## Features

- **Security Mitigation Checks**: ASLR, DEP/NX, SafeSEH, CFG, High Entropy VA
- **DLL Import Analysis**: Detects suspicious APIs and local DLL loading
- **Advanced Import Analysis**: 
  - Delay load imports (runtime DLL loading detection)
  - Bound imports analysis
  - Import hash (imphash) calculation for malware identification
  - Import ordinal usage analysis (obfuscation detection)
- **Export Analysis**: 
  - Exported function extraction
  - Export anomaly detection (suspicious patterns, obfuscated exports)
- **Section Analysis**: Entropy calculation, packer detection, W^X violations
- **Packer & Obfuscation Detection**:
  - Entropy distribution analysis per section (with block-level granularity)
  - Known packer signatures (UPX, Themida, VMProtect, ASPack, etc.)
  - Visual entropy analysis data for graphing
  - Overlay detection (data appended after PE structure)
  - Resource section anomalies
  - Comprehensive packer identification with confidence levels
- **Load Configuration Analysis**: 
  - Security cookie (/GS) stack canary implementation
  - SEH handler table analysis
  - Guard flags (Control Flow Guard, Export Suppression)
  - Process heap protection settings
- **Resource Extraction**: Version info, icons, manifest parsing
- **Certificate Validation**: Authenticode signature verification
- **String Analysis**: Unsafe C/C++ functions, sensitive data detection
- **Multiple Output Formats**: Text, JSON, CSV

## Project Structure

```
byt3land_pe_security/
├── __init__.py                 # Package initialization
├── main.py                     # Main entry point and CLI
├── test_analyzer.py            # Test suite
├── constants.py                # All constants and lookup tables
├── models.py                  # Data models (dataclasses)
├── utils.py                   # Utility functions
├── analyzers/                 # Analysis modules
│   ├── __init__.py
│   ├── base.py               # Base analyzer class
│   ├── mitigation_analyzer.py    # Security mitigations
│   ├── import_export_analyzer.py  # DLL imports/exports
│   ├── section_analyzer.py       # PE sections
│   ├── resource_analyzer.py      # Resources (version, icons, manifest)
│   ├── load_config_analyzer.py  # Load configuration analysis
│   ├── packer_analyzer.py       # Packer & obfuscation detection
│   └── string_analyzer.py       # String analysis
└── formatters/                # Output formatters
    ├── __init__.py
    ├── text_formatter.py     # Human-readable text
    ├── json_formatter.py     # JSON structured data
    └── csv_formatter.py      # CSV format
```

## Installation

### Requirements

- Python 3.7+
- pefile: `pip install pefile`
- cryptography (optional): `pip install cryptography` (for detailed certificate analysis)

### Setup

```bash
# Clone or copy the byt3land_pe_security directory
cd byt3land_pe_security

# Install dependencies
pip install -r requirements.txt
# or manually:
pip install pefile
pip install cryptography  # optional
```

## Usage

### Basic Usage

```bash
# Analyze a single file (text output)
python -m byt3land_pe_security.main program.exe

# Or directly
python byt3land_pe_security/main.py program.exe
```

### Output Formats

```bash
# JSON output
python -m byt3land_pe_security.main program.exe --format json --output report.json

# CSV output
python -m byt3land_pe_security.main program.exe --format csv --output report.csv

# Verbose mode
python -m byt3land_pe_security.main program.exe --verbose
```

### Batch Analysis

```bash
# Analyze all PE files in a directory
python -m byt3land_pe_security.main directory/ --batch --format json --output batch_report.json
```

### Help

```bash
python -m byt3land_pe_security.main --help
```

## Running Tests

```bash
# Run the test suite
python byt3land_pe_security/test_analyzer.py
```

The test suite verifies:
- Module imports
- Analyzer initialization
- Utility functions
- Data models
- Formatters

## Module Details

### Analyzers

#### MitigationAnalyzer
- Checks ASLR (Address Space Layout Randomization)
- Checks DEP/NX (Data Execution Prevention)
- Checks SafeSEH (Structured Exception Handler)
- Checks CFG (Control Flow Guard)
- Checks High Entropy VA
- Parses and validates digital certificates

#### ImportExportAnalyzer
- Extracts imported DLLs and functions
- Detects suspicious API calls
- Identifies local DLL loading risks
- Extracts exported functions
- **Advanced Features**:
  - Delay load imports detection (runtime DLL loading)
  - Bound imports analysis
  - Import hash (imphash) calculation
  - Export anomaly detection
  - Import ordinal usage analysis

#### SectionAnalyzer
- Analyzes PE sections
- Calculates entropy for each section
- Detects packers (high entropy sections)
- Identifies W^X violations (writable + executable)

#### PackerAnalyzer
- Comprehensive packer and obfuscation detection
- **Entropy Distribution Analysis**:
  - Block-level entropy calculation (4KB blocks)
  - Per-section entropy analysis
  - High entropy block identification
- **Known Packer Signatures**:
  - Detects 20+ common packers (UPX, Themida, VMProtect, etc.)
  - Confidence-based identification (High/Medium/Low)
  - Section name pattern matching
- **Visual Entropy Analysis**:
  - Per-block entropy data for graphing
  - Section entropy distribution metrics
- **Overlay Detection**:
  - Identifies data appended after PE structure
  - Classifies overlay type (encrypted, ZIP, RAR, etc.)
  - Calculates overlay entropy
- **Resource Anomaly Detection**:
  - High entropy resource sections
  - Unusually large resources
  - Suspicious resource entries
- **Comprehensive Packer Identification**:
  - Multi-factor analysis (entropy, signatures, overlays, resources)
  - Packer name and confidence level
  - Detailed packer indicators

#### LoadConfigAnalyzer
- Analyzes load configuration directory
- Checks security cookie (/GS) implementation
- Analyzes SEH handler table
- Checks Control Flow Guard flags (CFG, Export Suppression)
- Analyzes process heap protection settings
- Provides detailed load configuration summary

#### StringAnalyzer
- Scans for unsafe C/C++ functions (strcpy, gets, etc.)
- Extracts sensitive strings (API keys, connection strings, etc.)

### Formatters

#### TextFormatter
- Human-readable console output
- Color-coded severity levels
- Comprehensive report sections

#### JSONFormatter
- Machine-readable JSON output
- Full analysis results
- Suitable for automation and integration

#### CSVFormatter
- Spreadsheet-friendly output
- Key findings and mitigations
- Easy import into analysis tools

## Migration from Original Script

If you were using the original `pe_security_analyzer.py`, the new modular version maintains full compatibility:

```bash
# Old command:
python pe_security_analyzer.py program.exe

# New command:
python -m byt3land_pe_security.main program.exe
```

All features and output formats remain identical. The refactoring only affects internal structure.

## Extending the Tool

### Adding a New Analyzer

1. Create a new analyzer in `analyzers/`:
```python
from .base import BaseAnalyzer
from ..models import Finding

class MyAnalyzer(BaseAnalyzer):
    def analyze(self):
        # Your analysis logic
        finding = Finding(
            category="MyCategory",
            title="My Finding",
            description="Description",
            severity="MEDIUM",
            recommendation="Recommendation"
        )
        self.findings.append(finding)
        return result
```

2. Import and use in `main.py`:
```python
from .analyzers import MyAnalyzer

# In analyze() method:
my_analyzer = MyAnalyzer(self.pe, self.findings, self.verbose)
results = my_analyzer.analyze()
```

### Adding a New Formatter

1. Create a new formatter in `formatters/`:
```python
from ..models import AnalysisReport

class MyFormatter:
    @staticmethod
    def format(report: AnalysisReport):
        # Your formatting logic
        return formatted_string
```

2. Export in `formatters/__init__.py`:
```python
from .my_formatter import MyFormatter

__all__ = [..., 'MyFormatter']
```

## License

This tool is provided for educational and security research purposes.

## Authors

- Byt3land Security Team

## Version

2.0.0 - Modular Edition