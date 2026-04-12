"""
Resource analyzer.
Extracts and analyzes version info, icons, and manifests from PE resources.
"""

import re
import struct
from typing import List

from ..models import VersionInfo, IconInfo, ManifestInfo, Finding, SeverityLevel


class ResourceAnalyzer:
    """
    Analyzer for PE resources.
    Extracts version information, icons, and application manifests.
    """

    def __init__(self, pe, findings_list: list, verbose: bool = False):
        """
        Initialize resource analyzer.
        
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

    def extract_version_info(self) -> VersionInfo:
        """
        Extract version information from PE resources.
        
        Returns:
            VersionInfo object with extracted version details
        """
        version_info = VersionInfo()

        if not self.pe:
            return version_info

        try:
            if not hasattr(self.pe, 'VS_VERSIONINFO'):
                self.log("No version information found")
                return version_info

            # Extract version info using pefile's version info
            if hasattr(self.pe, 'FileInfo'):
                for fileinfo in self.pe.FileInfo:
                    if fileinfo.Key.decode('utf-8') == 'StringFileInfo':
                        for string_table in fileinfo.StringTable:
                            if hasattr(string_table, 'entries'):
                                for entry in string_table.entries.items():
                                    if isinstance(entry[0], bytes):
                                        key = entry[0].decode('utf-8', errors='ignore')
                                        value = entry[1].decode('utf-8', errors='ignore')
                                    else:
                                        key = entry[0]
                                        value = entry[1]

                                    # Map string keys to version info fields
                                    key_lower = key.lower()
                                    if key_lower == 'fileversion':
                                        version_info.file_version = value
                                    elif key_lower == 'productversion':
                                        version_info.product_version = value
                                    elif key_lower == 'companyname':
                                        version_info.company_name = value
                                    elif key_lower == 'productname':
                                        version_info.product_name = value
                                    elif key_lower == 'legalcopyright':
                                        version_info.copyright = value
                                    elif key_lower == 'originalfilename':
                                        version_info.original_filename = value
                                    elif key_lower == 'internalname':
                                        version_info.internal_name = value
                                    elif key_lower == 'filedescription':
                                        version_info.file_description = value
                                    elif key_lower == 'legaltrademarks':
                                        version_info.trademark = value
                                    elif key_lower == 'privatebuild':
                                        version_info.private_build = value
                                    elif key_lower == 'specialbuild':
                                        version_info.special_build = value
                                    elif key_lower == 'comments':
                                        version_info.comments = value

                self.log(f"Version info extracted - Company: {version_info.company_name}, Product: {version_info.product_name}")

        except Exception as e:
            self.log(f"Error extracting version info: {e}")

        return version_info

    def extract_icons(self) -> List[IconInfo]:
        """
        Extract icon information from PE resources.
        
        Returns:
            List of IconInfo objects
        """
        icons = []

        if not self.pe:
            return icons

        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                self.log("No resources found - icon extraction skipped")
                return icons

            # Find icon group resource (type 14)
            icon_group_entry = None
            for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(entry, 'id') and entry.id == 14:  # RT_GROUP_ICON
                    icon_group_entry = entry
                    break

            if not icon_group_entry:
                self.log("No icon group found")
                return icons

            # Extract icon group data
            dir_type = icon_group_entry.directory
            if hasattr(dir_type, 'entries'):
                for entry_idx, group_entry in enumerate(dir_type.entries):
                    try:
                        icon_data = self.pe.get_data(group_entry.data.struct.OffsetToData, group_entry.data.struct.Size)
                        icon_info = IconInfo(index=entry_idx)
                        
                        # Parse icon header (ICONDIR and ICONDIRENTRY structures)
                        if len(icon_data) >= 6:
                            icon_count = struct.unpack('<H', icon_data[4:6])[0]
                            
                            entry_offset = 6 + (16 * entry_idx)
                            if entry_offset + 16 <= len(icon_data):
                                width = icon_data[entry_offset]
                                height = icon_data[entry_offset + 1]
                                bit_depth = struct.unpack('<H', icon_data[entry_offset + 6:entry_offset + 8])[0]
                                size_bytes = struct.unpack('<I', icon_data[entry_offset + 8:entry_offset + 12])[0]
                                
                                icon_info.width = width if width > 0 else 256
                                icon_info.height = height if height > 0 else 256
                                icon_info.bit_depth = bit_depth
                                icon_info.size_bytes = size_bytes
                                icon_info.data = icon_data[entry_offset:entry_offset + 16]
                        
                        icons.append(icon_info)
                    except Exception as e:
                        self.log(f"Error parsing icon {entry_idx}: {e}")

                self.log(f"Extracted {len(icons)} icon(s)")

        except Exception as e:
            self.log(f"Error extracting icons: {e}")

        return icons

    def parse_manifest(self) -> ManifestInfo:
        """
        Parse application manifest from PE resources.
        
        Returns:
            ManifestInfo object with parsed manifest details
        """
        manifest_info = ManifestInfo()

        if not self.pe:
            return manifest_info

        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                self.log("No resources found - manifest parsing skipped")
                return manifest_info

            # Find manifest resource (type 24)
            manifest_entry = None
            for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(entry, 'id') and entry.id == 24:  # RT_MANIFEST
                    manifest_entry = entry
                    break

            if not manifest_entry:
                self.log("No manifest resource found")
                return manifest_info

            # Extract manifest data
            dir_type = manifest_entry.directory
            if hasattr(dir_type, 'entries'):
                for lang_entry in dir_type.entries:
                    try:
                        manifest_data = self.pe.get_data(lang_entry.data.struct.OffsetToData, lang_entry.data.struct.Size)
                        manifest_str = manifest_data.decode('utf-8', errors='ignore').strip('\x00')
                        
                        manifest_info.is_manifest_embedded = True
                        manifest_info.manifest_xml = manifest_str
                        
                        # Parse execution level
                        exec_level_match = re.search(r'requestedExecutionLevel\s+level=["\']([^"\']+)["\']', manifest_str, re.IGNORECASE)
                        if exec_level_match:
                            manifest_info.requested_execution_level = exec_level_match.group(1)
                            
                            level = manifest_info.requested_execution_level.lower()
                            if 'requireadministrator' in level:
                                manifest_info.execution_level = "Administrator"
                            elif 'highestavailable' in level:
                                manifest_info.execution_level = "Highest Available"
                            elif 'asinvoker' in level:
                                manifest_info.execution_level = "As Invoker"
                            else:
                                manifest_info.execution_level = level
                        
                        # Parse UI access
                        ui_access_match = re.search(r'uiAccess\s*=\s*["\']([^"\']+)["\']', manifest_str, re.IGNORECASE)
                        if ui_access_match:
                            manifest_info.ui_access = ui_access_match.group(1).lower() == 'true'
                        
                        # Extract compatibility modes
                        compatibility_modes = []
                        compat_sections = re.findall(r'<compatibility[^>]*>.*?</compatibility>', manifest_str, re.IGNORECASE | re.DOTALL)
                        for section in compat_sections:
                            guids = re.findall(r'\{[0-9a-fA-F-]{36}\}', section)
                            compatibility_modes.extend(guids)
                        
                        supported_os = re.search(r'<supportedOS[^>]*Id=["\']([^"\']+)["\']', manifest_str, re.IGNORECASE)
                        if supported_os:
                            compatibility_modes.append(f"OS: {supported_os.group(1)}")
                        
                        manifest_info.compatibility_modes = list(set(compatibility_modes))
                        
                        self.log(f"Manifest parsed - Execution Level: {manifest_info.execution_level}")
                        
                        # Add findings for high privilege requirements
                        if 'administrator' in manifest_info.execution_level.lower():
                            self.findings.append(Finding(
                                category="Security",
                                title="High Privilege Requirement",
                                description=f"Application requires {manifest_info.execution_level} privileges",
                                severity=str(SeverityLevel.MEDIUM.value),
                                recommendation="Evaluate if administrator privileges are truly necessary"
                            ))
                        
                    except Exception as e:
                        self.log(f"Error parsing manifest data: {e}")

        except Exception as e:
            self.log(f"Error parsing manifest: {e}")

        return manifest_info