"""
Constants and lookup tables for PE security analysis.
Contains all security flags, machine types, and detection patterns.
"""

# DLL Characteristics Flags
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040      # ASLR
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100          # DEP/NX
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200      # No isolation
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400            # No SEH
IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800           # No bind
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000        # WDM driver
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000  # Terminal server aware
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000          # Control Flow Guard
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020   # High Entropy VA

# Load Configuration Guard Flags (IMAGE_GUARD_CF_* flags)
IMAGE_GUARD_CF_INSTRUMENTED = 0x00000100           # Control Flow Guard enabled
IMAGE_GUARD_CFW_INSTRUMENTED = 0x00000200          # Control Flow Guard writes enabled
IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400 # Control Flow Guard function table present
IMAGE_GUARD_SECURITY_COOKIE_UNUSED = 0x00000800    # Security cookie not used
IMAGE_GUARD_PROTECT_DELAYLOAD_IAT = 0x00001000     # Protect delay load IAT
IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 0x00002000  # Delay load IAT in own section
IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 0x00004000  # Export suppression enabled
IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x00008000  # Export suppression info present
IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT = 0x00010000 # Long jump table present
IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xF0000000 # Function table size mask

# Process Heap Flags (HEAP_* flags)
HEAP_GROWABLE = 0x00000002      # Heap is growable
HEAP_TAIL_CHECKING_ENABLED = 0x00000010  # Tail checking enabled
HEAP_FREE_CHECKING_ENABLED = 0x00000020  # Free checking enabled
HEAP_DISABLE_COALESCE_ON_FREE = 0x00000080  # Disable coalesce on free
HEAP_CREATE_ALIGN_16 = 0x00010000  # Aligned on 16-byte boundary
HEAP_CREATE_ENABLE_TRACING = 0x00020000  # Enable tracing
HEAP_CREATE_ENABLE_EXECUTE = 0x00040000  # Enable execute

# Machine Types
MACHINE_TYPES = {
    0x014c: "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0x0200: "Intel Itanium",
    0x01c0: "ARM",
    0xaa64: "ARM64",
    0x01c4: "ARMNT (Thumb-2)"
}

# Subsystem Types
SUBSYSTEM_TYPES = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "XBOX"
}

# Known Suspicious DLLs
SUSPICIOUS_DLLS = [
    "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe", "powershell.exe",
    "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
    "cmstp.exe", "msiexec.exe", "forfiles.exe", "pcalua.exe"
]

# Known Suspicious API Functions
SUSPICIOUS_APIS = {
    # Process/Thread Manipulation
    "CreateRemoteThread": "Process injection",
    "OpenProcess": "Process access",
    "VirtualAllocEx": "Memory allocation in remote process",
    "WriteProcessMemory": "Process memory write",
    "ReadProcessMemory": "Process memory read",
    "NtCreateThreadEx": "Thread creation",
    "RtlCreateUserThread": "Thread creation",

    # Memory Manipulation
    "VirtualAlloc": "Executable memory allocation",
    "VirtualProtect": "Memory protection change",
    "WriteProcessMemory": "Process write",
    "NtMapViewOfSection": "Section mapping",

    # Registry Manipulation
    "RegOpenKeyEx": "Registry access",
    "RegSetValueEx": "Registry write",
    "RegCreateKeyEx": "Registry creation",

    # File Operations
    "CreateFile": "File creation",
    "WriteFile": "File write",
    "CopyFile": "File copy",
    "MoveFile": "File move",
    "DeleteFile": "File delete",

    # Network Operations
    "InternetOpen": "Internet connection",
    "InternetOpenUrl": "URL download",
    "InternetReadFile": "Internet read",
    "URLDownloadToFile": "Direct download",
    "WinHttpOpen": "HTTP connection",
    "WinHttpOpenRequest": "HTTP request",

    # Shellcode/Code Execution
    "WinExec": "Process execution",
    "ShellExecute": "Shell execution",
    "CreateProcess": "Process creation",

    # Cryptography
    "CryptEncrypt": "Encryption",
    "CryptDecrypt": "Decryption",
    "CryptHashData": "Hash computation",

    # Anti-Analysis
    "IsDebuggerPresent": "Debugger detection",
    "CheckRemoteDebuggerPresent": "Remote debugger detection",
    "OutputDebugString": "Debug string",
    "GetTickCount": "Timing check",
    "QueryPerformanceCounter": "Timing check",
    "GetSystemTime": "Time check",

    # Privilege Escalation
    "AdjustTokenPrivileges": "Token modification",
    "OpenProcessToken": "Token access",
    "LookupPrivilegeValue": "Privilege lookup",
    "EnablePrivileges": "Enable privileges",

    # DLL Injection
    "LoadLibrary": "DLL loading",
    "LoadLibraryA": "DLL loading",
    "LoadLibraryW": "DLL loading",
    "GetProcAddress": "Function resolution",
    "SetWindowsHookEx": "Hook installation",

    # Credential Access
    "SamIConnect": "SAM database access",
    "SamIGetDomainInformation": "Domain info",
    "LsaCallAuthenticationPackage": "Credential package"
}

# Strings that indicate suspicious content
SUSPICIOUS_STRINGS = [
    r"http://", r"https://", r"ftp://", r"smb://",
    r"\.tmp", r"\.temp", r"\.bat", r"\.vbs", r"\.ps1",
    r"cmd\.exe", r"powershell", r"wscript", r"cscript",
    r"HACKTOOLS", r"TOOLS", r"Suspicious", r"Malware",
    r"password", r"credential", r"token", r"api_key",
    r"eval\s*\(", r"exec\s*\(", r"system\s*\(",
    r"shellcode", r"exploit", r"payload"
]

# High Entropy Strings (potential encrypted/packed data)
HIGH_ENTROPY_THRESHOLD = 7.0

# Historically unsafe C/C++ runtime functions
UNSAFE_C_FUNCTIONS = {
    "strcpy": "Buffer overflow - no bounds checking",
    "strcat": "Buffer overflow - no bounds checking",
    "sprintf": "Buffer overflow - no bounds checking",
    "vsprintf": "Buffer overflow - no bounds checking",
    "gets": "Buffer overflow - no length limit",
    "scanf": "Buffer overflow - no bounds checking",
    "fscanf": "Buffer overflow - no bounds checking",
    "sscanf": "Buffer overflow - no bounds checking",
    "strncpy": "May not null-terminate - use strlcpy instead",
    "strncat": "May not null-terminate - use strlcat instead",
    "memcpy": "Buffer overflow risk if length unchecked",
    "memmove": "Buffer overflow risk if length unchecked",
    "wstrcpy": "Wide string version - no bounds checking",
    "wstrcat": "Wide string version - no bounds checking",
    "wcsncpy": "Wide string version - may not null-terminate",
    "wcsncat": "Wide string version - may not null-terminate",
    "swprintf": "Wide string - no bounds checking",
    "vswprintf": "Wide string - no bounds checking"
}

# Sensitive string regex patterns
SENSITIVE_STRING_PATTERNS = {
    "Potential AWS Key": r"AKIA[0-9A-Z]{16}",
    "Potential Generic API Key": r"(?i)(api[_-]?key|apikey|access[_-]?key)[\s:=]+[A-Za-z0-9_\-]{20,}",
    "Potential Azure Key": r"[0-9a-f]{32}",
    "SQL Connection String": r"(?i)(Server|Data Source|Host)[\s=;]+.*?;(Database|Initial Catalog)[\s=;]+.*?;(User Id|UID|User)[\s=;]+",
    "MongoDB Connection String": r"mongodb://[^\s\"']+",
    "Private IP Address": r"(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
    "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "URL with Credentials": r"(?i)[a-z]+://[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[^\s\"']+",
    "Base64 String": r"[A-Za-z0-9+/]{40,}={0,2}"
}