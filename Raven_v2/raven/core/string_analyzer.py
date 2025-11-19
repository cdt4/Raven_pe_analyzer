"""
Analyzes and categorizes strings found in binaries.
"""
import re


# These are APIs commonly used in malware
SUSPICIOUS_APIS = {
    'kernel32.dll': [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'LoadLibraryA', 'GetProcAddress', 'CreateProcessA', 'OpenProcess',
        'TerminateProcess', 'ReadProcessMemory', 'VirtualProtect',
        'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next'
    ],
    'advapi32.dll': [
        'RegSetValueExA', 'RegCreateKeyExA', 'RegDeleteKeyA', 'RegOpenKeyExA',
        'AdjustTokenPrivileges', 'LookupPrivilegeValueA', 'OpenProcessToken'
    ],
    'urlmon.dll': [
        'URLDownloadToFileA', 'URLDownloadToCacheFileA'
    ],
    'wininet.dll': [
        'InternetOpenA', 'InternetOpenUrlA', 'InternetReadFile', 'InternetConnectA',
        'InternetSetOptionA', 'HttpOpenRequestA', 'HttpSendRequestA'
    ],
    'shell32.dll': [
        'ShellExecuteExW', 'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA'
    ],
    'ws2_32.dll': [
        'socket', 'connect', 'send', 'recv', 'bind', 'listen', 'accept',
        'gethostbyname', 'WSAStartup', 'WSACleanup'
    ],
    'user32.dll': [
        'SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState',
        'GetForegroundWindow', 'GetWindowTextA', 'BlockInput'
    ],
    'ntdll.dll': [
        'NtCreateThreadEx', 'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
        'NtWriteVirtualMemory', 'NtResumeThread', 'RtlCreateUserThread'
    ]
}


def classify_string(text):
    """Figure out what kind of string this is - URL, path, registry key, etc."""
    if not text or len(text) < 4:
        return 'other'
    
    lower_text = text.lower()
    
    # Check for web addresses
    if re.search(r'((http|https|ftp)://|www\.)[^\s/$.?#].[^\s]*', text, re.IGNORECASE):
        return 'url'
    
    # Windows file paths
    if re.match(r'^[a-zA-Z]:\\[\\S|*\S]?.*$', text):
        return 'file_path'
    if '/' in text and ('\\' in text or ('.' in text and ' ' not in text)):
        return 'file_path'
    
    # Registry keys
    if text.startswith('HKEY_') or '\\Software\\' in text or '\\Microsoft\\' in text:
        return 'registry_key'
    
    # IP addresses
    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', text):
        return 'ip_address'
    
    # Domain names
    if re.search(r'\b[a-zA-Z0-9-]+\.(com|org|net|info|biz|ru|cn|uk|de|fr|io|gov|edu|xyz|top|site|online)\b', lower_text):
        return 'domain'
    
    # Executable files
    if text.endswith(('.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs', '.scr', '.cpl', '.js', '.jar')):
        return 'executable'
    
    # Malware-related keywords
    bad_words = [
        'temp', 'appdata', 'localappdata', 'mozilla', 'chrome',
        'password', 'key', 'secret', 'token', 'admin', 'backdoor',
        'exploit', 'inject', 'payload', 'malware', 'virus', 'rootkit',
        'crypt', 'ransom', 'spy', 'logger', 'keylogger', 'bot', 'miner',
        'stealer', 'rat', 'trojan', 'worm', 'botnet', 'cobaltstrike',
        'metasploit', 'empire', 'processhacker', 'wireshark'
    ]
    if any(word in lower_text for word in bad_words):
        return 'suspicious'
    
    # Error messages
    if 'error' in lower_text or 'fail' in lower_text or 'not found' in lower_text:
        return 'error_message'
    
    # Cryptocurrency wallet addresses
    if re.search(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', text):  # Bitcoin
        return 'crypto_wallet'
    if re.search(r'\b0x[a-fA-F0-9]{40}\b', text):  # Ethereum
        return 'crypto_wallet'
    
    return 'other'


def extract_ascii_strings(data, min_len=4):
    """Pull out readable ASCII strings from binary data."""
    results = []
    current = bytearray()
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable characters
            current.append(byte)
        else:
            if len(current) >= min_len:
                try:
                    string = current.decode('ascii')
                    category = classify_string(string)
                    results.append((string, category))
                except UnicodeDecodeError:
                    pass
            current = bytearray()
    
    # Don't forget the last string
    if len(current) >= min_len:
        try:
            string = current.decode('ascii')
            category = classify_string(string)
            results.append((string, category))
        except UnicodeDecodeError:
            pass
    
    return results


def extract_unicode_strings(data, min_len=4):
    """Extract Unicode (UTF-16LE) strings from binary data."""
    results = []
    current = bytearray()
    i = 0
    
    while i < len(data) - 1:
        # Look for ASCII char followed by null byte (UTF-16LE pattern)
        if 32 <= data[i] <= 126 and data[i+1] == 0:
            current.append(data[i])
            i += 2
        else:
            if len(current) >= min_len:
                try:
                    string = current.decode('ascii')
                    category = classify_string(string)
                    results.append((string, category))
                except UnicodeDecodeError:
                    pass
            current = bytearray()
            i += 1
    
    # Handle last string
    if len(current) >= min_len:
        try:
            string = current.decode('ascii')
            category = classify_string(string)
            results.append((string, category))
        except UnicodeDecodeError:
            pass
    
    return results
