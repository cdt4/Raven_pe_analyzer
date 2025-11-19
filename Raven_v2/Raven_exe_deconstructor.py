import pefile
import capstone
import argparse
import os
import json
import math
import re
from datetime import datetime
import datetime
import hashlib
import zlib
import struct
from collections import defaultdict
from colorama import Fore, Style, init

# Initialize colorama
init()

class EntropyAnalyzer:
    """Class to calculate and analyze entropy of binary data"""
    
    @staticmethod
    def calculate_entropy(data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        counter = defaultdict(int)
        total = len(data)
        
        for byte in data:
            counter[byte] += 1
        
        for count in counter.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def get_entropy_color(entropy):
        """Get color coding for entropy value"""
        if entropy > 7.5:
            return Fore.RED
        elif entropy > 6.5:
            return Fore.YELLOW
        else:
            return Fore.GREEN

class StringAnalyzer:
    """Class to analyze and classify strings"""
    
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
    
    @staticmethod
    def classify_string(s):
        """Classify a string based on its content"""
        if not s or len(s) < 4:
            return 'other'
            
        s_lower = s.lower()
        
        # URL detection
        url_pattern = re.compile(
            r'((http|https|ftp)://|www\.)[^\s/$.?#].[^\s]*', 
            re.IGNORECASE
        )
        if url_pattern.search(s):
            return 'url'
        
        # File path detection
        if re.search(r'^[a-zA-Z]:\\[\\\S|*\S]?.*$', s):
            return 'file_path'
        if '/' in s and ('\\' in s or ('.' in s and ' ' not in s)):
            return 'file_path'
        
        # Registry key detection
        if s.startswith('HKEY_') or '\\Software\\' in s or '\\Microsoft\\' in s:
            return 'registry_key'
        
        # IP address detection
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', s):
            return 'ip_address'
        
        # Domain detection
        if re.search(r'\b[a-zA-Z0-9-]+\.(com|org|net|info|biz|ru|cn|uk|de|fr|io|gov|edu|xyz|top|site|online)\b', s_lower):
            return 'domain'
        
        # Executable names
        if s.endswith(('.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs', '.scr', '.cpl', '.js', '.jar')):
            return 'executable'
        
        # Common suspicious patterns
        suspicious_keywords = [
            'temp', 'appdata', 'localappdata', 'mozilla', 'chrome',
            'password', 'key', 'secret', 'token', 'admin', 'backdoor',
            'exploit', 'inject', 'payload', 'malware', 'virus', 'rootkit',
            'crypt', 'ransom', 'spy', 'logger', 'keylogger', 'bot', 'miner',
            'stealer', 'rat', 'trojan', 'worm', 'botnet', 'cobaltstrike',
            'metasploit', 'empire', 'processhacker', 'wireshark'
        ]
        if any(keyword in s_lower for keyword in suspicious_keywords):
            return 'suspicious'
        
        # Error messages
        if 'error' in s_lower or 'fail' in s_lower or 'not found' in s_lower:
            return 'error_message'
        
        # Crypto wallets/addresses
        if re.search(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', s):  # Bitcoin address
            return 'crypto_wallet'
        if re.search(r'\b0x[a-fA-F0-9]{40}\b', s):  # Ethereum address
            return 'crypto_wallet'
        
        return 'other'

class RiskAssessor:
    """Class to assess risk level based on findings"""
    
    @staticmethod
    def calculate_risk(analysis):
        """Calculate heuristic risk rating with improved accuracy"""
        risk_score = 0
        risk_factors = []
        
        # Basic file info checks
        basic_info = analysis.get('basic_info', {})
        
        # Check for suspicious compilation timestamp
        timestamp = basic_info.get('compilation_timestamp', 0)
        if timestamp == 0 or timestamp < 946684800:  # Before year 2000
            risk_score += 1
            risk_factors.append("Suspicious or missing compilation timestamp")
        
        # High entropy sections (more selective)
        high_entropy_sections = 0
        for section in analysis.get('sections', []):
            if section.get('entropy', 0) > 7.8:  # Increased threshold
                high_entropy_sections += 1
        
        if high_entropy_sections >= 2:
            risk_score += 4  # Multiple high entropy sections is very suspicious
            risk_factors.append(f"Multiple high entropy sections ({high_entropy_sections})")
        elif high_entropy_sections == 1:
            risk_score += 1  # Single high entropy section could be legitimate
            risk_factors.append("Single high entropy section")
        
        # Suspicious imports (weighted by severity)
        critical_apis = 0
        suspicious_apis = 0
        
        for imp in analysis.get('suspicious_imports', []):
            func_name = imp.get('function', '')
            dll_name = imp.get('dll', '')
            
            # Critical APIs that are almost always malicious
            critical_api_patterns = [
                'CreateRemoteThread', 'WriteProcessMemory', 'NtCreateThreadEx',
                'VirtualAllocEx', 'NtAllocateVirtualMemory', 'RtlCreateUserThread',
                'SetWindowsHookEx', 'GetAsyncKeyState', 'BlockInput'
            ]
            
            if any(api in func_name for api in critical_api_patterns):
                critical_apis += 1
            else:
                suspicious_apis += 1
        
        risk_score += critical_apis * 3  # Critical APIs get high weight
        risk_score += min(suspicious_apis, 5)  # Cap suspicious APIs to avoid over-scoring
        
        if critical_apis > 0:
            risk_factors.append(f"Critical malware-associated APIs ({critical_apis})")
        if suspicious_apis > 0:
            risk_factors.append(f"Suspicious APIs ({suspicious_apis})")
        
        # Packer detection (more nuanced)
        packer_signatures = 0
        packer_patterns = 0
        
        for finding in analysis.get('suspicious_findings', []):
            if finding['type'] == 'packer_signature':
                packer_signatures += 1
            elif finding['type'] == 'packer_pattern':
                packer_patterns += 1
        
        if packer_signatures > 0:
            risk_score += 3  # Known packer signatures are concerning
            risk_factors.append(f"Known packer signatures ({packer_signatures})")
        elif packer_patterns > 0:
            risk_score += 1  # Generic patterns are less concerning
            risk_factors.append(f"Generic packer patterns ({packer_patterns})")
        
        # Overlay data (context-dependent)
        if analysis.get('overlay'):
            overlay_size = analysis['overlay'].get('size', 0)
            if overlay_size > 1024 * 1024:  # Large overlay (>1MB) is more suspicious
                risk_score += 2
                risk_factors.append(f"Large overlay data ({overlay_size} bytes)")
            else:
                risk_score += 0.5  # Small overlay might be legitimate
                risk_factors.append(f"Small overlay data ({overlay_size} bytes)")
        
        # Suspicious strings (weighted and capped)
        strings_data = analysis.get('strings', {})
        
        # High-risk string types
        crypto_wallets = len(strings_data.get('crypto_wallet', []))
        if crypto_wallets > 0:
            risk_score += crypto_wallets * 2
            risk_factors.append(f"Cryptocurrency wallets found ({crypto_wallets})")
        
        # Medium-risk string types (capped to avoid over-scoring)
        suspicious_strings = min(len(strings_data.get('suspicious', [])), 10)
        external_urls = min(len(strings_data.get('url', [])), 5)
        ip_addresses = min(len(strings_data.get('ip_address', [])), 3)
        
        risk_score += suspicious_strings * 0.3
        risk_score += external_urls * 0.5
        risk_score += ip_addresses * 0.7
        
        if suspicious_strings > 5:
            risk_factors.append(f"Many suspicious strings ({len(strings_data.get('suspicious', []))})")
        if external_urls > 2:
            risk_factors.append(f"Multiple external URLs ({len(strings_data.get('url', []))})")
        if ip_addresses > 1:
            risk_factors.append(f"Hard-coded IP addresses ({len(strings_data.get('ip_address', []))})")
        
        # Structural anomalies
        anomaly_count = len(analysis.get('anomalies', []))
        if anomaly_count > 3:
            risk_score += 2
            risk_factors.append(f"Multiple structural anomalies ({anomaly_count})")
        elif anomaly_count > 0:
            risk_score += 0.5
            risk_factors.append(f"Structural anomalies ({anomaly_count})")
        
        # Legitimate software indicators (reduce score)
        exports = analysis.get('exports', {}).get('functions', [])
        if len(exports) > 10:  # Libraries often have many exports
            risk_score -= 1
            risk_factors.append(f"Library-like exports ({len(exports)})")
        
        # Digital signature check (would need to be implemented)
        # For now, assume unsigned binaries are slightly more risky
        # This could be enhanced with actual signature verification
        
        # Final risk calculation with more reasonable thresholds
        # Convert to integer to avoid floating point in comparisons
        final_score = int(risk_score)
        
        # Store risk factors for detailed reporting
        analysis['risk_factors'] = risk_factors
        analysis['risk_score'] = final_score
        
        # More balanced thresholds
        if final_score >= 12:  # Increased from 15
            return 'Critical'
        elif final_score >= 7:   # Increased from 10
            return 'High'
        elif final_score >= 3:   # Decreased from 5
            return 'Medium'
        else:
            return 'Low'

class PackerDetector:
    """Enhanced packer and obfuscation detection"""
    
    PACKER_SIGNATURES = {
        b'UPX!': 'UPX',
        b'!EP': 'PECompact',
        b'MPRESS1': 'MPRESS',
        b'MEW': 'MEW',
        b'NsPacK': 'NsPacK',
        b'ASPack': 'ASPack',
        b'FSG!': 'FSG',
        b'RLPack': 'RLPack',
        b'PEC2TO': 'PEC2',
        b'PEC2': 'PEC2',
        b'PELOCK': 'PELock',
        b'Themida': 'Themida',
        b'VMProtect': 'VMProtect',
        b'.aspack': 'ASPack',
        b'.packed': 'Generic Packer',
        b'WinUpack': 'Upack',
        b'PEBundle': 'PEBundle',
        b'Petite': 'Petite',
        b'kkrunchy': 'kkrunchy',
        b'Yoda\'s Crypter': 'Yoda',
        b'ACProtect': 'ACProtect',
        b'EXECryptor': 'EXECryptor',
        b'Obsidium': 'Obsidium',
        b'tElock': 'tElock',
        b'Armadillo': 'Armadillo',
        b'Enigma': 'Enigma Protector'
    }
    
    ENTRY_POINT_PATTERNS = {
        b'\x60\xE8\x00\x00\x00\x00\x5D': 'UPX',
        b'\xE8\x00\x00\x00\x00\xE9\xEB': 'PECompact',
        b'\xFC\x68': 'FSG',
        b'\xEB\x10\x5A\x4A\x33\xC9': 'ASPack',
        b'\xBE\x00\x00\x00\x00\x8D\xBE': 'UPX',
        b'\x60\xBE\x00\x00\x00\x00\x8D\xBE': 'UPX',
        b'\xE8\x00\x00\x00\x00\x58': 'Generic Unpacking Stub'
    }
    
    @staticmethod
    def detect_packer_signatures(data):
        """Detect packer signatures in binary data"""
        detected = []
        for sig, name in PackerDetector.PACKER_SIGNATURES.items():
            if sig in data:
                detected.append(name)
        return detected
    
    @staticmethod
    def detect_entry_point_patterns(ep_data):
        """Detect packer patterns in entry point code"""
        detected = []
        for pattern, name in PackerDetector.ENTRY_POINT_PATTERNS.items():
            if ep_data.startswith(pattern):
                detected.append(name)
        return detected
    
    @staticmethod
    def detect_section_anomalies(sections):
        """Detect anomalies that might indicate packing"""
        anomalies = []
        
        # Check for non-standard section names
        common_sections = {'.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.reloc', '.bss'}
        for section in sections:
            name = section['name']
            if name not in common_sections and not name.startswith('/'):
                anomalies.append(f"Non-standard section name: {name}")
        
        # Check for sections with both write and execute permissions
        for section in sections:
            if (section['characteristics'] & 0x20000000) and (section['characteristics'] & 0x80000000):
                anomalies.append(f"Section {section['name']} has both write and execute permissions")
        
        # Check for sections with zero raw size but non-zero virtual size
        for section in sections:
            if section['raw_size'] == 0 and section['virtual_size'] > 0:
                anomalies.append(f"Section {section['name']} has zero raw size but non-zero virtual size")
        
        return anomalies
    
    @staticmethod
    def detect_entropy_anomalies(sections):
        """Detect entropy anomalies that might indicate packing"""
        anomalies = []
        high_entropy_count = 0
        
        for section in sections:
            entropy = section['entropy']
            if entropy > 7.5:
                high_entropy_count += 1
                anomalies.append(f"High entropy in section {section['name']}: {entropy:.2f}")
        
        if high_entropy_count >= 2:
            anomalies.append(f"Multiple high entropy sections detected ({high_entropy_count})")
        
        return anomalies

class Disassembler:
    """Enhanced disassembler with function detection and API resolution"""
    
    def __init__(self, pe):
        self.pe = pe
        self.arch = capstone.Cs(
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_32 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE else capstone.CS_MODE_64
        )
        self.arch.detail = True
        self.functions = []
        self.api_calls = []
        self.cache = {}
    
    def disassemble_section(self, section_name):
        """Disassemble a specific section with caching"""
        if section_name in self.cache:
            return self.cache[section_name]
        
        output = []
        for section in self.pe.sections:
            if section.Name.decode().strip('\x00') == section_name:
                try:
                    code = section.get_data()
                    code_addr = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    
                    for insn in self.arch.disasm(code, code_addr):
                        output.append(f"0x{insn.address:016X}: {insn.mnemonic} {insn.op_str}")
                        
                        # Detect API calls
                        if insn.mnemonic == 'call' or insn.mnemonic == 'jmp':
                            self._analyze_call(insn, output)
                    
                    # Cache the result
                    self.cache[section_name] = output
                    return output
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error disassembling section {section_name}: {e}{Style.RESET_ALL}")
        
        return []
    
    def _analyze_call(self, insn, output):
        """Analyze call/jmp instructions for API resolution"""
        try:
            # Try to resolve the target address
            target_str = insn.op_str.strip()
            if target_str.startswith('0x'):
                target_addr = int(target_str, 16)
                
                # Check if this is an import
                if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.address == target_addr:
                                api_name = imp.name.decode() if imp.name else f"ord_{imp.ordinal}"
                                output.append(f"        ; -> {entry.dll.decode()}!{api_name}")
                                self.api_calls.append({
                                    'address': insn.address,
                                    'target': target_addr,
                                    'dll': entry.dll.decode(),
                                    'api': api_name
                                })
                                return
        except:
            pass
    
    def detect_functions(self):
        """Detect function boundaries in code sections"""
        self.functions = []
        
        for section in self.pe.sections:
            section_name = section.Name.decode().strip('\x00')
            if section.Characteristics & 0x00000020:  # CODE section
                try:
                    code = section.get_data()
                    code_addr = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    
                    current_function = None
                    
                    for insn in self.arch.disasm(code, code_addr):
                        # Look for function prologues
                        if (insn.mnemonic == 'push' and insn.op_str == 'ebp') or \
                           (insn.mnemonic == 'mov' and insn.op_str == 'ebp, esp'):
                            if current_function:
                                current_function['end'] = insn.address - 1
                                self.functions.append(current_function)
                            
                            current_function = {
                                'start': insn.address,
                                'end': 0,
                                'section': section_name,
                                'size': 0
                            }
                        
                        # Look for function epilogues
                        elif insn.mnemonic == 'ret' and current_function:
                            current_function['end'] = insn.address
                            current_function['size'] = current_function['end'] - current_function['start']
                            self.functions.append(current_function)
                            current_function = None
                    
                    # Handle the last function if any
                    if current_function:
                        current_function['end'] = code_addr + len(code) - 1
                        current_function['size'] = current_function['end'] - current_function['start']
                        self.functions.append(current_function)
                        
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error analyzing functions in section {section_name}: {e}{Style.RESET_ALL}")
        
        return self.functions

class ReportGenerator:
    """Class to generate comprehensive analysis reports in multiple formats"""
    
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.analysis_results = analyzer.analysis_results
    
    def generate_report(self, format_type='text', options=None):
        """Generate report in the specified format"""
        if format_type == 'json':
            return self._generate_json_report(options)
        elif format_type == 'html':
            return self._generate_html_report(options)
        else:
            return self._generate_text_report(options)
    
    def save_report(self, file_path, format_type='text', options=None):
        """Save report to file"""
        report_content = self.generate_report(format_type, options)
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return True
        except Exception as e:
            print(f"Error saving report: {e}")
            return False
    
    def _generate_json_report(self, options=None):
        """Generate JSON report"""
        return json.dumps(self.analysis_results, indent=2, default=str)
    
    def _generate_text_report(self, options=None):
        """Generate comprehensive text analysis report"""
        report = []
        
        # Header
        report.append("=" * 80)
        report.append("RAVEN EXE DECONSTRUCTOR - ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target: {os.path.basename(self.analyzer.file_path)}")
        report.append("")
        
        # Basic info with risk rating
        report.append("=== BASIC INFORMATION ===")
        for key, value in self.analysis_results['basic_info'].items():
            report.append(f"{key.replace('_', ' ').title()}: {value}")
        
        # File hashes
        report.append("\n=== FILE HASHES ===")
        for algo, hash_val in self.analysis_results['file_hashes'].items():
            report.append(f"{algo.upper()}: {hash_val}")
        
        # Risk assessment
        risk = self.analysis_results['risk']
        report.append(f"\n=== RISK ASSESSMENT: {risk} ===")
        
        # Sections with entropy
        report.append("\n=== SECTION ANALYSIS ===")
        for section in self.analysis_results['sections']:
            section_line = (
                f"{section['name']}: "
                f"VA=0x{section['virtual_address']:X}, "
                f"Size=0x{section['virtual_size']:X}, "
                f"Entropy={section['entropy']:.2f}, "
                f"Flags={section['characteristics_human']}"
            )
            
            if section['anomalies']:
                section_line += f" [ANOMALIES: {', '.join(section['anomalies'])}]"
            
            report.append(section_line)
        
        # Resources
        if self.analysis_results['resources']:
            report.append("\n=== RESOURCES ===")
            for resource in self.analysis_results['resources']:
                report.append(f"  {resource['type']} (ID: {resource['id']})")
                if resource['languages']:
                    report.append(f"    Languages: {', '.join(str(lang) for lang in resource['languages'])}")
        
        # Exports
        if self.analysis_results['exports'].get('functions'):
            report.append(f"\n=== EXPORTS ({self.analysis_results['exports']['count']}) ===")
            for exp in self.analysis_results['exports']['functions']:
                report.append(f"  - {exp['name']} (0x{exp['address']:X}, ordinal: {exp['ordinal']})")
        
        # Imports
        if self.analysis_results['imports']:
            report.append("\n=== IMPORTS ===")
            for dll, functions in self.analysis_results['imports'].items():
                report.append(f"{dll}:")
                for func in functions[:15]:  # Show first 15 functions per DLL
                    report.append(f"  - {func}")
                
                if len(functions) > 15:
                    report.append(f"  ... and {len(functions)-15} more")
        
        # Strings (if requested or if limited)
        include_strings = options.get('include_strings', False) if options else False
        string_min_length = options.get('string_min_length', 4) if options else 4
        
        if include_strings and self.analysis_results['strings']:
            report.append("\n=== STRINGS ===")
            
            # Show most important string types first
            important_types = ['url', 'file_path', 'registry_key', 'executable', 
                              'suspicious', 'error_message', 'ip_address', 'domain', 'crypto_wallet']
            
            for s_type in important_types:
                strings = self.analysis_results['strings'].get(s_type, [])
                if strings:
                    report.append(f"  {s_type.upper()} Strings:")
                    for s in strings[:20]:  # Show up to 20 of each important type
                        report.append(f"    - {s}")
                    if len(strings) > 20:
                        report.append(f"    ... and {len(strings)-20} more")
        
        # Overlay info
        if self.analysis_results['overlay']:
            report.append("\n=== OVERLAY DATA ===")
            report.append(
                f"Size: {self.analysis_results['overlay']['size']} bytes, "
                f"Offset: 0x{self.analysis_results['overlay']['offset']:X}"
            )
            report.append(f"Message: {self.analysis_results['overlay']['message']}")
        
        # Suspicious findings
        if self.analysis_results['suspicious_findings']:
            report.append("\n=== SUSPICIOUS FINDINGS ===")
            for finding in self.analysis_results['suspicious_findings']:
                if finding['type'] == 'high_entropy_section':
                    report.append(
                        f"High entropy section: {finding['section']} "
                        f"(Entropy: {finding['entropy']:.2f}) - "
                        f"Possibly packed or encrypted"
                    )
                elif finding['type'] == 'packer_signature':
                    report.append(f"Packer detected: {finding['packer']}")
                elif finding['type'] == 'high_entropy_entry':
                    report.append(
                        f"High entropy at entry point (Entropy: {finding['entropy']:.2f}) - "
                        "Possible packed/encrypted code"
                    )
                elif finding['type'] == 'suspicious_import':
                    report.append(f"Suspicious API: {finding['message']}")
                elif finding['type'] == 'embedded_pe':
                    report.append("Possible embedded PE file in overlay data")
        
        # Anomalies
        if self.analysis_results['anomalies']:
            report.append("\n=== STRUCTURAL ANOMALIES ===")
            for anomaly in self.analysis_results['anomalies']:
                report.append(f"{anomaly.get('section', 'General')}: {anomaly['message']}")
        
        # Functions (if requested)
        include_disassembly = options.get('include_disassembly', False) if options else False
        
        if include_disassembly and self.analysis_results['functions']:
            report.append("\n=== FUNCTIONS ===")
            for func in self.analysis_results['functions'][:50]:  # Show first 50 functions
                report.append(
                    f"Function at 0x{func['start']:X} - 0x{func['end']:X} "
                    f"(Size: {func['size']} bytes, Section: {func['section']})"
                )
        
        return "\n".join(report)
    
    def _generate_html_report(self, options=None):
        """Generate an HTML analysis report"""
        html = []
        html.append("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Raven Analysis Report</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
                h1, h2, h3 { color: #2c3e50; }
                .header { background: #34495e; color: white; padding: 20px; border-radius: 5px; }
                .section { margin-bottom: 30px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .risk-critical { color: #e74c3c; font-weight: bold; }
                .risk-high { color: #e67e22; font-weight: bold; }
                .risk-medium { color: #f39c12; }
                .risk-low { color: #27ae60; }
                .suspicious { color: #e74c3c; }
                .warning { color: #e67e22; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 15px; }
                th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
                th { background-color: #f8f9fa; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .string-list { font-family: monospace; }
                .timestamp { color: #7f8c8d; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Raven EXE Analysis Report</h1>
                <div class="timestamp">Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</div>
                <div class="timestamp">Target: """ + os.path.basename(self.analyzer.file_path) + """</div>
            </div>
        """)
        
        # Basic info
        html.append("<div class='section'><h2>Basic Information</h2>")
        html.append("<table>")
        for key, value in self.analysis_results['basic_info'].items():
            html.append(f"<tr><th>{key.replace('_', ' ').title()}</th><td>{value}</td></tr>")
        html.append("</table></div>")
        
        # File hashes
        html.append("<div class='section'><h2>File Hashes</h2>")
        html.append("<table>")
        for algo, hash_val in self.analysis_results['file_hashes'].items():
            html.append(f"<tr><th>{algo.upper()}</th><td>{hash_val}</td></tr>")
        html.append("</table></div>")
        
        # Risk assessment
        risk = self.analysis_results['risk']
        risk_class = f"risk-{risk.lower()}"
        html.append(f"<div class='section'><h2>Risk Assessment: <span class='{risk_class}'>{risk}</span></h2></div>")
        
        # Sections
        html.append("<div class='section'><h2>Section Analysis</h2>")
        html.append("<table><tr><th>Name</th><th>Virtual Address</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th><th>Flags</th><th>Anomalies</th></tr>")
        for section in self.analysis_results['sections']:
            entropy_class = "suspicious" if section['entropy'] > 7.5 else "warning" if section['entropy'] > 6.5 else ""
            anomalies = ", ".join(section['anomalies']) if section['anomalies'] else ""
            html.append(f"<tr><td>{section['name']}</td><td>0x{section['virtual_address']:X}</td><td>0x{section['virtual_size']:X}</td><td>0x{section['raw_size']:X}</td><td class='{entropy_class}'>{section['entropy']:.2f}</td><td>{section['characteristics_human']}</td><td>{anomalies}</td></tr>")
        html.append("</table></div>")
        
        # Imports
        if self.analysis_results['imports']:
            html.append("<div class='section'><h2>Imports</h2>")
            for dll, functions in self.analysis_results['imports'].items():
                html.append(f"<h3>{dll}</h3><ul>")
                for func in functions:
                    html.append(f"<li>{func}</li>")
                html.append("</ul>")
            html.append("</div>")
        
        # Strings (if requested)
        include_strings = options.get('include_strings', False) if options else False
        string_min_length = options.get('string_min_length', 4) if options else 4
        
        if include_strings and self.analysis_results['strings']:
            html.append("<div class='section'><h2>Strings</h2>")
            
            # Show most important string types first
            important_types = ['url', 'file_path', 'registry_key', 'executable', 
                              'suspicious', 'error_message', 'ip_address', 'domain', 'crypto_wallet']
            
            for s_type in important_types:
                strings = self.analysis_results['strings'].get(s_type, [])
                if strings:
                    html.append(f"<h3>{s_type.upper()} Strings</h3>")
                    html.append("<div class='string-list'><ul>")
                    for s in strings[:20]:  # Show up to 20 of each important type
                        html.append(f"<li>{s}</li>")
                    if len(strings) > 20:
                        html.append(f"<li>... and {len(strings)-20} more</li>")
                    html.append("</ul></div>")
        
        # Suspicious findings
        if self.analysis_results['suspicious_findings']:
            html.append("<div class='section'><h2>Suspicious Findings</h2><ul>")
            for finding in self.analysis_results['suspicious_findings']:
                html.append(f"<li class='suspicious'>{finding['message']}</li>")
            html.append("</ul></div>")
        
        # Functions (if requested)
        include_disassembly = options.get('include_disassembly', False) if options else False
        
        if include_disassembly and self.analysis_results['functions']:
            html.append("<div class='section'><h2>Functions</h2>")
            html.append("<table><tr><th>Address</th><th>Size</th><th>Section</th></tr>")
            for func in self.analysis_results['functions'][:50]:  # Show first 50 functions
                html.append(f"<tr><td>0x{func['start']:X}</td><td>{func['size']} bytes</td><td>{func['section']}</td></tr>")
            html.append("</table></div>")
        
        html.append("""
        </body>
        </html>
        """)
        
        return "\n".join(html)

class PEAnalyzer:
    """Main PE analysis class with all enhanced features"""
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None
        self.disassembler = None
        self.analysis_results = {
            'basic_info': {},
            'sections': [],
            'imports': defaultdict(list),
            'exports': {},
            'resources': [],
            'entropy': {},
            'suspicious_findings': [],
            'suspicious_imports': [],
            'strings': defaultdict(list),
            'anomalies': [],
            'overlay': None,
            'risk': 'Low',
            'file_hashes': {},
            'packer_info': [],
            'functions': [],
            'api_calls': []
        }
    
    def load_pe(self):
        """Load and parse the PE file"""
        try:
            self.pe = pefile.PE(self.file_path, fast_load=True)
            self.pe.parse_data_directories()
            self.disassembler = Disassembler(self.pe)
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading PE file: {e}{Style.RESET_ALL}")
            return False
    
    def calculate_hashes(self):
        """Calculate various file hashes"""
        try:
            with open(self.file_path, 'rb') as f:
                file_data = f.read()
            
            self.analysis_results['file_hashes'] = {
                'md5': hashlib.md5(file_data).hexdigest(),
                'sha1': hashlib.sha1(file_data).hexdigest(),
                'sha256': hashlib.sha256(file_data).hexdigest(),
                'ssdeep': self._calculate_ssdeep(file_data)
            }
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error calculating hashes: {e}{Style.RESET_ALL}")
    
    def _calculate_ssdeep(self, data):
        """Calculate ssdeep fuzzy hash"""
        try:
            import ssdeep
            return ssdeep.hash(data)
        except ImportError:
            return "ssdeep module not available - install with: pip install ssdeep"
        except Exception as e:
            return f"Error calculating ssdeep: {str(e)}"
    
    def analyze_basic_info(self):
        """Analyze basic PE file information"""
        if not self.pe:
            return
        
        # Convert timestamp to human readable format
        timestamp = self.pe.FILE_HEADER.TimeDateStamp
        try:
            compile_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except:
            compile_time = f"Invalid timestamp (0x{timestamp:X})"
        
        self.analysis_results['basic_info'] = {
            'filename': os.path.basename(self.file_path),
            'file_size': os.path.getsize(self.file_path),
            'architecture': 'x64' if self.pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 'x86',
            'entry_point': self.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'image_base': self.pe.OPTIONAL_HEADER.ImageBase,
            'section_count': len(self.pe.sections),
            'compilation_timestamp': timestamp,
            'compilation_time': compile_time,
            'checksum': self.pe.OPTIONAL_HEADER.CheckSum,
            'subsystem': self.pe.OPTIONAL_HEADER.Subsystem,
            'is_dll': bool(self.pe.FILE_HEADER.Characteristics & 0x2000),
            'is_driver': bool(self.pe.FILE_HEADER.Characteristics & 0x1000)
        }
    
    def analyze_sections(self):
        """Analyze PE sections with entropy calculation and anomaly detection"""
        if not self.pe:
            return
        
        previous_section_end = 0
        section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        
        for i, section in enumerate(self.pe.sections):
            try:
                section_data = section.get_data()
                entropy = EntropyAnalyzer.calculate_entropy(section_data)
                
                # Check for anomalies
                anomalies = []
                
                # Check for zero raw size but non-zero virtual size
                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                    anomalies.append("Zero raw size but non-zero virtual size")
                
                # Check if section extends beyond file size
                section_end = section.PointerToRawData + section.SizeOfRawData
                if section_end > len(self.pe.__data__):
                    anomalies.append("Section extends beyond file size")
                
                # Check for overlapping sections
                current_section_start = section.PointerToRawData
                if current_section_start < previous_section_end and i > 0:
                    anomalies.append(f"Overlap with previous section ({previous_section_end:X} < {current_section_start:X})")
                previous_section_end = section.PointerToRawData + section.SizeOfRawData
                
                # Check for non-standard section names
                section_name = section.Name.decode().strip('\x00')
                if not re.match(r'^[.a-zA-Z0-9_]+$', section_name):
                    anomalies.append("Non-standard section name")
                
                # Check for executable sections with write permissions
                if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
                    anomalies.append("Executable section with write permissions (W^X violation)")
                
                section_info = {
                    'name': section_name,
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_address': section.PointerToRawData,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': section.Characteristics,
                    'characteristics_human': self.get_section_characteristics(section.Characteristics),
                    'entropy': entropy,
                    'is_suspicious': entropy > 7.8,  # Match with risk assessment threshold
                    'anomalies': anomalies
                }
                
                self.analysis_results['sections'].append(section_info)
                
                if section_info['is_suspicious']:
                    self.analysis_results['suspicious_findings'].append({
                        'type': 'high_entropy_section',
                        'section': section_name,
                        'entropy': entropy,
                        'message': f"High entropy section detected ({entropy:.2f}) - possibly packed or encrypted"
                    })
                
                if anomalies:
                    for anomaly in anomalies:
                        self.analysis_results['anomalies'].append({
                            'type': 'section_anomaly',
                            'section': section_name,
                            'message': anomaly
                        })
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error analyzing section: {e}{Style.RESET_ALL}")
    
    def get_section_characteristics(self, characteristics):
        """Convert section characteristics to human-readable format"""
        flags = []
        flag_mapping = {
            0x00000020: 'CODE',
            0x00000040: 'INITIALIZED_DATA',
            0x00000080: 'UNINITIALIZED_DATA',
            0x04000000: 'NOT_CACHED',
            0x08000000: 'NOT_PAGED',
            0x10000000: 'SHARED',
            0x20000000: 'EXECUTE',
            0x40000000: 'READ',
            0x80000000: 'WRITE'
        }
        
        for flag, name in flag_mapping.items():
            if characteristics & flag:
                flags.append(name)
        
        return ' | '.join(flags)
    
    def analyze_imports(self):
        """Analyze imports with suspicious API detection"""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll = entry.dll.decode().lower()
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode()
                        self.analysis_results['imports'][dll].append(func_name)
                        
                        # Check for suspicious APIs
                        for suspicious_dll, apis in StringAnalyzer.SUSPICIOUS_APIS.items():
                            if dll == suspicious_dll.lower() and func_name in apis:
                                suspicious_import = {
                                    'type': 'suspicious_import',
                                    'dll': dll,
                                    'function': func_name,
                                    'message': f"Suspicious API imported: {dll}!{func_name}"
                                }
                                self.analysis_results['suspicious_imports'].append(suspicious_import)
                                self.analysis_results['suspicious_findings'].append(suspicious_import)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error analyzing imports: {e}{Style.RESET_ALL}")
    
    def analyze_exports(self):
        """Analyze exports in detail"""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return
        
        try:
            export_dir = self.pe.DIRECTORY_ENTRY_EXPORT
            self.analysis_results['exports'] = {
                'base': export_dir.struct.Base if hasattr(export_dir.struct, 'Base') else 0,
                'count': export_dir.struct.NumberOfFunctions,
                'names_count': export_dir.struct.NumberOfNames,
                'functions': []
            }
            
            for exp in export_dir.symbols:
                if exp.name:
                    self.analysis_results['exports']['functions'].append({
                        'name': exp.name.decode(),
                        'address': exp.address,
                        'ordinal': exp.ordinal
                    })
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error analyzing exports: {e}{Style.RESET_ALL}")
    
    def analyze_resources(self):
        """Analyze resource directory"""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return
        
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        if resource_type.name is not None:
                            name = str(resource_type.name)
                        else:
                            name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, resource_type.struct.Id)
                        
                        resource_entry = {
                            'type': name,
                            'id': resource_type.struct.Id,
                            'languages': []
                        }
                        
                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        if hasattr(resource_lang, 'data'):
                                            lang_id = getattr(resource_lang.data.struct, 'Lang', 
                                                            getattr(resource_lang.data.struct, 'Language', None))
                                            if lang_id is not None:
                                                resource_entry['languages'].append(lang_id)
                        
                        self.analysis_results['resources'].append(resource_entry)
                    except Exception as e:
                        print(f"{Fore.YELLOW}[!] Error processing resource type: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error analyzing resources: {e}{Style.RESET_ALL}")
    
    def detect_packers(self):
        """Detect common packers and cryptors with enhanced heuristics"""
        if not self.pe:
            return
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # Signature-based detection
            packers = PackerDetector.detect_packer_signatures(data)
            for packer in packers:
                self.analysis_results['suspicious_findings'].append({
                    'type': 'packer_signature',
                    'packer': packer,
                    'message': f"Detected packer signature: {packer}"
                })
            
            # Entry point pattern detection
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_section = self.pe.get_section_by_rva(ep)
            
            if ep_section:
                ep_data = ep_section.get_data()
                ep_offset = ep - ep_section.VirtualAddress
                ep_code = ep_data[ep_offset:ep_offset+32]
                
                ep_patterns = PackerDetector.detect_entry_point_patterns(ep_code)
                for pattern in ep_patterns:
                    self.analysis_results['suspicious_findings'].append({
                        'type': 'packer_pattern',
                        'packer': pattern,
                        'message': f"Detected packer pattern: {pattern}"
                    })
            
            # Section anomaly detection
            section_anomalies = PackerDetector.detect_section_anomalies(self.analysis_results['sections'])
            for anomaly in section_anomalies:
                self.analysis_results['anomalies'].append({
                    'type': 'packer_anomaly',
                    'message': anomaly
                })
            
            # Entropy anomaly detection
            entropy_anomalies = PackerDetector.detect_entropy_anomalies(self.analysis_results['sections'])
            for anomaly in entropy_anomalies:
                self.analysis_results['anomalies'].append({
                    'type': 'entropy_anomaly',
                    'message': anomaly
                })
            
            # Compile packer info
            self.analysis_results['packer_info'] = {
                'signatures': packers,
                'patterns': ep_patterns,
                'section_anomalies': section_anomalies,
                'entropy_anomalies': entropy_anomalies
            }
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error detecting packers: {e}{Style.RESET_ALL}")
    
    def analyze_entry_point(self):
        """Analyze the entry point characteristics"""
        if not self.pe:
            return
        
        try:
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_section = self.pe.get_section_by_rva(ep)
            
            if ep_section:
                ep_data = ep_section.get_data()
                ep_offset = ep - ep_section.VirtualAddress
                ep_code = ep_data[ep_offset:ep_offset+32]  # First 32 bytes
                
                entropy = EntropyAnalyzer.calculate_entropy(ep_code)
                self.analysis_results['entropy']['entry_point'] = entropy
                
                if entropy > 7.5:
                    self.analysis_results['suspicious_findings'].append({
                        'type': 'high_entropy_entry',
                        'entropy': entropy,
                        'message': "High entropy at entry point - possible packed/encrypted code"
                    })
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error analyzing entry point: {e}{Style.RESET_ALL}")
    
    def detect_overlay(self):
        """Detect overlay data (data appended after the PE file)"""
        if not self.pe:
            return
        
        try:
            pe_size = self.pe.OPTIONAL_HEADER.SizeOfHeaders
            for section in self.pe.sections:
                pe_size = max(pe_size, section.PointerToRawData + section.SizeOfRawData)
            
            file_size = os.path.getsize(self.file_path)
            
            if file_size > pe_size:
                overlay_size = file_size - pe_size
                self.analysis_results['overlay'] = {
                    'size': overlay_size,
                    'offset': pe_size,
                    'message': f"Found {overlay_size} bytes of overlay data"
                }
                
                # Check if overlay contains PE file
                with open(self.file_path, 'rb') as f:
                    f.seek(pe_size)
                    overlay_data = f.read(min(overlay_size, 4096))  # Read first 4KB of overlay
                    
                    if b'MZ' in overlay_data:
                        self.analysis_results['suspicious_findings'].append({
                            'type': 'embedded_pe',
                            'message': "Overlay may contain embedded PE file"
                        })
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error detecting overlay: {e}{Style.RESET_ALL}")
    
    def disassemble_code(self, section_name=None, output_file=None):
        """Disassemble code sections with caching"""
        if not self.pe or not self.disassembler:
            return None
        
        try:
            if section_name:
                disasm = self.disassembler.disassemble_section(section_name)
            else:
                # Disassemble all code sections
                disasm = []
                for section in self.pe.sections:
                    if section.Characteristics & 0x00000020:  # CODE section
                        section_disasm = self.disassembler.disassemble_section(section.Name.decode().strip('\x00'))
                        disasm.extend(section_disasm)
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write("\n".join(disasm))
            
            return disasm
        except Exception as e:
            print(f"{Fore.RED}[-] Error during disassembly: {e}{Style.RESET_ALL}")
            return None
    
    def detect_functions(self):
        """Detect function boundaries in the binary"""
        if not self.pe or not self.disassembler:
            return []
        
        try:
            functions = self.disassembler.detect_functions()
            self.analysis_results['functions'] = functions
            self.analysis_results['api_calls'] = self.disassembler.api_calls
            return functions
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error detecting functions: {e}{Style.RESET_ALL}")
            return []
    
    def extract_strings(self, min_length=4, output_file=None):
        """Extract and classify strings from the binary with optimization"""
        try:
            # Check if we already extracted strings
            if self.analysis_results['strings'] and not output_file:
                return [(s_type, s) for s_type, strings in self.analysis_results['strings'].items() for s in strings]
            
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            strings = []
            
            # Extract ASCII strings
            ascii_strings = self._extract_ascii_strings(data, min_length)
            strings.extend(ascii_strings)
            
            # Extract Unicode strings
            unicode_strings = self._extract_unicode_strings(data, min_length)
            strings.extend(unicode_strings)
            
            # Classify and store strings
            for s, s_type in strings:
                self.analysis_results['strings'][s_type].append(s)
            
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for s, s_type in strings:
                        f.write(f"[{s_type}] {s}\n")
            
            return strings
        except Exception as e:
            print(f"{Fore.RED}[-] Error extracting strings: {e}{Style.RESET_ALL}")
            return []
    
    def _extract_ascii_strings(self, data, min_length):
        """Extract ASCII strings efficiently"""
        strings = []
        current_string = bytearray()
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(byte)
            else:
                if len(current_string) >= min_length:
                    try:
                        s = current_string.decode('ascii')
                        s_type = StringAnalyzer.classify_string(s)
                        strings.append((s, s_type))
                    except UnicodeDecodeError:
                        pass
                current_string = bytearray()
        
        # Handle the last string
        if len(current_string) >= min_length:
            try:
                s = current_string.decode('ascii')
                s_type = StringAnalyzer.classify_string(s)
                strings.append((s, s_type))
            except UnicodeDecodeError:
                pass
        
        return strings
    
    def _extract_unicode_strings(self, data, min_length):
        """Extract Unicode strings efficiently"""
        strings = []
        current_string = bytearray()
        i = 0
        
        while i < len(data) - 1:
            # Check for UTF-16LE pattern (ASCII char followed by null byte)
            if 32 <= data[i] <= 126 and data[i+1] == 0:
                current_string.append(data[i])
                i += 2
            else:
                if len(current_string) >= min_length:
                    try:
                        s = current_string.decode('ascii')
                        s_type = StringAnalyzer.classify_string(s)
                        strings.append((s, s_type))
                    except UnicodeDecodeError:
                        pass
                current_string = bytearray()
                i += 1
        
        # Handle the last string
        if len(current_string) >= min_length:
            try:
                s = current_string.decode('ascii')
                s_type = StringAnalyzer.classify_string(s)
                strings.append((s, s_type))
            except UnicodeDecodeError:
                pass
        
        return strings
    
    def calculate_risk(self):
        """Calculate heuristic risk rating"""
        self.analysis_results['risk'] = RiskAssessor.calculate_risk(self.analysis_results)
    
    def generate_report(self, format='text', options=None):
        """Generate a comprehensive analysis report in various formats"""
        reporter = ReportGenerator(self)
        return reporter.generate_report(format, options)
    
    def save_analysis(self, output_format='json', options=None):
        """Save analysis results to file"""
        output_file = os.path.splitext(self.file_path)[0] + f'_analysis.{output_format}'
        
        try:
            reporter = ReportGenerator(self)
            return reporter.save_report(output_file, output_format, options)
        except Exception as e:
            print(f"[-] Error saving analysis: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description="Advanced EXE Reverse Engineering Tool")
    parser.add_argument("file", help="Path to the EXE file to analyze")
    parser.add_argument("-d", "--disassemble", action="store_true", help="Disassemble the code sections")
    parser.add_argument("-s", "--strings", action="store_true", help="Extract strings from the binary")
    parser.add_argument("-e", "--entropy", action="store_true", help="Show detailed entropy analysis")
    parser.add_argument("-f", "--functions", action="store_true", help="Detect functions")
    parser.add_argument("-o", "--output", help="Output file for disassembly/strings results")
    parser.add_argument("-a", "--all", action="store_true", help="Run all analysis options")
    parser.add_argument("-save", "--save-analysis", choices=['json', 'txt', 'html'], help="Save full analysis to file")
    parser.add_argument("-format", "--report-format", choices=['text', 'json', 'html'], default='text', help="Format for the report output")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"{Fore.RED}[-] File not found: {args.file}{Style.RESET_ALL}")
        return
    
    analyzer = PEAnalyzer(args.file)
    
    if not analyzer.load_pe():
        return
    
    print(f"{Fore.GREEN}[*] Analyzing: {args.file}{Style.RESET_ALL}")
    
    # Run all analyses
    analyzer.calculate_hashes()
    analyzer.analyze_basic_info()
    analyzer.analyze_sections()
    analyzer.analyze_imports()
    analyzer.analyze_exports()
    analyzer.analyze_resources()
    analyzer.detect_packers()
    analyzer.analyze_entry_point()
    analyzer.detect_overlay()
    analyzer.extract_strings()
    analyzer.calculate_risk()
    
    # Additional analyses
    if args.functions or args.all:
        analyzer.detect_functions()
    
    # Display report
    print(analyzer.generate_report(args.report_format))
    
    # Additional requested analyses
    if args.disassemble or args.all:
        disasm = analyzer.disassemble_code(output_file=args.output)
        if disasm and not args.output:
            print("\n".join(disasm[:200]))  # Show first 200 lines if not saving to file
    
    if args.strings or args.all:
        strings = analyzer.extract_strings(output_file=args.output)
        if strings and not args.output:
            print("\nStrings found (classified):")
            for s, s_type in strings[:100]:  # Show first 100 strings if not saving to file
                color = Fore.RED if s_type in ['suspicious', 'url', 'executable', 'crypto_wallet'] else Fore.YELLOW if s_type != 'other' else ''
                print(f"{color}[{s_type}]{Style.RESET_ALL} {s}")
    
    if args.save_analysis:
        analyzer.save_analysis(args.save_analysis)

if __name__ == "__main__":
    main()