"""
Main analyzer that coordinates all the analysis components.
"""
import os
from collections import defaultdict
from colorama import Fore, Style

from raven.parsing import (
    load_pe_file, get_basic_info, calculate_file_hashes,
    parse_sections, parse_imports, parse_exports, parse_resources,
    check_for_overlay
)
from raven.core import (
    calculate_entropy, extract_ascii_strings, extract_unicode_strings,
    calculate_risk_level, find_packer_signatures, check_entry_point_patterns,
    check_section_weirdness, check_entropy_issues
)
from raven.disasm import CodeDisassembler
from raven.reporting import generate_text_report, generate_json_report, generate_html_report, save_report


class PEAnalyzer:
    """Coordinates all analysis tasks for a PE file."""
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None
        self.disassembler = None
        
        # Results storage
        self.results = {
            'basic_info': {},
            'file_hashes': {},
            'sections': [],
            'imports': {},
            'exports': {},
            'resources': [],
            'suspicious_findings': [],
            'suspicious_imports': [],
            'strings': defaultdict(list),
            'anomalies': [],
            'overlay': None,
            'packer_info': {},
            'functions': [],
            'api_calls': [],
            'risk': 'Low',
            'risk_score': 0,
            'risk_factors': []
        }
    
    def run_full_analysis(self):
        """Execute all analysis steps."""
        print(f"{Fore.GREEN}[*] Starting analysis of {self.file_path}{Style.RESET_ALL}")
        
        # Load the PE
        self.pe = load_pe_file(self.file_path)
        if not self.pe:
            return False
        
        self.disassembler = CodeDisassembler(self.pe)
        
        # Run all analyses
        self.analyze_basic_info()
        self.analyze_hashes()
        self.analyze_sections()
        self.analyze_imports()
        self.analyze_exports()
        self.analyze_resources()
        self.analyze_entry_point()
        self.detect_packers()
        self.check_overlay()
        self.extract_strings()
        self.detect_functions()
        self.calculate_risk()
        
        print(f"{Fore.GREEN}[+] Analysis complete!{Style.RESET_ALL}")
        return True
    
    def analyze_basic_info(self):
        """Get basic PE file information."""
        self.results['basic_info'] = get_basic_info(self.pe, self.file_path)
    
    def analyze_hashes(self):
        """Calculate file hashes."""
        self.results['file_hashes'] = calculate_file_hashes(self.file_path)
    
    def analyze_sections(self):
        """Parse sections and check for anomalies."""
        self.results['sections'] = parse_sections(self.pe)
        
        # Add suspicious findings for high entropy sections
        for section in self.results['sections']:
            if section['is_suspicious']:
                self.results['suspicious_findings'].append({
                    'type': 'high_entropy_section',
                    'section': section['name'],
                    'entropy': section['entropy'],
                    'message': f"High entropy in section {section['name']} ({section['entropy']:.2f}) - possibly packed"
                })
            
            # Track anomalies
            if section['anomalies']:
                for anomaly_msg in section['anomalies']:
                    self.results['anomalies'].append({
                        'type': 'section_anomaly',
                        'section': section['name'],
                        'message': anomaly_msg
                    })
    
    def analyze_imports(self):
        """Parse imports and flag suspicious ones."""
        imports, suspicious = parse_imports(self.pe)
        self.results['imports'] = imports
        self.results['suspicious_imports'] = suspicious
        self.results['suspicious_findings'].extend(suspicious)
    
    def analyze_exports(self):
        """Parse exports."""
        self.results['exports'] = parse_exports(self.pe)
    
    def analyze_resources(self):
        """Parse resources."""
        self.results['resources'] = parse_resources(self.pe)
    
    def analyze_entry_point(self):
        """Analyze the entry point for suspicious patterns."""
        try:
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_section = self.pe.get_section_by_rva(ep)
            
            if ep_section:
                ep_data = ep_section.get_data()
                ep_offset = ep - ep_section.VirtualAddress
                ep_code = ep_data[ep_offset:ep_offset+32]
                
                entropy = calculate_entropy(ep_code)
                if entropy > 7.5:
                    self.results['suspicious_findings'].append({
                        'type': 'high_entropy_entry',
                        'entropy': entropy,
                        'message': f"High entropy at entry point ({entropy:.2f}) - possible packed code"
                    })
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Entry point analysis failed: {e}{Style.RESET_ALL}")
    
    def detect_packers(self):
        """Look for packer signatures and patterns."""
        try:
            with open(self.file_path, 'rb') as f:
                file_data = f.read()
            
            # Check signatures
            packers = find_packer_signatures(file_data)
            for packer in packers:
                self.results['suspicious_findings'].append({
                    'type': 'packer_signature',
                    'packer': packer,
                    'message': f"Packer detected: {packer}"
                })
            
            # Check entry point patterns
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_section = self.pe.get_section_by_rva(ep)
            
            if ep_section:
                ep_data = ep_section.get_data()
                ep_offset = ep - ep_section.VirtualAddress
                ep_code = ep_data[ep_offset:ep_offset+32]
                
                patterns = check_entry_point_patterns(ep_code)
                for pattern in patterns:
                    self.results['suspicious_findings'].append({
                        'type': 'packer_pattern',
                        'packer': pattern,
                        'message': f"Packer pattern detected: {pattern}"
                    })
            
            # Check section weirdness
            section_issues = check_section_weirdness(self.results['sections'])
            for issue in section_issues:
                self.results['anomalies'].append({
                    'type': 'packer_anomaly',
                    'message': issue
                })
            
            # Check entropy issues
            entropy_issues = check_entropy_issues(self.results['sections'])
            for issue in entropy_issues:
                self.results['anomalies'].append({
                    'type': 'entropy_anomaly',
                    'message': issue
                })
            
            self.results['packer_info'] = {
                'signatures': packers,
                'patterns': patterns,
                'section_issues': section_issues,
                'entropy_issues': entropy_issues
            }
            
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Packer detection failed: {e}{Style.RESET_ALL}")
    
    def check_overlay(self):
        """Check for overlay data."""
        overlay = check_for_overlay(self.pe, self.file_path)
        if overlay:
            self.results['overlay'] = overlay
            if overlay.get('contains_pe'):
                self.results['suspicious_findings'].append({
                    'type': 'embedded_pe',
                    'message': "Overlay may contain embedded PE file"
                })
    
    def extract_strings(self, min_len=4):
        """Extract and classify strings."""
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # Extract both ASCII and Unicode strings
            ascii_strings = extract_ascii_strings(data, min_len)
            unicode_strings = extract_unicode_strings(data, min_len)
            
            # Combine and organize by type
            for string, string_type in ascii_strings + unicode_strings:
                self.results['strings'][string_type].append(string)
                
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: String extraction failed: {e}{Style.RESET_ALL}")
    
    def detect_functions(self):
        """Detect function boundaries."""
        if self.disassembler:
            try:
                functions = self.disassembler.find_functions()
                self.results['functions'] = functions
                self.results['api_calls'] = self.disassembler.api_calls
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Function detection failed: {e}{Style.RESET_ALL}")
    
    def calculate_risk(self):
        """Calculate overall risk level."""
        self.results['risk'] = calculate_risk_level(self.results)
    
    def generate_report(self, format_type='text'):
        """Generate a report in the specified format."""
        if format_type == 'json':
            return generate_json_report(self.results)
        elif format_type == 'html':
            return generate_html_report(self.results, self.file_path)
        else:
            return generate_text_report(self.results, self.file_path)
    
    def save_report(self, output_path, format_type='text'):
        """Save report to a file."""
        return save_report(self.results, self.file_path, output_path, format_type)
