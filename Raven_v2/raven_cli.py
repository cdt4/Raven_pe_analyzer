#!/usr/bin/env python3
"""
Raven CLI - Command-line interface for PE file analysis.
"""
import argparse
import os
import sys
from colorama import Fore, Style, init

from raven.analyzer import PEAnalyzer

init()


def main():
    parser = argparse.ArgumentParser(
        description="Raven - Advanced PE File Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python raven_cli.py malware.exe
  python raven_cli.py suspicious.dll --report html --output report.html
  python raven_cli.py sample.exe --report json --output analysis.json
        """
    )
    
    parser.add_argument('file', help='Path to the PE file to analyze')
    parser.add_argument(
        '--report', '-r',
        choices=['text', 'json', 'html'],
        default='text',
        help='Report format (default: text)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Save report to file (default: print to console)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed progress information'
    )
    
    args = parser.parse_args()
    
    # Check if file exists
    if not os.path.exists(args.file):
        print(f"{Fore.RED}[!] Error: File not found: {args.file}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Create analyzer
    print(f"{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║              RAVEN PE File Analyzer v2.0                      ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    print()
    
    analyzer = PEAnalyzer(args.file)
    
    # Run analysis
    success = analyzer.run_full_analysis()
    
    if not success:
        print(f"{Fore.RED}[!] Analysis failed{Style.RESET_ALL}")
        sys.exit(1)
    
    # Generate report
    print()
    if args.output:
        print(f"{Fore.CYAN}[*] Saving {args.report} report to: {args.output}{Style.RESET_ALL}")
        success = analyzer.save_report(args.output, args.report)
        if success:
            print(f"{Fore.GREEN}[+] Report saved successfully!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Failed to save report{Style.RESET_ALL}")
            sys.exit(1)
    else:
        # Print to console
        print()
        print(analyzer.generate_report(args.report))
    
    # Show risk summary
    risk = analyzer.results['risk']
    risk_color = {
        'Critical': Fore.RED,
        'High': Fore.YELLOW,
        'Medium': Fore.YELLOW,
        'Low': Fore.GREEN
    }.get(risk, Fore.WHITE)
    
    print()
    print(f"{risk_color}╔═══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{risk_color}║  RISK LEVEL: {risk:^50} ║{Style.RESET_ALL}")
    print(f"{risk_color}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Analysis interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)
