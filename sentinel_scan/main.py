#!/usr/bin/env python3
"""
SentinelScan - Web Security Testing Tool
A comprehensive CLI tool for security testing and reconnaissance.
"""

import argparse
import sys
import logging
from datetime import datetime
from pathlib import Path

from modules.header_checker import HeaderChecker
from modules.port_scanner import PortScanner
from modules.xss_scanner import XSSScanner
from modules.sql_injection_scanner import SQLInjectionScanner
from modules.subdomain_finder import SubdomainFinder


def setup_logging():
    """Configure logging system"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"sentinelscan_{timestamp}.log"

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)


def run_header_check(args, logger):
    """Execute HTTP header security check"""
    logger.info(f"Starting header check for: {args.url}")
    checker = HeaderChecker(args.url)
    results = checker.check_headers()
    checker.display_results(results)


def run_port_scan(args, logger):
    """Execute port scanning"""
    logger.info(f"Starting port scan on: {args.target}")
    scanner = PortScanner(args.target)
    results = scanner.scan_ports(args.ports)
    scanner.display_results(results)


def run_xss_scan(args, logger):
    """Execute XSS vulnerability scan"""
    logger.info(f"Starting XSS scan on: {args.url}")
    scanner = XSSScanner(args.url)
    results = scanner.scan()
    scanner.display_results(results)


def run_sqli_scan(args, logger):
    """Execute SQL injection scan"""
    logger.info(f"Starting SQL injection scan on: {args.url}")
    scanner = SQLInjectionScanner(args.url)
    results = scanner.scan()
    scanner.display_results(results)


def run_subdomain_scan(args, logger):
    """Execute subdomain enumeration"""
    logger.info(f"Starting subdomain scan for: {args.domain}")
    finder = SubdomainFinder(args.domain)
    results = finder.scan(wordlist_path=args.wordlist, threads=args.threads)
    finder.display_results(results)

    if args.output:
        finder.export_results(args.output)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="SentinelScan - Web Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Header checker command
    headers_parser = subparsers.add_parser('headers', help='Check HTTP security headers')
    headers_parser.add_argument('--url', required=True, help='Target URL')

    # Port scanner command
    port_parser = subparsers.add_parser('portscan', help='Scan open ports')
    port_parser.add_argument('--target', required=True, help='Target IP or hostname')
    port_parser.add_argument('--ports', default='1-1000', help='Port range (default: 1-1000)')

    # XSS scanner command
    xss_parser = subparsers.add_parser('xss', help='Scan for XSS vulnerabilities')
    xss_parser.add_argument('--url', required=True, help='Target URL')

    # SQL injection scanner command
    sqli_parser = subparsers.add_parser('sqli', help='Scan for SQL injection vulnerabilities')
    sqli_parser.add_argument('--url', required=True, help='Target URL')

    # Subdomain finder command
    subdomain_parser = subparsers.add_parser('subdomain', help='Find subdomains')
    subdomain_parser.add_argument('--domain', required=True, help='Target domain')
    subdomain_parser.add_argument('--wordlist', help='Path to subdomain wordlist')
    subdomain_parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    subdomain_parser.add_argument('--output', help='Output file path')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    logger = setup_logging()
    logger.info(f"SentinelScan started - Command: {args.command}")

    try:
        if args.command == 'headers':
            run_header_check(args, logger)
        elif args.command == 'portscan':
            run_port_scan(args, logger)
        elif args.command == 'xss':
            run_xss_scan(args, logger)
        elif args.command == 'sqli':
            run_sqli_scan(args, logger)
        elif args.command == 'subdomain':
            run_subdomain_scan(args, logger)

        logger.info("Scan completed successfully")

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

