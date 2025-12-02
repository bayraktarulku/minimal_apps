"""
HTTP Security Header Checker Module
Analyzes HTTP response headers for security vulnerabilities.
"""

import requests
import logging
from typing import Dict, List
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


class HeaderChecker:
    """Checks HTTP security headers for best practices"""

    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'Enforces HTTPS connections',
            'severity': 'HIGH'
        },
        'X-Frame-Options': {
            'description': 'Prevents clickjacking attacks',
            'severity': 'HIGH'
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME sniffing',
            'severity': 'MEDIUM'
        },
        'Content-Security-Policy': {
            'description': 'Controls resource loading',
            'severity': 'HIGH'
        },
        'X-XSS-Protection': {
            'description': 'Enables XSS filtering',
            'severity': 'MEDIUM'
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information',
            'severity': 'LOW'
        },
        'Permissions-Policy': {
            'description': 'Controls browser features',
            'severity': 'LOW'
        }
    }

    def __init__(self, url: str, timeout: int = 10):
        self.url = url if url.startswith('http') else f'https://{url}'
        self.timeout = timeout

    def check_headers(self) -> Dict:
        """Perform header security check"""
        try:
            logger.info(f"Fetching headers from {self.url}")
            response = requests.get(
                self.url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True
            )

            results = {
                'url': self.url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'security_analysis': self._analyze_security(response.headers),
                'missing_headers': self._find_missing_headers(response.headers),
                'server_info': response.headers.get('Server', 'Not disclosed')
            }

            return results

        except requests.exceptions.SSLError:
            logger.error(f"SSL certificate error for {self.url}")
            return {'error': 'SSL certificate validation failed'}
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout for {self.url}")
            return {'error': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {'error': str(e)}

    def _analyze_security(self, headers: Dict) -> List[Dict]:
        """Analyze security headers"""
        findings = []

        for header, info in self.SECURITY_HEADERS.items():
            if header in headers:
                findings.append({
                    'header': header,
                    'value': headers[header],
                    'status': 'PRESENT',
                    'severity': info['severity'],
                    'description': info['description']
                })
            else:
                findings.append({
                    'header': header,
                    'value': None,
                    'status': 'MISSING',
                    'severity': info['severity'],
                    'description': info['description']
                })

        return findings

    def _find_missing_headers(self, headers: Dict) -> List[str]:
        """Find missing security headers"""
        return [
            header for header in self.SECURITY_HEADERS.keys()
            if header not in headers
        ]

    def display_results(self, results: Dict):
        """Display analysis results"""
        if 'error' in results:
            print(f"\n[ERROR] {results['error']}")
            return

        print(f"\n{'='*70}")
        print(f"HTTP SECURITY HEADER ANALYSIS")
        print(f"{'='*70}")
        print(f"URL: {results['url']}")
        print(f"Status Code: {results['status_code']}")
        print(f"Server: {results['server_info']}")
        print(f"{'='*70}\n")

        print("SECURITY HEADERS ANALYSIS:")
        print("-" * 70)

        for finding in results['security_analysis']:
            status_symbol = "[+]" if finding['status'] == 'PRESENT' else "[-]"
            severity = finding['severity']

            print(f"{status_symbol} {finding['header']:<30} [{severity}]")
            print(f"    {finding['description']}")
            if finding['value']:
                print(f"    Value: {finding['value'][:60]}")
            print()

        missing_count = len(results['missing_headers'])
        total_count = len(self.SECURITY_HEADERS)
        score = ((total_count - missing_count) / total_count) * 100

        print(f"{'='*70}")
        print(f"SECURITY SCORE: {score:.1f}% ({total_count - missing_count}/{total_count} headers present)")
        print(f"{'='*70}\n")

