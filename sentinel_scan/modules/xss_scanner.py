"""
XSS (Cross-Site Scripting) Scanner Module
Detects reflected and stored XSS vulnerabilities.
"""

import requests
import logging
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup


logger = logging.getLogger(__name__)


class XSSScanner:
    """Scans web applications for XSS vulnerabilities"""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "'-alert('XSS')-'",
        "\"><script>alert('XSS')</script>",
        "<body onload=alert('XSS')>",
        "<input autofocus onfocus=alert('XSS')>",
        "<marquee onstart=alert('XSS')>"
    ]

    def __init__(self, url: str, timeout: int = 10):
        self.url = url if url.startswith('http') else f'https://{url}'
        self.timeout = timeout
        self.session = requests.Session()

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
        """Test form for XSS vulnerabilities"""
        vulnerabilities = []
        action = urljoin(self.url, form['action'] or '')

        for payload in self.XSS_PAYLOADS:
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button']:
                    data[input_field['name']] = payload

            try:
                if form['method'] == 'post':
                    response = self.session.post(action, data=data, timeout=self.timeout)
                else:
                    response = self.session.get(action, params=data, timeout=self.timeout)

                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'url': action,
                        'method': form['method'].upper(),
                        'payload': payload,
                        'parameter': list(data.keys())[0] if data else 'unknown'
                    })
                    logger.warning(f"XSS vulnerability found: {action}")
                    break

            except requests.RequestException as e:
                logger.error(f"Request failed: {str(e)}")

        return vulnerabilities

    def _test_url_params(self) -> List[Dict]:
        """Test URL parameters for XSS"""
        vulnerabilities = []
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            return vulnerabilities

        for param_name in params.keys():
            for payload in self.XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                try:
                    response = self.session.get(test_url, timeout=self.timeout)

                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'url': test_url,
                            'method': 'GET',
                            'payload': payload,
                            'parameter': param_name
                        })
                        logger.warning(f"XSS vulnerability found in URL param: {param_name}")
                        break

                except requests.RequestException as e:
                    logger.error(f"Request failed: {str(e)}")

        return vulnerabilities

    def scan(self) -> Dict:
        """Perform XSS vulnerability scan"""
        logger.info(f"Starting XSS scan on {self.url}")

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
        print(f"XSS VULNERABILITY SCAN RESULTS")
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
            print("[+] No XSS vulnerabilities detected.")

        print(f"\n{'='*70}\n")

