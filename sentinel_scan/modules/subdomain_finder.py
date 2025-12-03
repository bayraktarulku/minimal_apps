"""
Subdomain Finder Module
Discovers subdomains through DNS enumeration and brute-forcing.
"""

import dns.resolver
import concurrent.futures
import logging
from typing import List, Set
from pathlib import Path


logger = logging.getLogger(__name__)


class SubdomainFinder:
    """Discovers subdomains of a target domain"""

    DEFAULT_WORDLIST = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
        'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
        'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
        'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
        'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
        'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my',
        'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
        'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums',
        'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en'
    ]

    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        self.found_subdomains: Set[str] = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

    def load_wordlist(self, wordlist_path: str = None) -> List[str]:
        """Load subdomain wordlist from file or use default"""
        if wordlist_path:
            try:
                path = Path(wordlist_path)
                if path.exists():
                    with open(path, 'r') as f:
                        wordlist = [line.strip().lower() for line in f if line.strip()]
                    logger.info(f"Loaded {len(wordlist)} subdomains from {wordlist_path}")
                    return wordlist
                else:
                    logger.warning(f"Wordlist not found: {wordlist_path}, using default")
            except Exception as e:
                logger.error(f"Error loading wordlist: {str(e)}")

        return self.DEFAULT_WORDLIST

    def _check_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain exists via DNS lookup"""
        full_domain = f"{subdomain}.{self.domain}"

        try:
            # Try A record
            answers = self.resolver.resolve(full_domain, 'A')
            if answers:
                ips = [str(rdata) for rdata in answers]
                self.found_subdomains.add(full_domain)
                logger.info(f"[+] Found: {full_domain} -> {', '.join(ips)}")
                return True

        except dns.resolver.NXDOMAIN:
            # Domain does not exist
            pass
        except dns.resolver.NoAnswer:
            # Domain exists but no A record, try CNAME
            try:
                answers = self.resolver.resolve(full_domain, 'CNAME')
                if answers:
                    self.found_subdomains.add(full_domain)
                    logger.info(f"[+] Found (CNAME): {full_domain}")
                    return True
            except:
                pass
        except dns.resolver.NoNameservers:
            logger.warning(f"No nameservers found for {full_domain}")
        except dns.exception.Timeout:
            logger.debug(f"Timeout for {full_domain}")
        except Exception as e:
            logger.debug(f"Error checking {full_domain}: {str(e)}")

        return False

    def scan(self, wordlist_path: str = None, threads: int = 10) -> Set[str]:
        """Perform subdomain enumeration"""
        wordlist = self.load_wordlist(wordlist_path)
        total = len(wordlist)

        logger.info(f"Starting subdomain scan for {self.domain}")
        logger.info(f"Testing {total} subdomains with {threads} threads")

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._check_subdomain, sub): sub
                      for sub in wordlist}

            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                if completed % 10 == 0:
                    logger.info(f"Progress: {completed}/{total}")

        logger.info(f"Scan complete. Found {len(self.found_subdomains)} subdomains")
        return self.found_subdomains

    def export_results(self, output_file: str):
        """Export results to file"""
        try:
            with open(output_file, 'w') as f:
                for subdomain in sorted(self.found_subdomains):
                    f.write(f"{subdomain}\n")
            logger.info(f"Results exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting results: {str(e)}")

    def display_results(self, results: Set[str]):
        """Display scan results"""
        print(f"\n{'='*70}")
        print(f"SUBDOMAIN ENUMERATION RESULTS")
        print(f"{'='*70}")
        print(f"Target Domain: {self.domain}")
        print(f"Subdomains Found: {len(results)}")
        print(f"{'='*70}\n")

        if results:
            print("DISCOVERED SUBDOMAINS:")
            print("-" * 70)
            for subdomain in sorted(results):
                print(f"  [+] {subdomain}")
        else:
            print("No subdomains discovered.")

        print(f"\n{'='*70}\n")

