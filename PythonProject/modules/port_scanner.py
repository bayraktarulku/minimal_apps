"""
Port Scanner Module
Scans target hosts for open TCP ports.
"""

import socket
import concurrent.futures
import logging
from typing import List, Dict
from datetime import datetime


logger = logging.getLogger(__name__)


class PortScanner:
    """TCP port scanner with service detection"""

    COMMON_SERVICES = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }

    def __init__(self, target: str, timeout: float = 1.0):
        self.target = target
        self.timeout = timeout

    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string"""
        try:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                return list(range(start, end + 1))
            elif ',' in port_range:
                return [int(p.strip()) for p in port_range.split(',')]
            else:
                return [int(port_range)]
        except ValueError:
            logger.error(f"Invalid port range: {port_range}")
            return []

    def _scan_port(self, port: int) -> Dict:
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()

            if result == 0:
                service = self.COMMON_SERVICES.get(port, 'Unknown')
                logger.info(f"Port {port} is OPEN ({service})")
                return {
                    'port': port,
                    'state': 'OPEN',
                    'service': service
                }

        except socket.gaierror:
            logger.error(f"Hostname resolution failed for {self.target}")
        except socket.error as e:
            logger.debug(f"Socket error on port {port}: {str(e)}")

        return None

    def scan_ports(self, port_range: str = "1-1000", max_workers: int = 100) -> Dict:
        """Scan multiple ports concurrently"""
        ports = self._parse_port_range(port_range)

        if not ports:
            return {'error': 'Invalid port range'}

        logger.info(f"Scanning {len(ports)} ports on {self.target}")
        start_time = datetime.now()

        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(self._scan_port, port): port for port in ports}

            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)

        elapsed_time = (datetime.now() - start_time).total_seconds()

        return {
            'target': self.target,
            'ports_scanned': len(ports),
            'open_ports': sorted(open_ports, key=lambda x: x['port']),
            'scan_time': elapsed_time
        }

    def display_results(self, results: Dict):
        """Display scan results"""
        if 'error' in results:
            print(f"\n[ERROR] {results['error']}")
            return

        print(f"\n{'='*70}")
        print(f"PORT SCAN RESULTS")
        print(f"{'='*70}")
        print(f"Target: {results['target']}")
        print(f"Ports Scanned: {results['ports_scanned']}")
        print(f"Scan Time: {results['scan_time']:.2f} seconds")
        print(f"{'='*70}\n")

        if results['open_ports']:
            print(f"OPEN PORTS ({len(results['open_ports'])} found):")
            print("-" * 70)
            print(f"{'PORT':<10} {'STATE':<15} {'SERVICE':<20}")
            print("-" * 70)

            for port_info in results['open_ports']:
                print(f"{port_info['port']:<10} {port_info['state']:<15} {port_info['service']:<20}")
        else:
            print("No open ports found.")

        print(f"\n{'='*70}\n")

