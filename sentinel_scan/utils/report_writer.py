import json
import os
from datetime import datetime


class ReportWriter:
    def __init__(self, report_dir='reports'):
        self.report_dir = report_dir
        os.makedirs(report_dir, exist_ok=True)

    def write_report(self, scan_type, target, results):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{scan_type}_{timestamp}.json"
        filepath = os.path.join(self.report_dir, filename)

        report = {
            'scan_type': scan_type,
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': results
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        return filepath

    def write_full_report(self, target, all_results):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"full_scan_{timestamp}.json"
        filepath = os.path.join(self.report_dir, filename)

        report = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scans': all_results
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        return filepath

