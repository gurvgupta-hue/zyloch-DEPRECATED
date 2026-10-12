"""
AWS Security Checkers Orchestrator

Manages execution of all security checkers, aggregation of results,
reporting, and integration with CI/CD pipelines.
"""

import json
import sys
from typing import Dict, List, Any, Optional
from collections import defaultdict
from pathlib import Path
from datetime import datetime

from . import CHECKER_REGISTRY, CHECKERS_BY_SERVICE


class CheckerOrchestrator:
    """Orchestrates execution of security checkers."""
    
    def __init__(self, terraform_plan: Dict[str, Any], 
                 verbose: bool = False,
                 filter_services: Optional[List[str]] = None,
                 filter_severity: Optional[List[str]] = None):
        """
        Initialize orchestrator.
        
        Args:
            terraform_plan: Parsed Terraform plan
            verbose: Enable verbose output
            filter_services: Only run checkers for specific services
            filter_severity: Only report violations at specified severity levels
        """
        self.plan = terraform_plan
        self.verbose = verbose
        self.filter_services = filter_services
        self.filter_severity = filter_severity or ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        self.violations = []
        self.execution_time = None
    
    def run_all_checkers(self) -> List[Dict[str, Any]]:
        """Run all registered checkers."""
        if self.verbose:
            print("[*] Starting security checks...")
        
        start_time = datetime.now()
        
        # Determine which checkers to run
        if self.filter_services:
            checkers_to_run = []
            for service in self.filter_services:
                if service in CHECKERS_BY_SERVICE:
                    checkers_to_run.extend(CHECKERS_BY_SERVICE[service])
        else:
            checkers_to_run = list(CHECKER_REGISTRY.values())
        
        # Execute each checker
        for checker_class in checkers_to_run:
            try:
                checker = checker_class(self.plan)
                violations = checker.check()
                
                if self.verbose and violations:
                    print(f"[+] {checker_class.__name__}: {len(violations)} findings")
                
                self.violations.extend(violations)
            except Exception as e:
                print(f"[!] Error running {checker_class.__name__}: {str(e)}", 
                      file=sys.stderr)
                if self.verbose:
                    import traceback
                    traceback.print_exc()
        
        # Filter by severity
        self.violations = [
            v for v in self.violations 
            if v.get('severity') in self.filter_severity
        ]
        
        end_time = datetime.now()
        self.execution_time = (end_time - start_time).total_seconds()
        
        if self.verbose:
            print(f"[*] Check completed in {self.execution_time:.2f}s")
        
        return self.violations
    
    def run_service_checkers(self, service: str) -> List[Dict[str, Any]]:
        """Run checkers for a specific service."""
        if service not in CHECKERS_BY_SERVICE:
            raise ValueError(f"Unknown service: {service}")
        
        self.violations = []
        for checker_class in CHECKERS_BY_SERVICE[service]:
            try:
                checker = checker_class(self.plan)
                self.violations.extend(checker.check())
            except Exception as e:
                print(f"[!] Error running {checker_class.__name__}: {str(e)}", 
                      file=sys.stderr)
        
        return self.violations
    
    def get_violations_by_severity(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group violations by severity."""
        result = defaultdict(list)
        for violation in self.violations:
            result[violation['severity']].append(violation)
        return dict(result)
    
    def get_violations_by_service(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group violations by service."""
        result = defaultdict(list)
        for violation in self.violations:
            policy_id = violation['policy_id']
            # Extract service from policy ID (e.g., AWS-SEC-S3-001 -> S3)
            parts = policy_id.split('-')
            if len(parts) >= 3:
                service = parts[2]
                result[service].append(violation)
        return dict(result)
    
    def get_violations_by_resource(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group violations by resource."""
        result = defaultdict(list)
        for violation in self.violations:
            resource = violation['resource_name']
            result[resource].append(violation)
        return dict(result)
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate execution summary."""
        by_severity = self.get_violations_by_severity()
        by_service = self.get_violations_by_service()
        
        return {
            'total_violations': len(self.violations),
            'by_severity': {k: len(v) for k, v in by_severity.items()},
            'by_service': {k: len(v) for k, v in by_service.items()},
            'execution_time_seconds': self.execution_time,
            'checked_services': list(by_service.keys()),
            'checked_resources': len(self.get_violations_by_resource()),
        }
    
    def generate_report_text(self) -> str:
        """Generate human-readable report."""
        lines = []
        lines.append("=" * 80)
        lines.append("AWS SECURITY COMPLIANCE REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Summary
        summary = self.generate_summary()
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Violations:           {summary['total_violations']}")
        lines.append(f"Execution Time:             {summary['execution_time_seconds']:.2f}s")
        lines.append(f"Services Checked:           {', '.join(summary['checked_services'])}")
        lines.append("")
        
        # By Severity
        lines.append("BY SEVERITY")
        lines.append("-" * 80)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = summary['by_severity'].get(severity, 0)
            lines.append(f"{severity:12} {count:5} findings")
        lines.append("")
        
        # By Service
        lines.append("BY SERVICE")
        lines.append("-" * 80)
        by_service = self.get_violations_by_service()
        for service in sorted(by_service.keys()):
            count = len(by_service[service])
            lines.append(f"{service:20} {count:5} findings")
        lines.append("")
        
        # Detailed Violations
        lines.append("DETAILED VIOLATIONS")
        lines.append("=" * 80)
        
        violations_by_severity = self.get_violations_by_severity()
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity not in violations_by_severity:
                continue
            
            violations = violations_by_severity[severity]
            if not violations:
                continue
            
            lines.append("")
            lines.append(f"{severity} SEVERITY ({len(violations)} findings)")
            lines.append("-" * 80)
            
            for i, v in enumerate(violations, 1):
                lines.append(f"{i}. [{v['policy_id']}]")
                lines.append(f"   Resource: {v['resource_type']} / {v['resource_name']}")
                lines.append(f"   Finding:  {v['message']}")
                lines.append(f"   Fix:      {v['remediation']}")
                lines.append("")
        
        lines.append("=" * 80)
        return "\n".join(lines)
    
    def export_json(self, filepath: str) -> None:
        """Export violations as JSON."""
        output = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'execution_time_seconds': self.execution_time,
            },
            'summary': self.generate_summary(),
            'violations': self.violations,
        }
        
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
    
    def export_csv(self, filepath: str) -> None:
        """Export violations as CSV."""
        import csv
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    'policy_id',
                    'severity',
                    'resource_type',
                    'resource_name',
                    'message',
                    'remediation',
                    'check_function'
                ]
            )
            writer.writeheader()
            writer.writerows(self.violations)
    
    def print_report(self) -> None:
        """Print human-readable report to stdout."""
        print(self.generate_report_text())


def load_terraform_plan(filepath: str) -> Dict[str, Any]:
    """Load Terraform plan from file."""
    with open(filepath, 'r') as f:
        if filepath.endswith('.json'):
            return json.load(f)
        else:
            raise ValueError("Unsupported plan format. Use JSON.")


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Run AWS security checks on Terraform plans'
    )
    parser.add_argument('--plan', required=True,
                        help='Path to Terraform plan file (JSON)')
    parser.add_argument('--services',
                        help='Comma-separated list of services to check')
    parser.add_argument('--severity',
                        default='CRITICAL,HIGH,MEDIUM,LOW',
                        help='Comma-separated list of severity levels')
    parser.add_argument('--report', help='Output report file (text)')
    parser.add_argument('--json', help='Output JSON file')
    parser.add_argument('--csv', help='Output CSV file')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Load plan
        plan = load_terraform_plan(args.plan)
        
        # Parse filters
        filter_services = None
        if args.services:
            filter_services = [s.strip() for s in args.services.split(',')]
        
        filter_severity = [s.strip() for s in args.severity.split(',')]
        
        # Run orchestrator
        orchestrator = CheckerOrchestrator(
            plan,
            verbose=args.verbose,
            filter_services=filter_services,
            filter_severity=filter_severity
        )
        
        violations = orchestrator.run_all_checkers()
        
        # Generate reports
        orchestrator.print_report()
        
        if args.report:
            with open(args.report, 'w') as f:
                f.write(orchestrator.generate_report_text())
            print(f"\n[+] Report saved to {args.report}")
        
        if args.json:
            orchestrator.export_json(args.json)
            print(f"[+] JSON export saved to {args.json}")
        
        if args.csv:
            orchestrator.export_csv(args.csv)
            print(f"[+] CSV export saved to {args.csv}")
        
        # Exit with error if critical violations found
        summary = orchestrator.generate_summary()
        critical_count = summary['by_severity'].get('CRITICAL', 0)
        if critical_count > 0:
            print(f"\n[!] {critical_count} CRITICAL violations found. Exiting with error code.", file=sys.stderr)
            sys.exit(1)
        
    except Exception as e:
        print(f"[!] Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
