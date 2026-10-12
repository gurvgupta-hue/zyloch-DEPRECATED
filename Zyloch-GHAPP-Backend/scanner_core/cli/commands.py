import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional
from scanner_core.core.validator import DockerSecurityValidator


def validate_file_command(args) -> int:
    """Handle the validate-file command"""
    validator = DockerSecurityValidator()
    
    try:
        violations = validator.validate_file(args.file)
        
        if args.json:
            results = validator.export_json()
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Results saved to {args.output}")
            else:
                print(json.dumps(results, indent=2))
        else:
            validator.print_report(verbose=args.verbose, show_file_details=True)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(validator.export_json(), f, indent=2)
                print(f"\nDetailed results also saved to {args.output}")
        
        # Return exit code based on findings
        if args.fail_on == 'any' and violations:
            return 1
        elif args.fail_on == 'high' and validator.has_high_issues():
            return 1
        elif args.fail_on == 'critical' and validator.has_critical_issues():
            return 1
        
        return 0
        
    except Exception as e:
        print(f"Error validating file: {e}", file=sys.stderr)
        return 2


def validate_directory_command(args) -> int:
    """Handle the validate-directory command"""
    validator = DockerSecurityValidator()
    
    try:
        violations = validator.validate_directory(args.directory, recursive=args.recursive)
        
        if args.json:
            results = validator.export_json()
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Results saved to {args.output}")
            else:
                print(json.dumps(results, indent=2))
        else:
            validator.print_report(verbose=args.verbose, show_file_details=True)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(validator.export_json(), f, indent=2)
                print(f"\nDetailed results also saved to {args.output}")
        
        # Return exit code based on findings
        if args.fail_on == 'any' and violations:
            return 1
        elif args.fail_on == 'high' and validator.has_high_issues():
            return 1
        elif args.fail_on == 'critical' and validator.has_critical_issues():
            return 1
        
        return 0
        
    except Exception as e:
        print(f"Error validating directory: {e}", file=sys.stderr)
        return 2


def validate_files_command(args) -> int:
    """Handle the validate-files command"""
    validator = DockerSecurityValidator()
    
    try:
        violations = validator.validate_files(args.files)
        
        if args.json:
            results = validator.export_json()
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Results saved to {args.output}")
            else:
                print(json.dumps(results, indent=2))
        else:
            validator.print_report(verbose=args.verbose, show_file_details=True)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(validator.export_json(), f, indent=2)
                print(f"\nDetailed results also saved to {args.output}")
        
        # Return exit code based on findings
        if args.fail_on == 'any' and violations:
            return 1
        elif args.fail_on == 'high' and validator.has_high_issues():
            return 1
        elif args.fail_on == 'critical' and validator.has_critical_issues():
            return 1
        
        return 0
        
    except Exception as e:
        print(f"Error validating files: {e}", file=sys.stderr)
        return 2


def list_checkers_command(args) -> int:
    """List all available security checkers"""
    validator = DockerSecurityValidator()
    
    print("Available Docker Security Checkers:")
    print("=" * 50)
    
    for checker in validator.checkers:
        checker_name = checker.__class__.__name__
        docstring = checker.__doc__ or "No description available"
        print(f"\n• {checker_name}")
        print(f"  {docstring}")
        if hasattr(checker, 'SUPPORTED_TYPES'):
            print(f"  Supported types: {', '.join(checker.SUPPORTED_TYPES)}")
    
    return 0


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="Docker Security Validator - Scan Docker files for security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s validate-file Dockerfile
  %(prog)s validate-file docker-compose.yml --verbose --json
  %(prog)s validate-directory ./project --recursive --output results.json
  %(prog)s validate-files Dockerfile docker-compose.yml --fail-on high
  %(prog)s list-checkers
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # validate-file command
    file_parser = subparsers.add_parser('validate-file', help='Validate a single Docker file')
    file_parser.add_argument('file', help='Path to Dockerfile or docker-compose.yml')
    file_parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed violation information')
    file_parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    file_parser.add_argument('--output', '-o', help='Save results to file')
    file_parser.add_argument('--fail-on', choices=['any', 'high', 'critical'], default='any',
                           help='Exit with error code 1 when violations are found (default: any)')
    file_parser.set_defaults(func=validate_file_command)
    
    # validate-directory command
    dir_parser = subparsers.add_parser('validate-directory', help='Validate all Docker files in a directory')
    dir_parser.add_argument('directory', help='Path to directory to scan')
    dir_parser.add_argument('--recursive', '-r', action='store_true', help='Scan subdirectories recursively')
    dir_parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed violation information')
    dir_parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    dir_parser.add_argument('--output', '-o', help='Save results to file')
    dir_parser.add_argument('--fail-on', choices=['any', 'high', 'critical'], default='any',
                           help='Exit with error code 1 when violations are found (default: any)')
    dir_parser.set_defaults(func=validate_directory_command)
    
    # validate-files command
    files_parser = subparsers.add_parser('validate-files', help='Validate multiple Docker files')
    files_parser.add_argument('files', nargs='+', help='Paths to Docker files')
    files_parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed violation information')
    files_parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    files_parser.add_argument('--output', '-o', help='Save results to file')
    files_parser.add_argument('--fail-on', choices=['any', 'high', 'critical'], default='any',
                           help='Exit with error code 1 when violations are found (default: any)')
    files_parser.set_defaults(func=validate_files_command)
    
    # list-checkers command
    list_parser = subparsers.add_parser('list-checkers', help='List all available security checkers')
    list_parser.set_defaults(func=list_checkers_command)
    
    return parser


def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())