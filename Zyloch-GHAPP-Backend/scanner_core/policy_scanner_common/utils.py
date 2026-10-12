import os
import sys
import json
import subprocess
import tempfile
import argparse
from pathlib import Path

# Fix Unicode encoding issues on Windows
if sys.platform == "win32":
    try:
        # Set UTF-8 encoding for stdout and stderr
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        else:
            # Fallback for older Python versions
            import codecs
            if not hasattr(sys.stdout, '_detached'):
                sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer)
                sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer)
                sys.stdout._detached = True
                sys.stderr._detached = True
    except Exception:
        # If all else fails, just continue without Unicode handling
        pass

def safe_print(text):
    """Print text safely, handling Unicode characters on Windows"""
    try:
        print(text)
    except UnicodeEncodeError:
        # Fallback: replace problematic characters
        safe_text = text.encode('ascii', 'replace').decode('ascii')
        print(safe_text)
    except Exception:
        # If even the fallback fails, try printing without encoding
        try:
            print(str(text))
        except Exception:
            pass

def check_opa_installed():
    """Verify OPA is available in PATH"""
    try:
        subprocess.run(['opa', 'version'], 
                       capture_output=True, 
                       text=True, 
                       check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        safe_print("OPA is not installed. Please install OPA and try again.")
        return False

def run_opa_eval(input_data, policy_path, query_path):
    """Run OPA evaluation with the provided input and policy"""
    try:
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmpfile:
            json.dump(input_data, tmpfile)
            tmpfile.flush()
            tmp_path = tmpfile.name
            
        result = subprocess.run(
            ['opa', 'eval', 
             '--format', 'json',
             '-d', policy_path, 
             '-i', tmp_path, 
             query_path],
            capture_output=True,
            text=True,
            check=True
        )
        
        try:
            os.unlink(tmp_path)
        except:
            pass
            
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        safe_print(f"OPA evaluation failed: {e}")
        safe_print(f"OPA stderr: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        safe_print(f"Failed to parse OPA output: {e}")
        return None
    except Exception as e:
        safe_print(f"Error during OPA evaluation: {e}")
        return None

def setup_argparser():
    """Create a common argument parser for all scanners"""
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=str, required=True, help='Directory to store output files')
    parser.add_argument('--scan-type', type=str, choices=['docker', 'kubernetes', 'workflow', 'all'], 
                        default='all', help='Type of scan to perform')
    parser.add_argument('--path', type=str, default=None, 
                        help='Path to scan (defaults to current repository)')
    return parser

def get_repo_root():
    """Get the repository root directory"""
    return os.environ.get('GITHUB_WORKSPACE', os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def create_output_dir(output_dir):
    """Create the output directory if it doesn't exist"""
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def write_markdown_report(findings, output_path, title, file_key='file'):
    """Write findings to a markdown report"""
    with open(output_path, "w", encoding="utf-8") as md:
        md.write(f"# {title}\n\n")
        
        if not findings:
            md.write("✅ No policy violations found.\n")
        else:
            # Group findings by file
            files_with_findings = {}
            for finding in findings:
                file_path = finding.get(file_key, 'Unknown')
                if file_path not in files_with_findings:
                    files_with_findings[file_path] = []
                files_with_findings[file_path].append(finding)
            
            # Write findings for each file
            for file_path, file_findings in files_with_findings.items():
                md.write(f"## File: `{file_path}`\n\n")
                for finding in file_findings:
                    # Handle different finding formats
                    if 'deny' in finding:
                        # Docker/Kubernetes format
                        for msg in finding['deny']:
                            md.write(f"- {msg}\n")
                    elif 'description' in finding:
                        # Workflow format
                        severity = finding.get("severity", "").upper()
                        prefix = f"({severity})"
                        if severity == "CRITICAL":
                            prefix = f"❌ {prefix}"
                        elif severity == "MEDIUM":
                            prefix = f"⚠️ {prefix}"
                        else:
                            prefix = f"ℹ️ {prefix}"
                        md.write(f"### {prefix}: [{finding.get('policy', 'Unknown')}] {finding['description']}\n")
                        md.write(f"  - **Code**: {finding.get('code', 'N/A')}\n")
                        md.write(f"  - **Learn more**: {finding.get('url', 'N/A')}\n")
                        md.write(f"  - **Line**: {finding.get('line', 'N/A')}\n")
                        md.write(f"  - **Match**: {finding.get('match', 'N/A')}\n")
                md.write("\n")
    
    safe_print(f"\nScan results written to: {output_path}")
    return output_path

def print_summary(findings, scan_type):
    """Print a summary of findings to the console"""
    if not findings:
        safe_print(f"\n✅ No policy violations found in {scan_type} scan")
        return
    
    safe_print(f"\nSummary of {scan_type} findings:")
    
    # Group findings by file
    files_with_findings = {}
    for finding in findings:
        file_path = finding.get('file', 'Unknown')
        if file_path not in files_with_findings:
            files_with_findings[file_path] = []
        files_with_findings[file_path].append(finding)
    
    # Print findings for each file
    for file_path, file_findings in files_with_findings.items():
        safe_print(f"\nFile: {file_path}")
        for finding in file_findings:
            # Handle different finding formats
            if 'deny' in finding:
                # Docker/Kubernetes format
                for msg in finding['deny']:
                    safe_print(f"  - {msg}")
            elif 'description' in finding:
                # Workflow format
                severity = finding.get("severity", "").upper()
                prefix = f"({severity})"
                if severity == "CRITICAL":
                    prefix = f"❌ {prefix}"
                elif severity == "MEDIUM":
                    prefix = f"⚠️ {prefix}"
                else:
                    prefix = f"ℹ️ {prefix}"
                safe_print(f"  {prefix}: [{finding.get('policy', 'Unknown')}] {finding['description']}")
