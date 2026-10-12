import os
import sys
import json
import asyncio
import tempfile
import shutil
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path

import numpy as np
import jwt
import requests
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo.database import Database
from bson import ObjectId
import git
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks, File, Form, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pymongo.database import Database
from bson import ObjectId
from dotenv import load_dotenv
load_dotenv()

# Add current directory to Python path for import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


from scanner_core.scan_controller import run_combined_scan
from scanner_core.policy_filter import filter_findings_by_policy
from scanner_core.logging_config import get_fastapi_logger
from scanner_core.helpers.scoring_engine import UnifiedScoringEngine
from scanner_core.helpers.output_formatter import ScanOutputFormatter
from autofix_prompts.autofix_service import generate_autofix
from autofix_prompts.github_pr_service import AutofixPrError, create_autofix_pr
from config.db import get_database as get_db_connection, close_database
from config.tenant_db import (
    get_tenant_db_for_installation,
    get_tenant_settings,
    get_policy_config,
    filter_scan_types_by_settings,
    resolve_tenant_db_required,
)
from middleware.s2s_auth_middleware import S2SAuthMiddleware
from config.webhook_auth import verify_github_webhook
try:
    
    logger = get_fastapi_logger()
    logger.info("Successfully imported scanner modules")
except ImportError as e:
    # Fallback logger if scanner modules fail
    from config.db import get_database as get_db_connection, close_database
    logger = logging.getLogger("combined-api")
    logger.setLevel(logging.INFO)
    logger.error(f"Failed to import scanner modules: {e}")

# Supported scanner keys
# Import GraphQL
try:
    from strawberry.fastapi import GraphQLRouter
    from graphql_api.schema import schema
    logger.info("Successfully imported GraphQL modules")
except ImportError as e:
    logger.warning(f"Failed to import GraphQL modules: {e}")
    schema = None

app = FastAPI(title="Policy Scanner API", version="1.0.0")
# Supported scanner keys (kept in one place for consistency)
SUPPORTED_SCANNERS = ("docker", "kubernetes", "workflow", "secret_scanner", "terraform_azure", "terraform_gcp", "sbom", "terraform_aws", "spec-scanner", "bicep", "ansible", "cloudformation", "skill-scanner", "cis-agent")

_IAC_SCANNERS = ("docker", "kubernetes", "terraform_aws", "terraform_azure", "terraform_gcp", "bicep", "ansible", "cloudformation")
_TERRAFORM_SCANNERS = ("terraform_aws", "terraform_azure", "terraform_gcp")

# --- Scanner Models ---
class ScanRequest(BaseModel):
    org_name: str
    repo_name: str
    branch: str = "main"
    scan_type: str = "all"
    installation_id: str  # GitHub App installation ID (required)
    # Scanners the tenant's plan entitles, resolved by the BFF (MT-05.2).
    # None means "unconstrained" (webhook path); an empty list means nothing runs.
    allowed_scan_types: Optional[List[str]] = None


class AutofixRequest(BaseModel):
    # Required for tenant scoping: the request is authorised against the tenant
    # that owns this installation (see resolve_tenant_db_required).
    installation_id: str = Field(min_length=1, max_length=128)
    policy_code: Optional[str] = None
    policy_name: Optional[str] = None
    description: str = Field(min_length=1, max_length=10000)
    severity: Optional[str] = Field(default=None, max_length=32)
    file: Optional[str] = Field(default=None, max_length=1000)
    line: Optional[str] = Field(default=None, max_length=32)
    scanner_type: Optional[str] = Field(default=None, max_length=64)
    code_block: str = Field(min_length=1, max_length=50000)
    sbom_context: Optional[Dict[str, Any]] = None
    force_refresh: bool = False


class AutofixPrRequest(BaseModel):
    installation_id: str = Field(min_length=1, max_length=128)
    repository: str = Field(min_length=3, max_length=255)
    branch: str = Field(default="main", min_length=1, max_length=255)
    file: str = Field(min_length=1, max_length=1000)
    code_block: str = Field(min_length=1, max_length=50000)
    proposal: str = Field(min_length=1, max_length=100000)


class GitHubInstallationPermissionError(RuntimeError):
    """Raised when GitHub refuses the requested installation token scope."""


# Lifecycle Management
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        logger.info("Initializing database connection...")
        get_db_connection()
        logger.info("Database connection initialized successfully")
            
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)

    yield  # Application runs here

    try:
        logger.info("Closing database connection...")
        close_database()
        logger.info("Database connection closed successfully")
    except Exception as e:
        logger.error(f"Error closing database connection: {e}", exc_info=True)


# FastAPI App Initialization
app = FastAPI(
    title="Policy Scanner & AI Code Check API", 
    version="2.0.0",
    lifespan=lifespan
)

# CORS: this is an internal service-to-service API — the browser never calls it
# directly (the product frontend goes through the backend BFF). `allow_origins=["*"]`
# together with `allow_credentials=True` makes Starlette echo back whatever Origin
# is presented, i.e. any site could make credentialed cross-origin requests.
# Credentials are off, and origins are opt-in via GHAPP_CORS_ORIGINS.
_cors_origins = [
    o.strip() for o in os.getenv("GHAPP_CORS_ORIGINS", "").split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Zyloch-Service-Key"],
)
app.add_middleware(S2SAuthMiddleware)

# MongoDB connection
def get_database() -> Database:
    return get_db_connection()

# GraphQL context — tenant DB + tenantId from BFF headers
async def get_graphql_context(request: Request) -> dict:
    """Provide tenant-scoped database connection to GraphQL context.

    Tenant context is required (KAN-40):
    - ``X-Installation-Id`` (or ``installation_id`` query) → resolve via installation_index
    - and/or ``X-Tenant-Id`` / ``X-Zyloch-Tenant-Id`` set by the BE BFF

    When both are present, they must agree. Resolvers additionally filter by ``tenantId``.
    """
    from config.tenant_db import get_tenant_db, ensure_tenant_scan_indexes

    installation_id = request.headers.get("X-Installation-Id") or request.query_params.get(
        "installation_id"
    )
    header_tenant = request.headers.get("X-Tenant-Id") or request.headers.get("X-Zyloch-Tenant-Id")

    if not installation_id and not header_tenant:
        raise HTTPException(
            status_code=400,
            detail="tenant context required (X-Tenant-Id and/or X-Installation-Id)",
        )

    if installation_id:
        try:
            tenant_db, tenant_id = resolve_tenant_db_required(installation_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        if header_tenant and str(header_tenant) != str(tenant_id):
            raise HTTPException(
                status_code=403,
                detail="X-Tenant-Id does not match installation tenant",
            )
    else:
        tenant_id = str(header_tenant)
        tenant_db = get_tenant_db(tenant_id)
        ensure_tenant_scan_indexes(tenant_db, tenant_id)

    return {
        "db": tenant_db,
        "installation_id": installation_id,
        "tenant_id": str(tenant_id),
        "request": request,
    }


# Add GraphQL endpoint with GraphiQL interface
if schema:
    graphql_app = GraphQLRouter(
        schema,
        context_getter=get_graphql_context,
        graphql_ide="graphiql"
    )
    app.include_router(graphql_app, prefix="/scan/graphql")
    logger.info("GraphQL endpoint mounted at /scan/graphql with GraphiQL interface")

# Pydantic models
class ScanRequest(BaseModel):
    org_name: str
    repo_name: str
    branch: str = "main"
    scan_type: str = "all"
    installation_id: str  # GitHub App installation ID (required)
    # Scanners the tenant's plan entitles, resolved by the BFF (MT-05.2).
    # None means "unconstrained" (webhook path); an empty list means nothing runs.
    allowed_scan_types: Optional[List[str]] = None

# GitHub App JWT generation
def generate_jwt() -> str:
    app_id = os.getenv("GITHUB_APP_ID")
    raw_key = os.getenv("GITHUB_APP_PRIVATE_KEY")

    if not raw_key:
        raise ValueError("GITHUB_APP_PRIVATE_KEY is missing from environment variables.")

    # 2. Strip surrounding quotes (just in case they were captured)
    cleaned_key = raw_key.strip('"').strip("'")

    # 3. Replace literal '\n' characters with actual newline breaks
    private_key = cleaned_key.replace('\\n', '\n')

    # 4. (Optional but recommended) Encode to bytes
    private_key_bytes = private_key.encode('utf-8')

    
    if not app_id or not private_key:
        logger.warning("GitHub App credentials not configured")
        return None
    
    try:
        payload = {
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(minutes=10),
            'iss': app_id
        }
        return jwt.encode(payload, private_key_bytes, algorithm='RS256')
    except Exception as e:
        logger.error(f"Error generating JWT: {e}", exc_info=True)
        return None

def get_installation_token(
    installation_id: str,
    permissions: Optional[dict[str, str]] = None,
    raise_permission_error: bool = False,
) -> str:
    jwt_token = generate_jwt()
    if not jwt_token:
        return None
    
    try:
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        response = requests.post(
            url,
            headers=headers,
            json={"permissions": permissions} if permissions else None,
            timeout=10,
        )
 
        if response.status_code == 201:
            return response.json().get('token')
        logger.error(f"Failed to get installation token: {response.status_code}")
        if raise_permission_error and response.status_code in {401, 403, 404, 422}:
            try:
                github_detail = response.json().get("message")
            except ValueError:
                github_detail = None
            detail_suffix = f" GitHub says: {github_detail}" if github_detail else ""
            raise GitHubInstallationPermissionError(
                "The GitHub App installation cannot grant the requested write access. "
                "Check the App's Contents and Pull requests permissions and approve the "
                f"updated permissions for this installation.{detail_suffix}"
            )
        return None
    except GitHubInstallationPermissionError:
        raise
    except Exception as e:
        logger.error(f"Error getting installation token: {e}", exc_info=True)
        return None

# verify_github_webhook now lives in config/webhook_auth.py (imported above) so it
# can be unit tested without importing the scanner dependency stack (MT-04.1).

def get_commit_hash_from_webhook(event_type: str, webhook_data: dict) -> str:
    try:
        if event_type == "push":
            return webhook_data.get("head_commit", {}).get("id", "")
        elif event_type == "pull_request":
            return webhook_data.get("pull_request", {}).get("head", {}).get("sha", "")
        return ""
    except Exception:
        return ""

def scan_exists_for_commit(db: Database, org_name: str, repo_name: str, commit_hash: str) -> bool:
    if not commit_hash: return False
    query = {
        "scan_metadata.organization": org_name,
        "scan_metadata.repository": repo_name,
        "scan_metadata.commit_hash": commit_hash,
        "scan_status": {"$in": ["running", "completed"]}
    }
    existing_scan = db.scan_summary.find_one(query)
    return existing_scan is not None

def clone_repository(repo_url: str, repo_path: str, branch: str = "main", installation_id: str = None) -> bool:
    try:
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)
        os.makedirs(repo_path, exist_ok=True)
        
        if installation_id:
            token = get_installation_token(installation_id)
            if not token:
                logger.warning(f"Failed to obtain installation token for installation_id={installation_id}. "
                               "Falling back to unauthenticated clone (works for public repos).")
            else:
                repo_url = repo_url.replace("https://github.com/", f"https://x-access-token:{token}@github.com/")
        repo = git.Repo.clone_from(repo_url, repo_path)
        
        if branch != "main":
            try:
                repo.git.checkout(branch)
            except git.exc.GitCommandError:
                repo.git.fetch("origin", branch)
                repo.git.checkout(branch)
        return True
    except Exception as e:
        logger.error(f"Error cloning repository: {e}")
        return False


def run_scanner_background(org_name: str, repo_name: str, repo_url: str, branch: str, scan_type: str, db: Database, installation_id: str = None, event_type: str = None, webhook_commit_hash: str = None, allowed_scan_types: Optional[List[str]] = None):
    scan_id = None
    temp_root = None
    tenant_id = None
    scan_formatter = ScanOutputFormatter()
    
    try:
        # Strategy C: resolve tenant DB from GitHub installation id.
        if not installation_id:
            logger.error("installation_id is required for tenant-scoped scans")
            return
        try:
            db, tenant_id = resolve_tenant_db_required(installation_id)
        except ValueError as e:
            logger.error(str(e))
            return

        # Create unique scan ID
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{org_name}_{repo_name}"
        
        logger.info(f"Starting scan: {scan_id}")
        logger.info(f"Organization: {org_name}, Repository: {repo_name}, Branch: {branch}")
        logger.info(f"Scan Type: {scan_type}, Event Type: {event_type}, URL: {repo_url}")
        
        # Create scan record with new flattened structure
        scan_record = {
            "scan_id": scan_id,
            "scan_status": "running",
            "created_at": datetime.now(),
            "installation_id": installation_id,
            "tenantId": tenant_id,
            "scan_metadata": scan_formatter.create_scan_metadata(
                scan_id=scan_id,
                organization=org_name,
                repository=repo_name,
                branch=branch,
                commit_hash=webhook_commit_hash,
                commit_message=None,
                commit_author=None,
                scan_type=scan_type,
                scan_timestamp=None,
                commit_date=None,
                repository_url=repo_url,
                event_type=event_type,
                tenant_id=tenant_id,
            ),
            "error": None
        }
        
        # Insert scan record (summary collection only)
        db.scan_summary.insert_one(scan_record)
        logger.info(f"Scan summary created in database with status: running")
        
        # Clone repository
        # Ensure the shared bind-mount exists, and make the clone dir traversable
        # by the non-root spec-generator (mkdtemp defaults to 0700).
        shared_tmp_dir = "/app/repos"
        os.makedirs(shared_tmp_dir, exist_ok=True)
        temp_root = tempfile.mkdtemp(prefix=f"zyloch_{scan_id}_", dir=shared_tmp_dir)
        os.chmod(temp_root, 0o755)
        repo_path = os.path.join(temp_root, f"{org_name}_{repo_name}")
        logger.info(f"Cloning repository: {repo_url} to {repo_path}")
        
        if not clone_repository(repo_url, repo_path, branch, installation_id):
            logger.error("Failed to clone repository")
            # Update scan status to failed
            db.scan_summary.update_one(
                {"scan_id": scan_id},
                {"$set": {"scan_status": "failed", "error": "Failed to clone repository"}}
            )
            # Cleanup temp root
            try:
                if os.path.exists(temp_root):
                    shutil.rmtree(temp_root)
            except Exception:
                pass
            return
        
        logger.info("Repository cloned successfully")
        
        # Verify repository exists and has content
        if not os.path.exists(repo_path):
            logger.error(f"Repository path does not exist after cloning: {repo_path}")
            db.scan_summary.update_one(
                {"scan_id": scan_id},
                {"$set": {"scan_status": "failed", "error": "Repository path does not exist after cloning"}}
            )
            # Cleanup temp root
            try:
                if os.path.exists(temp_root):
                    shutil.rmtree(temp_root)
            except Exception:
                pass
            return
        
        repo_files = os.listdir(repo_path)
        logger.info(f"Repository contains {len(repo_files)} files/directories")
        
        # Get commit information
        commit_hash = webhook_commit_hash or "unknown"  # Use webhook commit hash if available
        commit_message = ""
        commit_author = ""
        commit_date = None
        
        try:
            repo = git.Repo(repo_path)
            git_commit_hash = repo.head.commit.hexsha
            commit_message = repo.head.commit.message.strip()
            commit_author = repo.head.commit.author.name
            commit_date = repo.head.commit.committed_datetime
            
            # Use git commit hash if webhook commit hash is not available
            if not webhook_commit_hash:
                commit_hash = git_commit_hash
            
            logger.info(f"Commit hash: {commit_hash[:8]}, Message: {commit_message[:50]}, Author: {commit_author}")
            
        except Exception as e:
            logger.warning(f"Could not get commit information: {e}", exc_info=True)
        
        # Create output directory
        write_artifacts = os.getenv("WRITE_ARTIFACTS", "true").lower() == "true"
        output_dir = os.path.join(temp_root, "output") if write_artifacts else None
        if write_artifacts and output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        logger.info(f"Running security scan - Type: {scan_type}, Output: {output_dir if write_artifacts else 'disabled'}")
        
        # Run the scanner using the new Scan Controller Service
        try:
            logger.info("Calling Scan Controller Service")
            
            # Map scan_type to scanner types (normalize frontend format)
            # Frontend sends "secret-scanner", backend uses "secret_scanner"
            normalized_scan_type = scan_type.replace("-", "_") if scan_type == "secret-scanner" else scan_type

            scan_types = []
            if normalized_scan_type == "all":
                scan_types = list(SUPPORTED_SCANNERS)
            elif normalized_scan_type == "iac":
                scan_types = list(_IAC_SCANNERS)
            elif normalized_scan_type == "workflow":
                scan_types = ["workflow"]
            elif normalized_scan_type == "secret_scanner":
                scan_types = ["secret_scanner"]
            elif normalized_scan_type == "sbom":
                scan_types = ["sbom"]
            elif normalized_scan_type == "spec-scanner":
                scan_types = ["spec-scanner"]
            elif normalized_scan_type in ("terraform", "terraform_aws", "terraform_azure", "terraform_gcp"):
                scan_types = list(_TERRAFORM_SCANNERS)
            elif normalized_scan_type == "skill-scanner":
                scan_types = ["skill-scanner"]
            elif normalized_scan_type in ("cis-agent", "cis_agent"):
                scan_types = ["cis-agent"]
            else:
                scan_types = list(SUPPORTED_SCANNERS)  # Default to all

            # --- Step 0: Narrow to the tenant's licensed scanners (MT-05.2) ---
            # The BFF resolves these from the tenant's plan entitlements. Applied
            # before the tenant's own toggles so a plan limit cannot be widened by
            # a scan_type the caller chose.
            if allowed_scan_types:
                permitted = set(allowed_scan_types)
                before = set(scan_types)
                scan_types = [s for s in scan_types if s in permitted]
                unlicensed = before - set(scan_types)
                if unlicensed:
                    logger.info(
                        f"Skipping unlicensed scan type(s) for org '{org_name}': "
                        + ", ".join(sorted(unlicensed))
                    )
                if not scan_types:
                    logger.warning(
                        f"No licensed scan types remain for org '{org_name}' — aborting scan"
                    )
                    return

            # --- Step 1: Gate on org-level scanConfigurations ---
            # --- Step 1: Honour tenant scan toggles from tenant_settings.scans ---
            try:
                tenant_settings = get_tenant_settings(db)
                if tenant_settings.get("scans"):
                    before = set(scan_types)
                    scan_types = filter_scan_types_by_settings(scan_types, tenant_settings)
                    skipped = before - set(scan_types)
                    if skipped:
                        logger.info(
                            f"Skipping disabled scan type(s) for org '{org_name}': "
                            + ", ".join(sorted(skipped))
                        )
            except Exception as scan_cfg_err:
                logger.warning(
                    f"Could not load scan settings for org '{org_name}': {scan_cfg_err} — proceeding with all requested scans"
                )

            # --- Step 2: Fetch per-scanner policy config BEFORE scanning ---
            policy_config = None
            try:
                policy_config = get_policy_config(db)
                if policy_config.get("scanners"):
                    logger.info(f"Loaded policy config for org '{org_name}' — applying pre-scan gating")
            except Exception as policy_err:
                logger.warning(f"Could not load policy config for org '{org_name}': {policy_err}")

            combined_results = run_combined_scan(
                repo_path=repo_path,
                output_dir=output_dir or "",
                scan_types=scan_types,
                scan_id=scan_id,
                policy_config=policy_config,
            )

            if combined_results:
                logger.info(f"Scan completed - Status: {combined_results.get('overall_status')}, "
                        f"Findings: {combined_results.get('summary', {}).get('total_findings', 0)}, "
                        f"Files: {combined_results.get('summary', {}).get('total_files_scanned', 0)}, "
                        f"Duration: {combined_results.get('overall_duration', 0):.2f}s")
            else:
                logger.warning("Scan Controller returned None or empty result")
                
            # Convert to the format expected by the rest of the code
            findings = combined_results.get('all_findings', []) if combined_results else []
            
        except Exception as scan_error:
            logger.error(f"Error during scanner execution: {scan_error}", exc_info=True)
            findings = []
        
        logger.info("Security scan completed")
        
        # Read the generated JSON report from Scan Controller Service (optional)
        scan_report = {}
        if write_artifacts and output_dir:
            json_report_path = os.path.join(output_dir, "combined_scan_results.json")
            if os.path.exists(json_report_path):
                try:
                    with open(json_report_path, 'r') as f:
                        scan_report = json.load(f)
                    logger.info(f"Scan report loaded from file: {json_report_path}")
                except Exception as file_error:
                    logger.error(f"Error reading scan report: {file_error}", exc_info=True)
                    scan_report = {"error": f"Failed to read scan report: {file_error}"}
        if not scan_report and 'combined_results' in locals() and combined_results:
            scan_report = combined_results
            logger.info("Using results from Scan Controller Service")
        if not scan_report:
            scan_report = {"error": "No scan report generated"}
            logger.warning("No scan report available")
        
        # Create scan metadata (use normalized scan_type)
        normalized_scan_type = scan_type.replace("-", "_") if scan_type == "secret-scanner" else scan_type
        scan_metadata = scan_formatter.create_scan_metadata(
            scan_id=scan_id,
            organization=org_name,
            repository=repo_name,
            branch=branch,
            commit_hash=commit_hash,
            commit_message=commit_message,
            commit_author=commit_author,
            scan_type=normalized_scan_type,
            scan_timestamp=datetime.now().isoformat(),
            commit_date=commit_date,
            repository_url=repo_url,
            event_type=event_type,
            tenant_id=tenant_id,
        )
        
        # Persist per-scanner results into dedicated collections (Approach 1)
        try:
            per_scanner = scan_report.get("per_scanner_results", {}) if isinstance(scan_report, dict) else {}
            scanner_result_ids = {}  # Store ObjectIds for consolidated reference updates
            
            for scanner_key, data in per_scanner.items():
                # SBOM-only scans get an LLM false-positive triage pass before
                # persistence: findings the LLM judges as false positives are
                # stripped here so they never reach the DB or the UI. Only
                # applies when SBOM was requested on its own, not as part of
                # an "all scanners" run.
                if scanner_key == "sbom" and normalized_scan_type == "sbom":
                    try:
                        from autofix_prompts.sbom_fp_validator import validate_sbom_dependencies
                        metadata = data.get("metadata", {}) or {}
                        dependencies = metadata.get("dependencies", [])
                        if dependencies:
                            filtered_deps, fp_stats = validate_sbom_dependencies(dependencies)
                            cve_summary = {
                                "total_packages_scanned": len(dependencies),
                                "raw_cve_matches": fp_stats.get("total_findings", 0),
                                "total_cves": fp_stats.get("total_cves", 0),
                                "possibly_reachable_cves": fp_stats.get("possibly_reachable_cves", 0),
                                "production_cves": fp_stats.get("production_cves", 0),
                                "fixable_cves": fp_stats.get("fixable_cves", 0),
                                "removed_false_positives": fp_stats.get("removed_false_positives", 0),
                                "possibly_reachable_cve_ids": fp_stats.get("possibly_reachable_cve_ids", []),
                                "production_cve_ids": fp_stats.get("production_cve_ids", []),
                                "fixable_cve_ids": fp_stats.get("fixable_cve_ids", []),
                                "validated": fp_stats.get("validated", False),
                                "batches_total": fp_stats.get("batches_total", 0),
                                "batches_failed": fp_stats.get("batches_failed", 0),
                            }
                            metadata["dependencies"] = filtered_deps
                            metadata["cve_summary"] = cve_summary
                            data["metadata"] = metadata
                            # scan_report["scanner_results"][scanner_key]["metadata"] and
                            # per_scanner_results[scanner_key]["metadata"] (= `data`, above)
                            # share the same dict object inside scan_controller.py, but
                            # main.py reloads scan_report from the on-disk JSON artifact
                            # (WRITE_ARTIFACTS=true) when available, which deep-copies
                            # everything and breaks that shared reference. scan_summary
                            # (what the UI actually reads for SBOM findings) is built from
                            # scan_report["scanner_results"], so it must be patched too or
                            # the UI keeps showing the pre-validation, unfiltered list.
                            scanner_results_summary = (
                                scan_report.get("scanner_results", {}) if isinstance(scan_report, dict) else {}
                            )
                            summary_entry = scanner_results_summary.get(scanner_key)
                            if isinstance(summary_entry, dict):
                                summary_entry_metadata = summary_entry.get("metadata")
                                if isinstance(summary_entry_metadata, dict):
                                    summary_entry_metadata["dependencies"] = filtered_deps
                                    summary_entry_metadata["cve_summary"] = cve_summary
                                else:
                                    summary_entry["metadata"] = {
                                        "dependencies": filtered_deps,
                                        "cve_summary": cve_summary,
                                    }
                            logger.info(
                                f"SBOM enrichment: packages_scanned={cve_summary['total_packages_scanned']} "
                                f"raw_cve_matches={cve_summary['raw_cve_matches']} "
                                f"total_cves={cve_summary['total_cves']} "
                                f"possibly_reachable={cve_summary['possibly_reachable_cves']} "
                                f"production={cve_summary['production_cves']} "
                                f"fixable={cve_summary['fixable_cves']} "
                                f"removed={cve_summary['removed_false_positives']} "
                                f"validated={cve_summary['validated']} "
                                f"batches={cve_summary['batches_total'] - cve_summary['batches_failed']}"
                                f"/{cve_summary['batches_total']} ok"
                            )
                    except Exception as fp_error:
                        logger.warning(f"SBOM enrichment skipped due to error: {fp_error}")

                collection_name = f"scan_results_{scanner_key}"
                col = getattr(db, collection_name)
                per_scanner_doc = {
                    "scan_id": scan_id,
                    "tenantId": tenant_id,
                    "scanner": scanner_key,
                    "repo_org": org_name,
                    "repo_name": repo_name,
                    "branch": branch,
                    "status": "completed",
                    "execution_id": scan_id,
                    "created_at": datetime.now(),
                    "updated_at": datetime.now(),
                    "metadata": data.get("metadata", {}),
                    "scanned_files": data.get("scanned_files", []),
                    "findings": data.get("findings", [])
                }
                result = col.update_one(
                    {"scan_id": scan_id, "scanner": scanner_key},
                    {"$set": per_scanner_doc},
                    upsert=True
                )
                
                # Get the document _id for consolidated reference
                if result.upserted_id:
                    scanner_result_ids[scanner_key] = result.upserted_id
                else:
                    # Document already existed, find it to get _id
                    existing_doc = col.find_one({"scan_id": scan_id, "scanner": scanner_key})
                    if existing_doc and "_id" in existing_doc:
                        scanner_result_ids[scanner_key] = existing_doc["_id"]
            
            # Write minimal summary to scan_summary (metadata + scanner_results_meta, no full aggregation)
            scanner_results_meta = scan_report.get("scanner_results", {})
            overall_duration = scan_report.get("overall_duration", 0.0)
            scanners_executed = list(per_scanner.keys())
            
            summary_doc = {
                "scan_id": scan_id,
                "tenantId": tenant_id,
                "created_at": datetime.now(),
                "scan_status": "completed",
                "installation_id": installation_id,
                "scan_metadata": scan_metadata,
                "scanners_executed": scanners_executed,
                "overall_duration": overall_duration,
                "scanner_results": scanner_results_meta,
            }
            
            # Calculate and embed comprehensive scores in scan_summary.scores
            try:
                scanner_policies = {}
                from scanner_core.helpers.scoring_engine import load_workflow_policies
                workflow_policies = load_workflow_policies()
                if workflow_policies:
                    scanner_policies["workflow"] = workflow_policies
                
                scoring_engine = UnifiedScoringEngine()
                comprehensive_scores = scoring_engine.calculate_comprehensive_scores(
                    per_scanner_results=per_scanner,
                    scanner_policies=scanner_policies if scanner_policies else None
                )
                summary_doc["scores"] = {
                    "overall_score": comprehensive_scores["overall_score"],
                    "score_by_scanner": comprehensive_scores["score_by_scanner"],
                    "file_wise_scores": comprehensive_scores["file_wise_scores"],
                    "scoring_breakdown": comprehensive_scores["scoring_breakdown"],
                    "scanners_executed": comprehensive_scores["scanners_executed"],
                    "calculated_at": datetime.now(),
                }
            except Exception as score_error:
                logger.error(f"Failed to calculate/store comprehensive scores: {score_error}", exc_info=True)

            db.scan_summary.update_one(
                {"scan_id": scan_id},
                {"$set": summary_doc},
                upsert=True
            )
            logger.info("Per-scanner results and summary saved to separate collections")
        except Exception as persist_error:
            logger.error(f"Failed to persist per-scanner/summary collections: {persist_error}", exc_info=True)
        
        # No legacy combined document write
        logger.info("Scan completed and summary saved to database")
        
        # Clean up repository after successful scan
        try:
            if temp_root and os.path.exists(temp_root):
                shutil.rmtree(temp_root)
                logger.info("Temp workspace cleaned up")
        except Exception as cleanup_error:
            logger.warning(f"Failed to clean up temp workspace: {cleanup_error}", exc_info=True)
            
    except Exception as e:
        logger.error(f"Error in background scanner: {e}", exc_info=True)
        
        # Update scan status to failed
        if scan_id and tenant_id:
            scan_metadata = scan_formatter.create_scan_metadata(
                scan_id=scan_id,
                organization=org_name,
                repository=repo_name,
                branch=branch,
                commit_hash=webhook_commit_hash or "unknown",
                commit_message="",
                commit_author="",
                scan_type=scan_type,
                scan_timestamp=datetime.now().isoformat(),
                commit_date=None,
                repository_url=repo_url,
                event_type=event_type,
                tenant_id=tenant_id,
            )
            
            # Update scan_summary
            db.scan_summary.update_one(
                {"scan_id": scan_id},
                {"$set": {
                    "scan_status": "failed",
                    "installation_id": installation_id,
                    "tenantId": tenant_id,
                    "scan_metadata": scan_metadata,
                    "error": str(e),
                }},
                upsert=True
            )
            
            # Update any scanner results that were created before failure
            # Map scan_type to scanner list
            if scan_type == "all":
                scanner_list = list(SUPPORTED_SCANNERS)
            else:
                scanner_list = [scan_type] if scan_type in SUPPORTED_SCANNERS else []
            
            for scanner_key in scanner_list:
                collection_name = f"scan_results_{scanner_key}"
                col = getattr(db, collection_name)
                col.update_one(
                    {"scan_id": scan_id, "scanner": scanner_key},
                    {"$set": {"status": "failed", "updated_at": datetime.now()}},
                    upsert=False  # Only update if exists
                )
            
            logger.error("Scan marked as failed in summary collection")
        
        # Clean up repository on error
        if 'temp_root' in locals() and temp_root and os.path.exists(temp_root):
            try:
                shutil.rmtree(temp_root)
                logger.info("Temp workspace cleaned up after error")
            except Exception as cleanup_error:
                logger.warning(f"Failed to clean up temp workspace: {cleanup_error}", exc_info=True)


def get_latest_consolidated(
    db: Database,
    repo_org: str,
    repo_name: str,
    branch: str,
    scanners: Optional[Tuple[str, ...]] = None,
) -> dict:
    """Get latest consolidated scan results for a repo/branch from tenant DB collections.

    Uses the most recent ``scan_summary`` document and loads per-scanner results
    for that ``scan_id``. Applies current ``tenant_settings.policies`` on read.

    Args:
        scanners: restrict the consolidated result to this subset of scanner
            keys (e.g. ``_IAC_SCANNERS`` for the aggregate "iac" scan_type).
            Defaults to all ``SUPPORTED_SCANNERS``.
    """
    scanner_keys = scanners if scanners is not None else SUPPORTED_SCANNERS
    try:
        summary_query = {
            "scan_metadata.organization": repo_org,
            "scan_metadata.repository": repo_name,
            "scan_metadata.branch": branch,
            "scan_status": "completed",
        }
        if scanners is not None:
            # Subset request (e.g. "iac"): only consider scans in which one of
            # these scanners actually produced results; otherwise a later
            # sbom/secret-only scan would masquerade as an empty IaC scan.
            latest_scan_ids = []
            for scanner in scanner_keys:
                d = db[f"scan_results_{scanner}"].find_one(
                    {"repo_org": repo_org, "repo_name": repo_name, "branch": branch,
                     "status": "completed", "scanner": scanner},
                    sort=[("created_at", -1)],
                )
                if d and d.get("scan_id"):
                    latest_scan_ids.append((d.get("created_at"), d["scan_id"]))
            if not latest_scan_ids:
                return None
            summary_query["scan_id"] = max(latest_scan_ids, key=lambda x: x[0])[1]

        scan_summary = db.scan_summary.find_one(summary_query, sort=[("created_at", -1)])
        if not scan_summary:
            return None

        scan_id = scan_summary.get("scan_id")
        per_scanner_docs = {}
        for scanner in scanner_keys:
            collection_name = f"scan_results_{scanner}"
            doc = db[collection_name].find_one(
                {"scan_id": scan_id, "scanner": scanner},
                sort=[("created_at", -1)],
            )
            if doc:
                if "_id" in doc:
                    doc["_id"] = str(doc["_id"])
                per_scanner_docs[scanner] = doc
            else:
                per_scanner_docs[scanner] = {"findings": [], "scanned_files": [], "metadata": {}}

        scanner_results_meta = scan_summary.get("scanner_results", {})
        overall_duration = scan_summary.get("overall_duration", 0.0)

        if "summary" not in scan_summary:
            padded_summary = _build_padded_summary(per_scanner_docs, scanner_results_meta, overall_duration)
            scan_summary["summary"] = padded_summary

        try:
            policy_config = get_policy_config(db)
            if policy_config.get("scanners"):
                for scanner_key in list(per_scanner_docs.keys()):
                    original_findings = (per_scanner_docs[scanner_key] or {}).get("findings", [])
                    filtered = filter_findings_by_policy(
                        scanner_type=scanner_key,
                        findings=original_findings,
                        policy_config=policy_config,
                    )
                    per_scanner_docs[scanner_key] = {
                        **(per_scanner_docs[scanner_key] or {}),
                        "findings": filtered,
                    }
        except Exception as _pf_err:
            logger.warning(f"Could not apply read-time policy filter for {repo_org}: {_pf_err}")

        consolidated = _consolidate_result(scan_summary, {
            k: {
                "findings": (v or {}).get("findings", []),
                "scanned_files": (v or {}).get("scanned_files", []),
                "metadata": (v or {}).get("metadata", {}),
            }
            for k, v in per_scanner_docs.items()
        })

        if "_id" in consolidated and consolidated["_id"] is not None:
            consolidated["_id"] = str(consolidated["_id"])

        return consolidated
    except Exception as e:
        logger.error(f"Error getting latest consolidated: {e}", exc_info=True)
        return None

def _normalize_severity(value: str) -> str:
    if not isinstance(value, str):
        return "unknown"
    v = value.lower()
    if v in ("critical", "high", "medium", "low"):
        return v
    return v or "unknown"


def _build_padded_summary(per_scanner: dict, scanner_results_meta: dict, overall_duration: float) -> dict:
    scanners = sorted(list(per_scanner.keys()))
    # Counts
    total_issues = 0
    total_issues_by_subscan = {k: 0 for k in SUPPORTED_SCANNERS}
    total_issue_counts_by_severity = {k: 0 for k in ("critical", "high", "medium", "low")}
    issue_counts_by_subscan_and_severity = {
        scanner: {k: 0 for k in ("critical", "high", "medium", "low")} for scanner in SUPPORTED_SCANNERS
    }
    # File scanned
    file_scanned = 0
    for scanner, data in per_scanner.items():
        findings = data.get("findings", []) or []
        scanned_files = data.get("scanned_files", []) or []
        if scanner in SUPPORTED_SCANNERS:
            total_issues_by_subscan[scanner] = len(findings)
        total_issues += len(findings)
        file_scanned += len(scanned_files)
        for f in findings:
            sev = _normalize_severity((f or {}).get("severity", "unknown"))
            if sev in total_issue_counts_by_severity:
                total_issue_counts_by_severity[sev] += 1
                if scanner in issue_counts_by_subscan_and_severity:
                    issue_counts_by_subscan_and_severity[scanner][sev] += 1
    # Calculate real scores using unified scoring engine
    scoring_engine = UnifiedScoringEngine()
    comprehensive_scores = scoring_engine.calculate_comprehensive_scores(
        per_scanner_results=per_scanner,
        scanner_policies=None  # Policies not available at this level
    )
    
    score_by_subscan = comprehensive_scores["score_by_scanner"]
    overall_score = comprehensive_scores["overall_score"]
    return {
        "file_scanned": file_scanned,
        "issues_summary": {
            "total_issues": total_issues,
            "total_issues_by_subscan": total_issues_by_subscan,
            "total_issue_counts_by_severity": total_issue_counts_by_severity,
            "issue_counts_by_subscan_and_severity": issue_counts_by_subscan_and_severity,
        },
        "score_summary": {
            "overall_score": overall_score,
            "score_by_subscan": score_by_subscan,
        },
        "scanners_executed": scanners,
    }


def _build_scans_findings(per_scanner: dict) -> dict:
    result = {}
    for scanner in SUPPORTED_SCANNERS:
        data = per_scanner.get(scanner, {})
        findings = data.get("findings", []) or []
        
        # group by file
        grouped = {}
        for f in findings:
            file_name = (f or {}).get("file", "")
            grouped.setdefault(file_name, []).append(f)
        items = []
        for file_name, lst in grouped.items():
            violated = []
            for f in lst:
                finding_dict = {
                    "policy_code": f.get("code", None),
                    "policy_name": f.get("policy", ""),
                    "description": f.get("description", ""),
                    "severity": _normalize_severity(f.get("severity", "")),
                    "Line_No": f.get("line") or "-",
                    "Matches": f.get("match", "-"),
                    "remediation": f.get("url", None),
                    "code_block": f.get("code_block"),
                }

                violated.append(finding_dict)
            finding_group = {
                "file_name": file_name,
                "violated_policies": violated,
            }
            # Spec-scanner: file_name is endpoint; emit real path as `file`.
            source_file = next(
                (f.get("source_file") for f in lst if isinstance(f, dict) and f.get("source_file")),
                None,
            )
            if source_file:
                finding_group["file"] = source_file
            items.append(finding_group)
        key = f"{scanner.title()}-findings"
        result[key] = items
    return result


def _consolidate_result(scan_summary_doc: dict, per_scanner_docs: dict) -> dict:
    scan_id = scan_summary_doc.get("scan_id")
    scanners_executed = list(per_scanner_docs.keys())
    overall_duration = scan_summary_doc.get("overall_duration", 0.0)
    scanner_results_meta = scan_summary_doc.get("scanner_results", {})
    summary = _build_padded_summary(per_scanner_docs, scanner_results_meta, overall_duration)
    scans_findings = _build_scans_findings(per_scanner_docs)
    scans_status = {s: (scanner_results_meta.get(s, {}).get("status", "unknown")) for s in SUPPORTED_SCANNERS}

    # Extract generator_validator from spec-scanner metadata so it is always
    # present in the consolidated response (whether run standalone or as part of "all").
    spec_meta = (per_scanner_docs.get("spec-scanner") or {}).get("metadata") or {}
    generator_validator = spec_meta.get("spec_scan_response") if isinstance(spec_meta, dict) else None

    scan_results_block: dict = {
        "scan_results": {
            "overall_duration": overall_duration,
            "summary": summary,
            "scanner_results": scanner_results_meta,
        },
        "scans_status": scans_status,
        "scans_findings": scans_findings,
    }
    if generator_validator is not None:
        scan_results_block["generator_validator"] = generator_validator

    consolidated = {
        "_id": scan_summary_doc.get("_id"),
        "scan_id": scan_id,
        "scan_status": scan_summary_doc.get("scan_status"),
        "created_at": scan_summary_doc.get("created_at"),
        "installation_id": scan_summary_doc.get("installation_id"),
        "scan_metadata": scan_summary_doc.get("scan_metadata", {}),
        "scan_results": scan_results_block,
        "error": scan_summary_doc.get("error", ""),
        "completed_at": scan_summary_doc.get("scan_metadata", {}).get("scan_timestamp"),
    }
    return consolidated


# API Endpoints
@app.get("/health", tags=["General"])
async def health():
    return {"status": "ok"}


@app.get("/", tags=["General"])
async def root():
    return {"message": "Policy Scanner & AI Code Check API is running"}

# --- Scanner Webhook & Manual Trigger Endpoints ---

@app.post("/webhook/github", tags=["Scanner"])
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    logger.info(f"Webhook received: {request.method} {request.url}")
    
    payload = await request.body()
    if not verify_github_webhook(request, payload):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    
    try:
        webhook_data = json.loads(payload)
        event_type = request.headers.get("X-GitHub-Event")
        
        if event_type in ["push", "pull_request"]:
            repo = webhook_data.get("repository", {})
            org_name = repo.get("owner", {}).get("login", "unknown")
            repo_name = repo.get("name", "unknown")
            repo_url = repo.get("clone_url", "")
            installation_id = webhook_data.get("installation", {}).get("id")
            
            if event_type == "push":
                branch = webhook_data.get("ref", "main").replace("refs/heads/", "")
            else:
                branch = webhook_data.get("pull_request", {}).get("head", {}).get("ref", "main")
            
            commit_hash = get_commit_hash_from_webhook(event_type, webhook_data)
            if not installation_id:
                raise HTTPException(status_code=400, detail="Webhook missing installation id")

            try:
                tenant_db, _ = resolve_tenant_db_required(installation_id)
            except ValueError as e:
                raise HTTPException(status_code=404, detail=str(e))
            
            if commit_hash and scan_exists_for_commit(tenant_db, org_name, repo_name, commit_hash):
                return {"message": "Scan skipped - duplicate", "reason": "duplicate_prevention"}
            
            background_tasks.add_task(
                run_scanner_background,
                org_name, repo_name, repo_url, branch, "all",
                tenant_db,
                str(installation_id),
                event_type, commit_hash
            )
            return {"message": "Scan initiated", "org": org_name, "repo": repo_name}

    except HTTPException as e:
        # Deliberate answers (400 missing installation, 404 unlinked installation)
        # must keep their status: the catch-all below turned them into a 500 with
        # a stack trace, so an expected "not linked" looked like a crash.
        logger.warning(f"Webhook rejected ({e.status_code}): {e.detail}")
        raise
    except Exception as e:
        logger.error(f"Error processing webhook: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error processing webhook")
    
    return {"message": "Event received"}

@app.post("/scan")
async def trigger_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Manually trigger a scan"""
    import asyncio
    try:
        try:
            tenant_db, _ = resolve_tenant_db_required(scan_request.installation_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        # Construct repository URL
        repo_url = f"https://github.com/{scan_request.org_name}/{scan_request.repo_name}.git"
        logger.info(f"Manual scan with GitHub App authentication (Installation ID: {scan_request.installation_id})")

        # Normalize scan type
        normalized_type = scan_request.scan_type

        if normalized_type == "spec-scanner":
            # Run synchronously so we can return the full spec generator result inline
            await asyncio.to_thread(
                run_scanner_background,
                scan_request.org_name,
                scan_request.repo_name,
                repo_url,
                scan_request.branch,
                scan_request.scan_type,
                tenant_db,
                scan_request.installation_id,
                "manual",
                None,
                scan_request.allowed_scan_types,
            )
            summary = tenant_db.scan_summary.find_one(
                {
                    "scan_metadata.organization": scan_request.org_name,
                    "scan_metadata.repository": scan_request.repo_name,
                },
                sort=[("created_at", -1)],
            )
            def _is_no_api_discovered(detail: str) -> bool:
                return "No API paths could be extracted" in str(detail or "")

            if summary and summary.get("scan_status") == "failed":
                fail_detail = summary.get("error") or "Scan failed"
                if not _is_no_api_discovered(fail_detail):
                    raise HTTPException(
                        status_code=500,
                        detail=fail_detail,
                    )

            spec_scanner_result = (
                (summary or {}).get("scanner_results") or {}
            ).get("spec-scanner")
            if spec_scanner_result and spec_scanner_result.get("status") == "failed":
                fail_detail = spec_scanner_result.get("error") or "Spec scan failed"
                if _is_no_api_discovered(fail_detail):
                    return {
                        "message": "No API Discovered",
                        "org_name": scan_request.org_name,
                        "repo_name": scan_request.repo_name,
                        "branch": scan_request.branch,
                        "scan_type": scan_request.scan_type,
                        "installation_id": scan_request.installation_id,
                        "generator_validator": {
                            "detail": "No API paths could be extracted from the repository.",
                            "scan": {"apis": [], "findings": [], "checks": []},
                        },
                        "no_api_discovered": True,
                    }
                raise HTTPException(
                    status_code=500,
                    detail=fail_detail,
                )

            spec_doc = tenant_db["scan_results_spec-scanner"].find_one(
                {"repo_org": scan_request.org_name, "repo_name": scan_request.repo_name},
                sort=[("created_at", -1)],
            )
            generator_validator = None
            if spec_doc and isinstance(spec_doc.get("metadata"), dict):
                generator_validator = spec_doc["metadata"].get("spec_scan_response")
                if spec_doc["metadata"].get("no_api_discovered") and not generator_validator:
                    generator_validator = {
                        "detail": "No API paths could be extracted from the repository.",
                        "scan": {"apis": [], "findings": [], "checks": []},
                    }

            if not generator_validator:
                # Empty-success path: scanner completed with no APIs discovered.
                if summary and (
                    ((summary.get("scanner_results") or {}).get("spec-scanner") or {}).get("metadata") or {}
                ).get("no_api_discovered"):
                    return {
                        "message": "No API Discovered",
                        "org_name": scan_request.org_name,
                        "repo_name": scan_request.repo_name,
                        "branch": scan_request.branch,
                        "scan_type": scan_request.scan_type,
                        "installation_id": scan_request.installation_id,
                        "generator_validator": {
                            "detail": "No API paths could be extracted from the repository.",
                            "scan": {"apis": [], "findings": [], "checks": []},
                        },
                        "no_api_discovered": True,
                    }
                raise HTTPException(
                    status_code=500,
                    detail="Spec scan did not produce a result (spec-generator may be unreachable)",
                )

            return {
                "message": "Scan completed",
                "org_name": scan_request.org_name,
                "repo_name": scan_request.repo_name,
                "branch": scan_request.branch,
                "scan_type": scan_request.scan_type,
                "installation_id": scan_request.installation_id,
                "generator_validator": generator_validator,
            }

        # For all other scan types, run in the background as before
        background_tasks.add_task(
            run_scanner_background,
            scan_request.org_name,
            scan_request.repo_name,
            repo_url,
            scan_request.branch,
            scan_request.scan_type,
            tenant_db,
            scan_request.installation_id,  # Use required installation ID from request
            "manual",  # Event type for manual scans
            None,  # No webhook commit hash for manual scans
            scan_request.allowed_scan_types,  # Plan-entitled scanners (MT-05.2)
        )
        
        return {
            "message": "Scan initiated",
            "org_name": scan_request.org_name,
            "repo_name": scan_request.repo_name,
            "branch": scan_request.branch,
            "scan_type": scan_request.scan_type,
            "installation_id": scan_request.installation_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        detail = getattr(e, "detail", None) or str(e) or repr(e)
        raise HTTPException(status_code=500, detail=f"Error initiating scan: {detail}")


@app.post("/scans/ai/autofix")
async def request_autofix(autofix_request: AutofixRequest, request: Request):
    """Generate a remediation proposal for one finding via the LiteLLM gateway.

    Tenant-scoped: the installation must resolve to a tenant before any model call
    is made. The S2S middleware only proves *a* Zyloch service is calling; it does
    not say which tenant the request is for, so without this an installation id
    that belongs to nobody (or to another tenant) would still spend model budget.
    """
    # Outside the try below on purpose: that block maps ValueError to 422 and any
    # other error to 502, either of which would mask this 404.
    try:
        _, tenant_id = resolve_tenant_db_required(autofix_request.installation_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    header_tenant = request.headers.get("X-Tenant-Id") or request.headers.get("X-Zyloch-Tenant-Id")
    if header_tenant and str(header_tenant) != str(tenant_id):
        raise HTTPException(status_code=403, detail="X-Tenant-Id does not match installation tenant")

    logger.info(
        "Autofix requested tenant=%s installation_id=%s policy_code=%s",
        tenant_id,
        autofix_request.installation_id,
        autofix_request.policy_code,
    )

    try:
        result = await asyncio.to_thread(
            generate_autofix,
            autofix_request.model_dump(exclude={"force_refresh", "installation_id"}),
            autofix_request.force_refresh,
            tenant_id,
        )
        return {
            "status": "completed",
            "policy_code": autofix_request.policy_code,
            "file": autofix_request.file,
            "line": autofix_request.line,
            **result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except requests.Timeout:
        logger.error("Autofix LiteLLM request timed out", exc_info=True)
        raise HTTPException(
            status_code=504,
            detail="The autofix model gateway timed out. Check LiteLLM availability and model latency.",
        )
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        logger.error("Autofix LiteLLM returned HTTP %s", status_code, exc_info=True)
        if status_code in {401, 403}:
            detail = "The LiteLLM API key was rejected. Verify LITELLM_API_KEY and the production gateway configuration."
        elif status_code == 404:
            detail = "The LiteLLM endpoint or autofix model was not found. Verify LITELLM_BASE_URL and AUTOFIX_MODEL."
        elif status_code == 429:
            detail = "The LiteLLM provider rate limit or quota was reached. Check provider quota and gateway limits."
        elif status_code and status_code >= 500:
            detail = "The LiteLLM provider returned an upstream server error. Check the model gateway logs."
        else:
            detail = "The LiteLLM gateway rejected the autofix request. Check the backend and gateway logs."
        raise HTTPException(status_code=502, detail=detail)
    except RuntimeError as exc:
        logger.error("Autofix coai/nfiguration or response error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        logger.error("Autofix request failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=502, detail="Autofix service is unavailable")


@app.post("/scans/ai/autofix/pr")
async def create_autofix_pull_request(pr_request: AutofixPrRequest):
    """Apply a reviewed autofix proposal and open a GitHub pull request.

    Tenant-scoped: `installation_id` arrives in the request body and previously went
    straight into a GitHub installation-token request. Any caller holding the S2S key
    could therefore mint a write-scoped token for an arbitrary installation and open a
    PR in another tenant's repository. Resolving the tenant first rejects an
    installation that is not mapped to one.
    """
    # Outside the try below on purpose: that block converts any unexpected error into
    # a 500 "GitHub auth" message, which would mask this 404.
    try:
        _, tenant_id = resolve_tenant_db_required(pr_request.installation_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    try:
        logger.info(
            "Requesting PR installation token tenant=%s installation_id=%s repository=%s branch=%s",
            tenant_id,
            pr_request.installation_id,
            pr_request.repository,
            pr_request.branch,
        )
        token = await asyncio.to_thread(
            get_installation_token,
            pr_request.installation_id,
            {"contents": "write", "pull_requests": "write"},
            True,
        )
    except GitHubInstallationPermissionError as exc:
        logger.error(f"GitHub Permission Error for installation {pr_request.installation_id}: {exc}")
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        # Catch unexpected API errors from the token request so you aren't flying blind
        logger.error(f"Failed to generate installation token: {exc}")
        raise HTTPException(status_code=500, detail="Internal error communicating with GitHub auth API.")

    if not token:
        logger.error(f"Token generation returned None for installation {pr_request.installation_id}")
        raise HTTPException(
            status_code=502,
            detail="GitHub could not provide an installation token. Verify the App has accepted the latest permissions and has access to the target repository.",
        )

    try:
        result = await asyncio.to_thread(
            create_autofix_pr,
            pr_request.model_dump(exclude={"installation_id"}),
            token,
        )
        return result
    except AutofixPrError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except requests.RequestException as exc:
        logger.error("Autofix PR request failed: %s", exc, exc_info=True)
        if exc.response is not None and exc.response.status_code == 403:
            raise HTTPException(
                status_code=403,
                detail=(
                    "The GitHub App installation is not authorized to create PRs in this repository. "
                    "Grant the App Contents: Read and write and Pull requests: Read and write "
                    "permissions, then approve the updated permissions for this repository."
                ),
            )
        raise HTTPException(status_code=502, detail="GitHub PR creation failed")

@app.get("/scans")
async def get_scans(
    installation_id: str,
    org_name: Optional[str] = None,
    repo_name: Optional[str] = None,
    scan_type: Optional[str] = None,
    limit: int = 50,
):
    """Get scan results with optional filtering - returns MongoDB structure directly"""
    try:
        try:
            tenant_db, _ = resolve_tenant_db_required(installation_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        # Build query - use the correct field paths (only completed scans)
        query = {
            "scan_status": "completed"  # Only return completed scans
        }
        if org_name:
            query["scan_metadata.organization"] = org_name
        if repo_name:
            query["scan_metadata.repository"] = repo_name
        if scan_type and scan_type != "all":
            # scan_metadata.scan_type is stored as the requested scan category
            # (e.g. "iac", "secret_scanner", "sbom"), not as individual scanner
            # names, so this is a direct equality match.
            normalized_scan_type = scan_type.replace("-", "_") if scan_type == "secret-scanner" else scan_type
            query["scan_metadata.scan_type"] = normalized_scan_type

        logger.info(f"Searching for scans with query: {query}")
        
        # Get scans from database
        cursor = tenant_db.scan_summary.find(query).sort("created_at", -1).limit(limit)
        scans = list(cursor)
        
        logger.info(f"Found {len(scans)} scans")
        
        # Convert ObjectId to string for JSON serialization
        for scan in scans:
            if "_id" in scan:
                scan["_id"] = str(scan["_id"])
        
        return {
            "message": f"Retrieved {len(scans)} scans",
            "total_count": len(scans),
            "scans": scans
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving scans: {str(e)}")

@app.get("/scans/latest")
async def get_latest_scan(
    installation_id: str,
    org_name: str,
    repo_name: str,
    branch: str,
    scan_type: Optional[str] = None,
):
    """Get the latest scan for a specific organization, repository, and branch.
    
    If scan_type is provided, returns only that scanner's latest result.
    If scan_type is not provided, returns consolidated overview from all scanners.
    """
    try:
        try:
            tenant_db, _ = resolve_tenant_db_required(installation_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        if scan_type == "iac":
            logger.info(f"Searching for latest iac scan: {org_name}/{repo_name}/{branch}")

            consolidated_result = get_latest_consolidated(
                tenant_db, org_name, repo_name, branch, scanners=_IAC_SCANNERS
            )

            if not consolidated_result:
                raise HTTPException(
                    status_code=404,
                    detail=f"No iac scans found for organization '{org_name}', repository '{repo_name}', branch '{branch}'"
                )

            logger.info("Found consolidated latest iac scan")
            return consolidated_result

        # If scan_type is provided, query specific scanner collection
        if scan_type and scan_type != "all":
            # Normalize scan_type aliases (frontend naming -> backend keys)
            normalized_scan_type = scan_type.replace("-", "_") if scan_type == "secret-scanner" else scan_type

            if normalized_scan_type not in SUPPORTED_SCANNERS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid scan_type: {scan_type}. Supported types: {SUPPORTED_SCANNERS}"
                )
            
            collection_name = f"scan_results_{normalized_scan_type}"
            query = {
                "repo_org": org_name,
                "repo_name": repo_name,
                "branch": branch,
                "status": "completed",
                "scanner": normalized_scan_type
            }
            
            logger.info(f"Searching for latest {normalized_scan_type} scan with query: {query}")
            
            # Get the most recent scan result for this scanner
            doc = tenant_db[collection_name].find_one(
                query,
                sort=[("created_at", -1)]
            )
            
            if not doc:
                raise HTTPException(
                    status_code=404,
                    detail=f"No {scan_type} scans found for organization '{org_name}', repository '{repo_name}', branch '{branch}'"
                )
            
            # Convert _id to string
            if "_id" in doc:
                doc["_id"] = str(doc["_id"])
            
            # Get scan_summary for metadata
            scan_id = doc.get("scan_id")
            scan_summary = tenant_db.scan_summary.find_one({"scan_id": scan_id}) if scan_id else None
            
            # Build response in expected format
            if scan_summary:
                # Build per_scanner_docs structure for _consolidate_result
                per_scanner_docs = {normalized_scan_type: doc}
                # Fill other scanners with empty data
                for scanner in SUPPORTED_SCANNERS:
                    if scanner != normalized_scan_type:
                        per_scanner_docs[scanner] = {"findings": [], "scanned_files": [], "metadata": {}}

                # Apply current policy config so settings changes are reflected immediately
                try:
                    policy_config = get_policy_config(tenant_db)
                    if policy_config.get("scanners"):
                        original = per_scanner_docs[normalized_scan_type].get("findings", [])
                        per_scanner_docs[normalized_scan_type]["findings"] = filter_findings_by_policy(
                            scanner_type=normalized_scan_type,
                            findings=original,
                            policy_config=policy_config,
                        )
                except Exception as _pf_err:
                    logger.warning(f"Could not apply read-time policy filter for {org_name}: {_pf_err}")
                
                # Rebuild summary if not present in scan_summary
                scanner_results_meta = scan_summary.get("scanner_results", {})
                if not scanner_results_meta:
                    scanner_results_meta = {
                        normalized_scan_type: {
                            "status": doc.get("status", "completed"),
                            "duration": doc.get("metadata", {}).get("duration", 0.0)
                        }
                    }
                    scan_summary["scanner_results"] = scanner_results_meta
                
                overall_duration = scan_summary.get("overall_duration", 0.0)
                if "summary" not in scan_summary:
                    padded_summary = _build_padded_summary(per_scanner_docs, scanner_results_meta, overall_duration)
                    scan_summary["summary"] = padded_summary
                
                consolidated = _consolidate_result(scan_summary, {
                    k: {
                        "findings": (v or {}).get("findings", []),
                        "scanned_files": (v or {}).get("scanned_files", []),
                        "metadata": (v or {}).get("metadata", {}),
                    }
                    for k, v in per_scanner_docs.items()
                })
            else:
                # Minimal response if no scan_summary found
                consolidated = {
                    "scan_id": scan_id or "unknown",
                    "scan_status": "completed",
                    "scan_metadata": {
                        "organization": org_name,
                        "repository": repo_name,
                        "branch": branch,
                        "scan_type": normalized_scan_type
                    },
                    "scan_results": {
                        "scans_findings": {
                            f"{normalized_scan_type.title()}-findings": doc.get("findings", [])
                        }
                    }
                }
            
            if "_id" in consolidated and consolidated["_id"] is not None:
                consolidated["_id"] = str(consolidated["_id"])
            
            logger.info(f"Found latest {normalized_scan_type} scan: {scan_id}")
            return consolidated
        
        # No scan_type provided - return consolidated overview
        logger.info(f"Searching for consolidated latest scan: {org_name}/{repo_name}/{branch}")
        
        consolidated_result = get_latest_consolidated(tenant_db, org_name, repo_name, branch)
        
        if not consolidated_result:
            raise HTTPException(
                status_code=404,
                detail=f"No scans found for organization '{org_name}', repository '{repo_name}', branch '{branch}'"
            )
        
        logger.info(f"Found consolidated latest scan")
        return consolidated_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving latest scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving latest scan: {str(e)}")

@app.get("/scans/{scan_id}")
async def get_scan_by_id(scan_id: str, installation_id: str):
    """Get specific scan result by ID - returns MongoDB structure directly"""
    try:
        try:
            tenant_db, _ = resolve_tenant_db_required(installation_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        logger.info(f"Looking for scan with ID: {scan_id}")
        
        scan = tenant_db.scan_summary.find_one({"scan_id": scan_id})
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan not found with ID: {scan_id}")
        
        # Convert ObjectId to string for JSON serialization
        if "_id" in scan:
            scan["_id"] = str(scan["_id"])
        
        logger.info(f"Found scan: {scan_id}")
        return scan
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving scan: {str(e)}")

@app.get("/organizations")
async def get_organizations(installation_id: str):
    """Get list of organizations that have been scanned within this tenant"""
    try:
        try:
            tenant_db, _ = resolve_tenant_db_required(installation_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        orgs = tenant_db.scan_summary.distinct("scan_metadata.organization")
        return {"organizations": orgs}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving organizations: {str(e)}")

@app.get("/organizations/{org_name}/repositories")
async def get_org_repositories(org_name: str, installation_id: str):
    """Get list of repositories for an organization within this tenant"""
    try:
        try:
            tenant_db, _ = resolve_tenant_db_required(installation_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        repos = tenant_db.scan_summary.distinct(
            "scan_metadata.repository", {"scan_metadata.organization": org_name}
        )
        return {"organization": org_name, "repositories": repos}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving repositories: {str(e)}")

@app.get("/scans/{scan_id}/scores")
async def get_scan_scores(scan_id: str, installation_id: str):
    """
    Get comprehensive scoring information for a specific scan.
    Returns scores embedded in ``scan_summary.scores``.
    """
    try:
        try:
            tenant_db, _ = resolve_tenant_db_required(installation_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        logger.info(f"Fetching scores for scan ID: {scan_id}")
        
        scan_doc = tenant_db.scan_summary.find_one({"scan_id": scan_id}, {"scores": 1, "scan_id": 1})
        
        if not scan_doc or not scan_doc.get("scores"):
            raise HTTPException(
                status_code=404,
                detail=f"Score information not found for scan ID: {scan_id}"
            )
        
        score_doc = {"scan_id": scan_id, **scan_doc["scores"]}
        logger.info(f"Found score information for scan {scan_id}")
        return score_doc
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving scan scores: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving scan scores: {str(e)}")

class PolicyDetectorConfig(BaseModel):
    """Enables or disables individual detectors for a scanner.
    Keys are detector/policy IDs; False means disabled."""
    detectors: Optional[Dict[str, Any]] = {}
    policies: Optional[Dict[str, Any]] = {}


class PolicyConfigurationsRequest(BaseModel):
    """Request body for updating org-level policy configurations."""
    scanners: Dict[str, Dict[str, Any]]


# --- Policy Configuration Endpoints ---

@app.get("/scans/organizations/{org_name}/policy-configurations", tags=["Policy Management"])
async def get_policy_configurations(org_name: str, installation_id: str):
    """
    Fetch the policy configurations for an organization (from tenant_settings.policies).
    """
    try:
        try:
            tenant_db, _ = resolve_tenant_db_required(installation_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        policy_config = get_policy_config(tenant_db)
        return {"org_name": org_name, "scanners": policy_config.get("scanners", {})}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching policy configurations for {org_name}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching policy configurations: {str(e)}")


@app.put("/scans/organizations/{org_name}/policy-configurations", tags=["Policy Management"])
async def update_policy_configurations(
    org_name: str,
    config: PolicyConfigurationsRequest,
    installation_id: str,
):
    """
    Partially update the policy configurations for an organization.

    Only the scanner keys included in the request body are updated; other
    scanners already stored for this org are left untouched.  This allows
    the IaC section of the UI and the Secrets section to save independently
    without overwriting each other.

    Request body:
    {
      "scanners": {
        "terraform_aws":   { "policies": { "AWS-SEC-001": false } },
        "secret_scanner":  { "policies": { "openai_api_key": false,
                                           "CREDIT_CARD_NUMBER": false } },
        "sbom":            { "policies": { "CVE-2024-1234": false } },
        ...
      }
    }

    A value of `false` disables the policy; `true` or omitting the key
    re-enables it.  Works for *any* scanner — not just IaC and secrets.
    """
    try:
        from datetime import timezone
        try:
            tenant_db, _ = resolve_tenant_db_required(installation_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        # Read the stored scanner configs first so a request that names a scanner
        # without supplying policies does not blank that scanner out.
        existing_doc = tenant_db.tenant_settings.find_one(
            {}, {"policies": 1, "_id": 0}
        ) or {}
        existing_scanners = (existing_doc.get("policies") or {}).get("scanners", {})

        set_fields: Dict[str, Any] = {"updatedAt": datetime.now(timezone.utc)}
        for scanner_key, scanner_data in config.scanners.items():
            policies = (
                scanner_data.get("policies")
                or scanner_data.get("detectors")
                or {}
            )
            scanner_entry: Dict[str, Any] = {"policies": policies}
            if "policies" not in scanner_data and "detectors" not in scanner_data:
                scanner_entry["policies"] = (
                    existing_scanners.get(scanner_key, {}).get("policies")
                    or existing_scanners.get(scanner_key, {}).get("detectors")
                    or {}
                )
            # Preserve the scanner-level enabled flag when present so the
            # read-time filter can short-circuit on fully-disabled scanners.
            if "enabled" in scanner_data:
                scanner_entry["enabled"] = scanner_data["enabled"]
            set_fields[f"policies.scanners.{scanner_key}"] = scanner_entry

        tenant_db.tenant_settings.update_one(
            {},
            {"$set": set_fields},
            upsert=True,
        )
        logger.info(
            f"Policy configurations updated for org '{org_name}': "
            f"scanners={list(config.scanners.keys())}"
        )
        return {"success": True, "message": "Policy configurations saved", "org_name": org_name}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating policy configurations for {org_name}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating policy configurations: {str(e)}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
