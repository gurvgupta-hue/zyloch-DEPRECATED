import os
import re
import logging
import joblib
import pandas as pd
import warnings
import requests
from math import log2
from typing import Dict, List, Any, Optional, Tuple, NamedTuple
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

from google.cloud import dlp_v2
from google.oauth2 import service_account

from scanner_core.base_scanner import (
    BaseScanner, 
    ScanRequest, 
    ScanResponse, 
    ScanResult, 
    ScanStatus, 
    ScanFinding, 
    ScanSeverity
)

logger = logging.getLogger("SecretScanner")
logger.setLevel(logging.INFO)
warnings.filterwarnings("ignore", category=UserWarning)

MODEL_FILE = os.path.join(os.path.dirname(__file__), "../policies/model/Voting_classifier_combined.joblib")

IGNORED_FILE_PATTERNS = {
    'yarn.lock', 'package-lock.json', 'go.sum', 'go.mod', 'cargo.lock', 
    'mvnw', 'mvnw.cmd', '.css', '.svg', '.ico', '.jpg', '.jpeg', '.png', 
    '__pycache__', '.git/', '.pyc', '.gradle', '.jar', '.class', 
    'node_modules/', 'vendor/', '.exe', '.app', '.com', '.apk', 
    '.so', '.dylib', '.lib', '.a', '.obj', '.o', '.csv', 'pom.properties', '.map',
}

# --- GCP DLP CONFIGURATION ---
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "sandbox-dev-474905")
GCP_CREDENTIALS_PATH = os.environ.get("GCP_CREDENTIALS_PATH", "gcp-credentials.json")
GCP_DLP_MAX_PAYLOAD_BYTES = 500 * 1024  # 500KB limit for inspect_content API

MANUAL_DETECTORS = [
    "INDIA_AADHAAR_INDIVIDUAL", "INDIA_PAN_INDIVIDUAL", "INDIA_PASSPORT", "INDIA_GST_INDIVIDUAL",
    "US_SOCIAL_SECURITY_NUMBER", "US_DRIVERS_LICENSE_NUMBER", "US_PASSPORT", 
    "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER", "US_EMPLOYER_IDENTIFICATION_NUMBER", 
    "US_BANK_ROUTING_MICR", "US_HEALTHCARE_NPI", "US_DEA_NUMBER", "US_MEDICARE_BENEFICIARY_ID_NUMBER", 
    "US_ADOPTION_TAXPAYER_IDENTIFICATION_NUMBER", "US_PREPARER_TAXPAYER_IDENTIFICATION_NUMBER", 
    "US_TOLLFREE_PHONE_NUMBER", "CREDIT_CARD_NUMBER", "CREDIT_CARD_TRACK_NUMBER", "IBAN_CODE", 
    "SWIFT_CODE", "FINANCIAL_ACCOUNT_NUMBER", "PERSON_NAME", "EMAIL_ADDRESS", "PHONE_NUMBER", 
    "STREET_ADDRESS", "DATE_OF_BIRTH", "IP_ADDRESS", "MAC_ADDRESS", "MAC_ADDRESS_LOCAL", "MEDICAL_TERM", "BLOOD_TYPE", "ICD9_CODE", 
    "ICD10_CODE", "FDA_CODE", "AUTH_TOKEN", "AZURE_AUTH_TOKEN", "ENCRYPTION_KEY", "JSON_WEB_TOKEN", "WEAK_PASSWORD_HASH", 
    "STORAGE_SIGNED_URL", "STORAGE_SIGNED_POLICY_DOCUMENT", "HTTP_COOKIE", "UK_NATIONAL_INSURANCE_NUMBER", 
    "UK_DRIVERS_LICENSE_NUMBER", "UK_PASSPORT", "UK_TAXPAYER_REFERENCE", "UK_ELECTORAL_ROLL_NUMBER", 
    "UK_NATIONAL_HEALTH_SERVICE_NUMBER", "CANADA_SOCIAL_INSURANCE_NUMBER", "CANADA_PASSPORT", 
    "CANADA_DRIVERS_LICENSE_NUMBER", "CANADA_BANK_ACCOUNT", "CANADA_OHIP", "CANADA_BC_PHN", 
    "CANADA_QUEBEC_HIN", "AUSTRALIA_TAX_FILE_NUMBER", "AUSTRALIA_MEDICARE_NUMBER", "AUSTRALIA_PASSPORT", 
    "AUSTRALIA_DRIVERS_LICENSE_NUMBER", "FRANCE_NIR", "FRANCE_CNI", "FRANCE_PASSPORT", 
    "FRANCE_TAX_IDENTIFICATION_NUMBER", "GERMANY_PASSPORT", "GERMANY_IDENTITY_CARD_NUMBER", 
    "GERMANY_TAXPAYER_IDENTIFICATION_NUMBER", "GERMANY_SCHUFA_ID", "SPAIN_DNI_NUMBER", "SPAIN_PASSPORT", 
    "SPAIN_SOCIAL_SECURITY_NUMBER", "SPAIN_NIE_NUMBER", "SPAIN_CIF_NUMBER", "JAPAN_PASSPORT", 
    "JAPAN_DRIVERS_LICENSE_NUMBER", "JAPAN_BANK_ACCOUNT", "BRAZIL_CPF_NUMBER", "BRAZIL_RG_NUMBER", 
    "ARGENTINA_DNI_NUMBER", "CHINA_PASSPORT", "CHINA_RESIDENT_ID_NUMBER", "KOREA_PASSPORT", "KOREA_RRN", 
    "MEXICO_CURP_NUMBER", "MEXICO_PASSPORT", "NETHERLANDS_BSN_NUMBER", "NETHERLANDS_PASSPORT", 
    "SINGAPORE_NATIONAL_REGISTRATION_ID_NUMBER", "SINGAPORE_PASSPORT", "SWEDEN_NATIONAL_ID_NUMBER", 
    "SWEDEN_PASSPORT", "TAIWAN_PASSPORT", "THAILAND_NATIONAL_ID_NUMBER", "TURKEY_ID_NUMBER", 
    "CHILE_CDI_NUMBER", "COLOMBIA_CDC_NUMBER", "VENEZUELA_CDI_NUMBER", "PARAGUAY_CIC_NUMBER", 
    "URUGUAY_CDI_NUMBER", "PERU_DNI_NUMBER", "INDONESIA_NIK_NUMBER", "INDONESIA_PASSPORT"
]

PCI_INFO_TYPES = {
    "CREDIT_CARD_NUMBER",
    "CREDIT_CARD_TRACK_NUMBER",
    "IBAN_CODE",
    "SWIFT_CODE",
    "FINANCIAL_ACCOUNT_NUMBER",
    "US_BANK_ROUTING_MICR",
    "CANADA_BANK_ACCOUNT",
    "JAPAN_BANK_ACCOUNT",
}

# Well-known open-source contributor/attribution convention files. PERSON_NAME
# and EMAIL_ADDRESS hits in these files are overwhelmingly maintainer/contributor
# attribution metadata rather than a sensitive data disclosure (e.g. a repo's
# .mailmap can legitimately list thousands of contributor names/emails). Real-world
# validation against large monorepos (react, rails) showed these files accounting
# for 60-80% of all Secret Scanner findings. Rather than suppress them outright
# (which could hide a genuine leak pasted into one of these files), we downgrade
# the severity so they stay visible without dominating the alert stream.
ATTRIBUTION_FILE_BASENAMES = {
    '.mailmap', 'authors', 'authors.md', 'authors.txt', 'contributors',
    'contributors.md', 'contributors.txt', 'maintainers.md', 'maintainers.txt',
    'codeowners', 'changelog.md', 'changelog.txt', 'changelog', 'notice',
    'notice.md', 'license', 'license.md', 'license.txt',
}
ATTRIBUTION_PII_INFO_TYPES = {"PERSON_NAME", "EMAIL_ADDRESS"}


def is_attribution_file(file_path: str) -> bool:
    basename = os.path.basename(file_path).lower()
    if basename in ATTRIBUTION_FILE_BASENAMES:
        return True
    # Package-manager manifests carry a similar contributors/authors list
    # (package.json "contributors", *.gemspec "authors", Gemfile.lock, Cargo.toml).
    if basename in ('gemfile.lock',) or basename.endswith('.gemspec'):
        return True
    return False


# --- Utility Functions ---

def redact_secret(value: str) -> str:
    if not value:
        return value
    return value[0] + '*' * (len(value) - 1)

def shannon_entropy(data: str) -> float:
    if not data: return 0
    entropy = 0
    for char_code in range(256):
        p_x = data.count(chr(char_code)) / len(data)
        if p_x > 0:
            entropy -= p_x * log2(p_x)
    return entropy

def bin_entropy(entropy: float) -> Dict[str, int]:
    return {
        "entropy_0_1": int(0 <= entropy < 1), "entropy_1_2": int(1 <= entropy < 2),
        "entropy_2_3": int(2 <= entropy < 3), "entropy_3_4": int(3 <= entropy < 4),
        "entropy_gt_4": int(entropy >= 4),
    }

def extract_features_from_line(line: str, file_path: str) -> Dict[str, Any]:
    features = defaultdict(int)
    lower_line, file_lower = line.lower(), file_path.lower()
    features.update({
        "has_parentheses": int("(" in line or ")" in line), 
        "has_brackets": int(any(c in line for c in "[]{}")),
        "has_period": int("." in line), 
        "starts_with_dollar": int(line.strip().startswith("$")),
        "has_password_word": int("password" in lower_line), 
        "has_spaces": int(" " in line),
        "has_html_tags": int(bool(re.search(r"</?\w+>", line))),
        "is_comment": int(line.strip().startswith(("#", "*", "//", "/*"))),
        "has_arrow": int("->" in line or "=>" in line),
        "has_null_like": int(any(x in lower_line for x in ["null", "nil", "undefined", "none", "true", "false"])),
        "has_begin_private_key": int("-----BEGIN" in line and "PRIVATE KEY" in line),
    })
    tokens = line.strip().split()
    features["is_numerical"] = int(tokens[-1].replace("=", "").replace(":", "").isdigit()) if tokens else 0
    features.update(bin_entropy(shannon_entropy(line)))
    features.update({
        "is_config_file": int(any(ext in file_lower for ext in [".yml", ".yaml", ".env", ".json", ".ini", ".toml"])),
        "is_settings_file": int("settings" in file_lower),
        "is_key_or_pem_file": int(file_lower.endswith(('.pem', '.key'))),
        "path_has_test_or_example": int("test" in file_lower or "example" in file_lower),
        "is_properties_file": int(".properties" in file_lower), 
        "is_readme_file": int("readme" in file_lower),
        "is_language_file": int("lang" in file_lower or "i18n" in file_lower),
    })
    return dict(features)


class SecretVerifier:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecretScanner-Validator/1.0"})
        self.signatures = {
            # AI provider keys
            'openai': r'sk-[a-zA-Z0-9\-_]{20,}',
            'anthropic': r'sk-ant-api03-[a-zA-Z0-9\-_]{20,}',
            'gemini': r'AIzaSy[0-9A-Za-z\-_]{33}',
            'grok': r'xai-[a-zA-Z0-9]{20,}',
            'huggingface': r'hf_[a-zA-Z0-9]{34}',
            'cohere': r'(?<![a-zA-Z0-9])[a-zA-Z0-9]{40}(?![a-zA-Z0-9])',
            # Generic credential types
            'github': r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
            'slack': r'xox[baprs]-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24}',
            'stripe': r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}',
            'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
        }

    def get_candidate(self, finding: ScanFinding) -> Optional[Tuple[str, str]]:
        # Prefer the raw (unredacted) match stored in code field; fall back to the redacted line
        text = finding.code or finding.match or ""
        for provider, pattern in self.signatures.items():
            match = re.search(pattern, text)
            if match: return match.group(0), provider
        return None

    def verify(self, finding: ScanFinding) -> Optional[ScanFinding]:
        candidate = self.get_candidate(finding)
        if not candidate: return finding 
        key, provider = candidate
        is_valid = False
        r = None
        try:
            if provider == 'openai':
                r = self.session.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=5)
            elif provider == 'anthropic':
                r = self.session.get("https://api.anthropic.com/v1/models", headers={"x-api-key": key, "anthropic-version": "2023-06-01"}, timeout=5)
            elif provider == 'gemini':
                r = self.session.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={key}", timeout=5)
            elif provider == 'grok':
                r = self.session.get("https://api.x.ai/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=5)
            elif provider == 'huggingface':
                r = self.session.get("https://huggingface.co/api/whoami-v2", headers={"Authorization": f"Bearer {key}"}, timeout=5)
            elif provider == 'cohere':
                r = self.session.get("https://api.cohere.com/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=5)
            elif provider == 'github':
                r = self.session.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"token {key}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
                    timeout=5,
                )
            elif provider == 'slack':
                r = self.session.post("https://slack.com/api/auth.test", data={"token": key}, timeout=5)
                # Slack always returns HTTP 200; validity is in the JSON body
                if r.status_code == 200:
                    is_valid = r.json().get("ok", False)
            elif provider == 'stripe':
                r = self.session.get(
                    "https://api.stripe.com/v1/customers?limit=1",
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=5,
                )
            elif provider == 'google_oauth':
                r = self.session.get(
                    f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={key}",
                    timeout=5,
                )

            # For all providers except Slack (handled above), derive validity from HTTP status
            if r is not None and provider != 'slack':
                if r.status_code == 200:
                    is_valid = True

        except Exception as e:
            logger.error(f"Network error verifying {provider}: {e}")
            return finding

        if is_valid:
            finding.description += f" [VERIFIED LIVE {provider.upper()} KEY]"
            return finding
        return None


class PatternDef(NamedTuple):
    label: str
    pattern: str
    confidence: str 
    compiled: re.Pattern 

class ContentFiltor:
    def __init__(self):
        self.sensitive_patterns: Dict[str, List[PatternDef]] = defaultdict(list)
        self.category_matchers: Dict[str, re.Pattern] = {}
        
        self._initialize_patterns()
        self._compile_optimization()

        self.safe_keywords = {
            'checksum', 'sha1', 'sha256', 'sha512', 'md5', 'uuid', 'guid',
            'version', 'integrity', 'git-lfs', 'author',
            'license', 'copyright', 'timestamp', 'date', 'image', 'icon', 'example'
        }

        self.file_specific_ignores = {
            '.xml': [r'<version>', r'<scope>', r'<groupId>', r'<artifactId>', r'xmlns'],
            '.pom': [r'<version>', r'<scope>', r'<groupId>', r'<artifactId>'],
            '.go': [r'import ', r'package ', r'//', r'/\*'], 
        }
        
        self.context_patterns = [
            r'(?i)(?:api|secret|access)[_-]?(?:key|token)\s*[:=]', 
            r'(?i)(?:password|pass|pwd)\s*[:=]',
            r'(?i)private[_-]?key\s*[:=]',
            r'(?i)bearer\s+',
        ]

    def _add(self, category: str, label: str, pattern: str, confidence: str = 'HIGH'):
        compiled = re.compile(pattern)
        self.sensitive_patterns[category].append(PatternDef(label, pattern, confidence, compiled))

    def _compile_optimization(self):
        for category, patterns in self.sensitive_patterns.items():
            if not patterns: continue
            combined_pattern = "|".join(f"(?:{p.pattern})" for p in patterns)
            try:
                self.category_matchers[category] = re.compile(combined_pattern)
            except Exception as e:
                logger.warning(f"Could not optimize category {category}: {e}")
                pass

    def _initialize_patterns(self):
        self._add('ai_keys', 'openai_api_key', r"\bsk-[a-zA-Z0-9\-_]{30,}\b")
        self._add('ai_keys', 'openai_org_id', r'\borg-[a-zA-Z0-9]{24}\b')
        self._add('ai_keys', 'anthropic_api_key', r'\bsk-ant-api03-[a-zA-Z0-9\-_]{20,}\b')
        self._add('ai_keys', 'gemini_api_key', r'\bAIzaSy[0-9A-Za-z\-_]{33}\b')
        self._add('ai_keys', 'huggingface_token', r'\bhf_[a-zA-Z0-9]{34}\b')
        self._add('ai_keys', 'cohere_api_key', r'\b(?<![a-zA-Z0-9])[a-zA-Z0-9]{40}(?![a-zA-Z0-9])\b')
        self._add('ai_keys', 'grok_api_key', r'\bxai-[a-zA-Z0-9]{48,}\b')
        self._add('credentials', 'aws_access_key', r"\bAKIA[A-Z0-9]{16}\b")
        self._add('credentials', 'aws_secret_key', r"(?i)(?:aws_secret|secret_access_key)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")
        self._add('credentials', 'google_api', r"\bAIza[A-Za-z0-9_-]{35}\b")
        self._add('credentials', 'stripe_secret', r"\b(?:sk_live|sk_test)_[A-Za-z0-9]{24,}\b")
        self._add('credentials', 'stripe_publishable', r"\b(?:pk_live|pk_test)_[A-Za-z0-9]{24,}\b")
        self._add('credentials', 'github_token', r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b")
        self._add('credentials', 'github_fine_grained_pat', r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b")
        self._add('credentials', 'google_oauth_client_secret', r"\bGOCSPX-[A-Za-z0-9_-]{28}\b")
        self._add('credentials', 'digitalocean_token', r"\bdop_v1_[a-f0-9]{64}\b")
        self._add('credentials', 'twilio_account_sid', r"\bAC[a-f0-9]{32}\b")
        self._add('credentials', 'twilio_auth_token', r"(?i)twilio(?:[_-]?auth)?(?:[_-]?token)?\s*[:=]\s*['\"]?[a-f0-9]{32}['\"]?")
        self._add('credentials', 'sendgrid_api_key', r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")
        self._add('credentials', 'aws_session_token', r"\b(?:FwoG|IQoJ)[A-Za-z0-9/+=]{20,}\b")
        self._add('credentials', 'slack_token', r"\bxox[baprs]-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24}\b")
        self._add('credentials', 'slack_webhook', r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+\b")
        self._add('credentials', 'jwt', r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
        self._add('credentials', 'private_key', r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----")
        self._add('credentials', 'basic_auth', r"\bBasic\s+[A-Za-z0-9+/]+=*\b")
        self._add('credentials', 'bearer_token', r"\bBearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
        self._add('credentials', 'database_url', r"(?i)(?:mysql|postgres|postgresql|mongodb|redis|mssql):\\/\\/[^:]+:[^@]+@[^/]+")
        self._add('credentials', 'mongodb_srv', r"mongodb\+srv:\\/\\/[^:]+:[^@]+@[^/]+")
        self._add('api_keys', 'generic_api_key', r'(?i)(?:api|secret|access)[_-]?(?:key|token)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?')
        self._add('api_keys', 'aws_access_key_legacy', r'AKIA[0-9A-Z]{16}')
        self._add('api_keys', 'google_api_legacy', r'AIzaSy[0-9A-Za-z\\-_]{33}')
        self._add('api_keys', 'stripe_pk_sk_legacy', r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24}')
        self._add('api_keys', 'github_personal_token_legacy', r'ghp_[a-zA-Z0-9]{36}')
        self._add('api_keys', 'slack_token_legacy', r'xox[baprs]-([0-9a-zA-Z]{10,48})')
        self._add('api_keys', 'slack_webhook_legacy', r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}')
        self._add('api_keys', 'aws_session_token_legacy', r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}')
        self._add('api_keys', 'facebook_token', r'(?i)(facebook|fb)(.{0,20})?[\'"][0-9a-f]{32}[\'"]')
        self._add('api_keys', 'twitter_oauth', r'(?i)twitter(.{0,20})?[\'"][0-9a-zA-Z]{35,44}[\'"]')
        self._add('api_keys', 'heroku_api', r'(?i)heroku(.{0,20})?[\'"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\'"]')
        self._add('api_keys', 'mailchimp_api', r'(?i)(mailchimp|mc)(.{0,20})?[\'"][0-9a-f]{32}-us[0-9]{1,2}[\'"]')
        self._add('api_keys', 'stripe_expanded', r'(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}')
        self._add('api_keys', 'square_token_legacy', r'sq0atp-[0-9A-Za-z\-_]{22}')
        self._add('api_keys', 'paypal_braintree_legacy', r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}')
        self._add('api_keys', 'google_oauth_legacy', r'ya29\.[0-9A-Za-z\-_]+')
        self._add('database_urls', 'generic_db_url', r'(?i)(?:database[_-]?url|db[_-]?url|connection[_-]?string)\s*[:=]\s*["\']?(.*?://.*?)["\']?')
        self._add('database_urls', 'mongodb_url', r'mongodb(?:\+srv)?://[^"\'\s]+')
        self._add('database_urls', 'postgres_url', r'postgres://[^"\'\s]+')
        self._add('passwords', 'generic_password', r'(?i)(?:password|pass|pwd)\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?')
        self._add('private_keys', 'generic_private_key_header', r'-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|PGP|X509)\s+PRIVATE\s+KEY-----')
        self._add('private_keys', 'simple_private_key_header', r'-----BEGIN\s+PRIVATE\s+KEY-----')
        self._add('jwt_tokens', 'jwt_pattern', r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*')
        self._add('generic_secrets', 'assignment_high_entropy', r'[:=]\s*["\']([a-zA-Z0-9+/=_-]{32,})["\']')
        self._add('generic_secrets', 'long_base64_string', r'[\'"][a-zA-Z0-9/+]{40,}={0,2}[\'"]')
        
    def is_technical_file_ignore(self, line: str, file_path: str) -> bool:
        for ext, patterns in self.file_specific_ignores.items():
            if file_path.endswith(ext):
                if any(re.search(p, line) for p in patterns):
                    return True
        return False

    def is_safe_keyword_present(self, line: str) -> bool:
        lower_line = line.lower()
        return any(kw in lower_line for kw in self.safe_keywords)

    def detect_sensitive_data(self, content: str, file_path: str = "", disabled_policies: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Scan *content* for sensitive patterns.

        Args:
            content: File text to scan.
            file_path: Path used for technical-file filtering heuristics.
            disabled_policies: Mapping of policy ID → False for policies that
                should be silently skipped.  Keys may be bare labels
                (``"openai_api_key"``) or ``"category/label"`` style strings.
        """
        disabled_policies = disabled_policies or {}
        findings = []
        lines = content.splitlines()
                
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if len(stripped) < 10: 
                continue

            if self.is_technical_file_ignore(line, file_path):
                continue

            for category, patterns in self.sensitive_patterns.items():
                matcher = self.category_matchers.get(category)
                if matcher and not matcher.search(line):
                    continue
                
                for pattern_def in patterns:
                    # Skip patterns whose policy is disabled.
                    # Check both "label" and "category/label" forms.
                    if (
                        disabled_policies.get(pattern_def.label) is False
                        or disabled_policies.get(f"{category}/{pattern_def.label}") is False
                    ):
                        continue

                    match = pattern_def.compiled.search(line)
                    if match:
                        matched_str = match.group(0)
                        if "test" in matched_str.lower(): 
                             continue

                        redacted_line = stripped.replace(matched_str, redact_secret(matched_str), 1)
                        findings.append({
                            "category": category,
                            "label": pattern_def.label,
                            "line_number": str(i),
                            "match": redacted_line,
                            "raw_match": matched_str,
                        })
                        break 
                        
        return findings

# --- Globals for Workers ---
worker_filtor: Optional[ContentFiltor] = None
worker_pipeline: Any = None
worker_feature_cols: List[str] = []
worker_dlp_client: Optional[dlp_v2.DlpServiceClient] = None
worker_dlp_parent: Optional[str] = None
worker_dlp_info_types: Optional[List[Dict[str, str]]] = None
# Disabled policies injected per scan (policy_id → False).  Set by the scan
# controller via ScanRequest.metadata before the worker pool is started.
worker_disabled_policies: Dict[str, Any] = {}


def init_worker(model_path: str, gcp_project_id: str, gcp_key_path: str, disabled_policies: Dict[str, Any] = None):
    """
    Runs ONCE per process when the pool starts. 
    Loads Regex Engine, ML Models, and GCP DLP Client into memory.
    """
    global worker_filtor, worker_pipeline, worker_feature_cols
    global worker_dlp_client, worker_dlp_parent, worker_dlp_info_types
    global worker_disabled_policies
    worker_disabled_policies = disabled_policies or {}
    
    # 1. Initialize Regex Engine
    try:
        worker_filtor = ContentFiltor()
    except Exception as e:
        print(f"Worker failed to init Filtor: {e}", flush=True)

    # 2. Load ML Model
    if model_path and os.path.exists(model_path):
        try:
            worker_pipeline, worker_feature_cols = joblib.load(model_path)
        except Exception as e:
            print(f"Worker failed to load ML model: {e}", flush=True)
            worker_pipeline = None
            worker_feature_cols = []

    # 3. Initialize Google Cloud DLP Client
    if gcp_key_path and os.path.exists(gcp_key_path):
        try:
            credentials = service_account.Credentials.from_service_account_file(gcp_key_path)
            worker_dlp_client = dlp_v2.DlpServiceClient(credentials=credentials)
            worker_dlp_parent = f"projects/{gcp_project_id}/locations/global"
            worker_dlp_info_types = [{"name": detector} for detector in MANUAL_DETECTORS]
        except Exception as e:
            print(f"Worker failed to initialize DLP Client: {e}. Skipping DLP Scans.", flush=True)
            worker_dlp_client = None


def process_single_file(file_info: Tuple[str, str]) -> List[ScanFinding]:
    file_path, relative_path = file_info
    global worker_filtor, worker_pipeline, worker_feature_cols, worker_dlp_client, worker_dlp_parent, worker_dlp_info_types
    global worker_disabled_policies
    
    local_findings = []
    if worker_filtor is None:
        return [] 

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        if not content: return []

        # --- 1. Regex Scanning ---
        regex_hits = worker_filtor.detect_sensitive_data(
            content, file_path, disabled_policies=worker_disabled_policies
        )
        for hit in regex_hits:
             policy_name = f"{hit['category']}/{hit['label']}"
             sev = ScanSeverity.HIGH
             if hit['category'] in ['private_keys', 'ai_keys']:
                sev = ScanSeverity.CRITICAL
                
             local_findings.append(ScanFinding(
                policy=policy_name,
                severity=sev,
                description=f"Detected {hit['label']} ({hit['category']})",
                file=relative_path, line=hit['line_number'], match=hit['match'],
                code=hit.get('raw_match'),
             ))

        # --- 2. Machine Learning Scanning ---
        if worker_pipeline:
            lines = content.splitlines()
            valid_indices = [
                i for i, line in enumerate(lines) 
                if not worker_filtor.is_safe_keyword_present(lines[i])
            ]
            
            if valid_indices:
                feature_rows = [extract_features_from_line(lines[i], relative_path) for i in valid_indices]
                df = pd.DataFrame(feature_rows)
                
                for col in worker_feature_cols:
                    if col not in df.columns: df[col] = 0
                
                predictions = worker_pipeline.predict(df[worker_feature_cols])
                
                for idx, label in enumerate(predictions):
                    if label == 1:
                        original_idx = valid_indices[idx]
                        line_content = lines[original_idx].strip()
                        entropy = shannon_entropy(line_content)
                        has_context = any(re.search(p, line_content) for p in worker_filtor.context_patterns)
                        
                        if (entropy > 4.5 and has_context) or (entropy > 5.8):
                            local_findings.append(ScanFinding(
                                policy="Vulnerability",
                                severity=ScanSeverity.MEDIUM,
                                description="API_KEY",
                                file=relative_path, line=str(original_idx + 1), match=redact_secret(line_content)
                            ))

        # --- 3. Google Cloud DLP (PII & PCI) Scanning ---
        # Note: Bypassing DLP scan for files exceeding GCP's 500KB payload limit.
        if worker_dlp_client and len(content.encode('utf-8')) <= GCP_DLP_MAX_PAYLOAD_BYTES:
            try:
                inspect_config = {
                    "info_types": worker_dlp_info_types,
                    "include_quote": True,
                    "min_likelihood": dlp_v2.Likelihood.LIKELY,
                }
                item = {"value": content}
                
                response = worker_dlp_client.inspect_content(
                    request={
                        "parent": worker_dlp_parent,
                        "inspect_config": inspect_config,
                        "item": item,
                    }
                )

                if response.result.findings:
                    lines = content.splitlines()
                    file_is_attribution = is_attribution_file(relative_path)
                    for finding in response.result.findings:
                        quote = finding.quote
                        info_type = finding.info_type.name
                        likelihood = finding.likelihood.name

                        # Find approximate line number. Prefer an exact per-line
                        # match; fall back to locating the quote in the full
                        # content (DLP quotes can span whitespace that differs
                        # slightly from the raw line) so we avoid reporting an
                        # untriageable "Unknown" line whenever possible.
                        line_num = "Unknown"
                        for idx, line in enumerate(lines):
                            if quote in line:
                                line_num = str(idx + 1)
                                break
                        else:
                            offset = content.find(quote)
                            if offset != -1:
                                line_num = str(content.count("\n", 0, offset) + 1)

                        # Determine severity
                        sev = ScanSeverity.CRITICAL if "CREDENTIALS" in info_type or "TOKEN" in info_type or "KEY" in info_type else ScanSeverity.HIGH

                        data_class = "PCI" if info_type in PCI_INFO_TYPES else "PII"

                        # Well-known contributor/attribution files (.mailmap, AUTHORS,
                        # CONTRIBUTORS, package manifests, ...) legitimately list many
                        # real names and emails; flagging each one as a HIGH-severity
                        # PII disclosure is not an actionable security finding.
                        # Downgrade rather than suppress so it stays visible.
                        if file_is_attribution and info_type in ATTRIBUTION_PII_INFO_TYPES:
                            sev = ScanSeverity.LOW
                            data_class += " (contributor attribution file - low risk)"

                        local_findings.append(ScanFinding(
                            policy=f"{info_type}",
                            severity=sev,
                            description=data_class,
                            file=relative_path, line=line_num, match=redact_secret(quote)
                        ))
                        
            except Exception as e:
                # Log error but don't stop the rest of the processing
                print(f"DLP Error on {relative_path}: {e}", flush=True)

    except Exception as e:
        print(f"Error processing {relative_path}: {e}", flush=True)
        
    return local_findings


class SecretScanner(BaseScanner):
    def __init__(self):
        super().__init__(scanner_type="secret_scanner")
        self.verifier = SecretVerifier()
        try:
            _, self.feature_cols = joblib.load(MODEL_FILE)
            self.model_loaded = True
        except Exception:
            self.model_loaded = False
            self.feature_cols = []

    def scan(self, request: ScanRequest) -> ScanResponse:
        start_time = datetime.now()
        repo_path = request.repo_path
        if not os.path.exists(repo_path):
            return self._create_error_response(request.scan_id, f"Path not found: {repo_path}")

        file_tasks = []
        scanned_files = []

        for root, _, files in os.walk(repo_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, repo_path)
                if not any(p in rel_path for p in IGNORED_FILE_PATTERNS):
                    file_tasks.append((file_path, rel_path))
                    scanned_files.append(rel_path)

        raw_findings = []
        current_model_path = MODEL_FILE if self.model_loaded else None
        disabled_policies = (request.metadata or {}).get("disabled_policies", {})

        # Pass initializer with ML paths and GCP configs
        with ProcessPoolExecutor(
            max_workers=os.cpu_count(), 
            initializer=init_worker, 
            initargs=(current_model_path, GCP_PROJECT_ID, GCP_CREDENTIALS_PATH, disabled_policies)
        ) as executor:
            
            futures = [executor.submit(process_single_file, task) for task in file_tasks]
            
            for future in as_completed(futures):
                try:
                    raw_findings.extend(future.result())
                except Exception as e:
                    print(f"Task failed: {e}", flush=True)

        seen = set()
        unique_findings = []
        for f in raw_findings:
            # Create a unique key using file, line, and match to avoid identical deduplication across files
            dedupe_key = f"{f.file}:{f.line}:{f.match}"
            if dedupe_key not in seen:
                unique_findings.append(f)
                seen.add(dedupe_key)

        verified_findings = []
        if unique_findings:
            with ThreadPoolExecutor(max_workers=20) as v_executor:
                v_futures = {v_executor.submit(self.verifier.verify, f): f for f in unique_findings}
                for v_future in as_completed(v_futures):
                    res = v_future.result()
                    if res:
                        # Clear the raw match stored in code to avoid leaking secrets in the response
                        res.code = None
                        verified_findings.append(res)

        duration = (datetime.now() - start_time).total_seconds()
        result = ScanResult(
            scanner_type=self.scanner_type,
            status=ScanStatus.COMPLETED,
            findings=verified_findings,
            scanned_files=scanned_files, 
            scan_duration=duration,
            metadata={"total_files": len(scanned_files), "hits": len(verified_findings)}
        )
        return self._create_success_response(request.scan_id, result)

def scan_repository(request: ScanRequest) -> ScanResponse:
    return SecretScanner().scan(request)