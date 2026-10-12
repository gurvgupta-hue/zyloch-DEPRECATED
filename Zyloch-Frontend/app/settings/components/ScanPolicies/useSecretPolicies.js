// ScanPolicies/useSecretPolicies.js
import { useState, useEffect } from 'react';
import secretDetectionData from '@/data/secretDetection.json';
import TechIcon from '@/components/common/TechIcon.js';
import { AlertTriangle, AlertCircle, Info } from 'lucide-react';
import {
  getPolicyConfigurations,
  updatePolicyConfigurations,
} from '@/lib/api/organization';

const detections = secretDetectionData.detections ?? [];

// Maps infoType → subcategory bucket for "Credentials and Tokens" / "Secrets and Credentials"
const INFO_TYPE_BUCKET = {
  // API Keys
  cohere_api_key: 'api-keys',
  gemini_api_key: 'api-keys',
  grok_api_key: 'api-keys',
  openai_api_key: 'api-keys',
  openai_org_id: 'api-keys',
  google_api: 'api-keys',
  google_api_legacy: 'api-keys',
  heroku_api: 'api-keys',
  generic_api_key: 'api-keys',
  aws_access_key: 'api-keys',
  aws_access_key_legacy: 'api-keys',
  stripe_publishable: 'api-keys',
  stripe_secret: 'api-keys',
  stripe_expanded: 'api-keys',
  stripe_pk_sk_legacy: 'api-keys',

  // Access Tokens
  github_token: 'access-tokens',
  github_personal_token_legacy: 'access-tokens',
  slack_token: 'access-tokens',
  slack_token_legacy: 'access-tokens',
  slack_webhook: 'access-tokens',
  slack_webhook_legacy: 'access-tokens',
  facebook_token: 'access-tokens',
  twitter_oauth: 'access-tokens',
  google_oauth_legacy: 'access-tokens',
  aws_session_token_legacy: 'access-tokens',
  paypal_braintree_legacy: 'access-tokens',
  square_token_legacy: 'access-tokens',
  bearer_token: 'access-tokens',
  basic_auth: 'access-tokens',
  huggingface_token: 'access-tokens',
  AUTH_TOKEN: 'access-tokens',
  AZURE_AUTH_TOKEN: 'access-tokens',
  HTTP_COOKIE: 'access-tokens',
  STORAGE_SIGNED_POLICY_DOCUMENT: 'access-tokens',
  STORAGE_SIGNED_URL: 'access-tokens',

  // Credentials
  aws_secret_key: 'credentials',
  database_url: 'credentials',
  mongodb_srv: 'credentials',
  mongodb_url: 'credentials',
  postgres_url: 'credentials',
  private_key: 'credentials',
  generic_db_url: 'credentials',
  generic_password: 'credentials',
  jwt: 'credentials',
  ENCRYPTION_KEY: 'credentials',
  WEAK_PASSWORD_HASH: 'credentials',
  JSON_WEB_TOKEN: 'credentials',

  // Generic Secrets
  jwt_pattern: 'generic-secrets',
  assignment_high_entropy: 'generic-secrets',
  long_base64_string: 'generic-secrets',
  generic_private_key_header: 'generic-secrets',
  simple_private_key_header: 'generic-secrets',
};

function buildInitialPolicies() {
  const buckets = {
    'dlp-pii': [],
    'dlp-pci': [],
    'dlp-phi': [],
    'api-keys': [],
    'access-tokens': [],
    credentials: [],
    'generic-secrets': [],
  };

  const seen = new Set();

  detections.forEach((item) => {
    const infoType = item.infoTypes?.[0] ?? '';
    const uniqueKey = infoType || item.title;
    if (seen.has(uniqueKey)) return;
    seen.add(uniqueKey);

    const policy = {
      id: uniqueKey,
      name: item.title,
      finding: item.finding,
      recommendation: item.recommendation,
      severity: item.severity?.toUpperCase(),
      infoType,
      enabled: true,
    };

    const cat = item.category;
    if (cat === 'Sensitive PII' || cat === 'Personal Data') {
      buckets['dlp-pii'].push(policy);
    } else if (cat === 'PCI and Financial Data') {
      buckets['dlp-pci'].push(policy);
    } else if (cat === 'Healthcare and Medical Data') {
      buckets['dlp-phi'].push(policy);
    } else {
      // "Credentials and Tokens" or "Secrets and Credentials"
      const bucket = INFO_TYPE_BUCKET[infoType] ?? 'generic-secrets';
      buckets[bucket].push(policy);
    }
  });

  return buckets;
}

const INITIAL_POLICIES = buildInitialPolicies();

const cloneState = (value) => {
  if (typeof globalThis.structuredClone === 'function') {
    return globalThis.structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value));
};

export const useSecretPolicies = ({ orgName } = {}) => {
  const [selectedCategory, setSelectedCategory] = useState('dlp-pii');
  const [expandedCategories, setExpandedCategories] = useState(['dlp', 'keys-tokens', 'generic']);
  const [policies, setPolicies] = useState(INITIAL_POLICIES);
  const [savedPolicies, setSavedPolicies] = useState(INITIAL_POLICIES);

  const SCANNER_KEY = 'secret_scanner';

  // Load persisted config through the tenant-scoped backend (MT-08).
  // The previous URL pointed at a scanner-service route that does not exist,
  // so this panel always silently fell back to defaults.
  useEffect(() => {
    const load = async () => {
      try {
        const scannersCfg = await getPolicyConfigurations();
        const scannerCfg = scannersCfg?.[SCANNER_KEY];
        if (!scannerCfg) return;
        // Support both "policies" (new) and "detectors" (legacy) keys.
        const disabled = scannerCfg.policies || scannerCfg.detectors || {};
        setPolicies(prev => {
          const updated = {};
          for (const [bucket, policyList] of Object.entries(prev)) {
            updated[bucket] = policyList.map(p => ({
              ...p,
              enabled: scannerCfg.enabled !== false && disabled[p.id] !== false,
            }));
          }
          setSavedPolicies(updated);
          return updated;
        });
      } catch (e) {
        console.error('Error loading secret policy config:', e);
      }
    };
    load();
  }, []);

  const saveToApi = async (updatedPolicies) => {
    const disabledPolicies = {};
    for (const policyList of Object.values(updatedPolicies)) {
      for (const p of policyList) {
        if (!p.enabled) disabledPolicies[p.id] = false;
      }
    }
    // Merge-scoped to this scanner only, so saving secrets never clobbers the
    // IaC panel's toggles (MT-08).
    await updatePolicyConfigurations({ [SCANNER_KEY]: { policies: disabledPolicies } });
  };

  const secretCategories = [
    {
      id: 'dlp',
      name: 'DLP',
      icon: <TechIcon name="key" size={16} className="text-current" />,
      description: 'Data Loss Prevention — PII, PCI, PHI',
      subCategories: [
        { id: 'dlp-pii', name: 'PII', icon: <TechIcon name="key" size={14} className="text-current" /> },
        { id: 'dlp-pci', name: 'PCI', icon: <TechIcon name="key" size={14} className="text-current" /> },
        { id: 'dlp-phi', name: 'PHI', icon: <TechIcon name="key" size={14} className="text-current" /> },
      ],
    },
    {
      id: 'keys-tokens',
      name: 'Keys & Tokens',
      icon: <TechIcon name="key" size={16} className="text-current" />,
      description: 'API keys, access tokens, and credentials',
      subCategories: [
        { id: 'api-keys', name: 'API Keys', icon: <TechIcon name="key" size={14} className="text-current" /> },
        { id: 'access-tokens', name: 'Access Tokens', icon: <TechIcon name="key" size={14} className="text-current" /> },
        { id: 'credentials', name: 'Credentials', icon: <TechIcon name="key" size={14} className="text-current" /> },
      ],
    },
    {
      id: 'generic',
      name: 'Generic Secrets',
      icon: <TechIcon name="secrets" size={16} className="text-current" />,
      description: 'High-entropy strings and generic secret patterns',
      subCategories: [
        { id: 'generic-secrets', name: 'Generic Secrets', icon: <TechIcon name="key" size={14} className="text-current" /> },
      ],
    },
  ];

  const handlePolicyToggle = (policyId, subCategory) => {
    setPolicies(prev => ({
      ...prev,
      [subCategory]: prev[subCategory].map(policy =>
        policy.id === policyId ? { ...policy, enabled: !policy.enabled } : policy
      ),
    }));
  };

  const handleBulkToggle = (subCategory, enabled, severityFilter = 'ALL') => {
    setPolicies(prev => ({
      ...prev,
      [subCategory]: (prev[subCategory] || []).map(policy => {
        if (severityFilter === 'ALL' || (policy.severity && policy.severity.toUpperCase() === severityFilter)) {
          return { ...policy, enabled };
        }
        return policy;
      }),
    }));
  };

  const savePreferences = async () => {
    await saveToApi(policies);
    setSavedPolicies(cloneState(policies));
  };

  const discardChanges = () => {
    setPolicies(cloneState(savedPolicies));
  };

  const calculateUnsavedCount = () => {
    if (!savedPolicies || !policies) return 0;
    let count = 0;
    const categories = new Set([
      ...Object.keys(savedPolicies),
      ...Object.keys(policies),
    ]);

    categories.forEach(cat => {
      const current = policies[cat] || [];
      const saved = savedPolicies[cat] || [];

      const savedById = new Map(saved.map((policy) => [policy.id, policy]));
      const currentById = new Map(current.map((policy) => [policy.id, policy]));

      current.forEach((policy) => {
        const savedPolicy = savedById.get(policy.id);
        if (!savedPolicy) {
          count++;
          return;
        }

        if (policy.enabled !== savedPolicy.enabled) {
          count++;
        }
      });

      saved.forEach((policy) => {
        if (!currentById.has(policy.id)) {
          count++;
        }
      });
    });

    return count;
  };

  const unsavedChangesCount = calculateUnsavedCount();

  const toggleCategory = (categoryId) => {
    setExpandedCategories(prev =>
      prev.includes(categoryId)
        ? prev.filter(id => id !== categoryId)
        : [...prev, categoryId]
    );
  };

  const calculatePolicyStats = () => {
    let totalPolicies = 0;
    let enabledPolicies = 0;
    let disabledPolicies = 0;

    Object.values(policies).forEach(policyList => {
      policyList.forEach(policy => {
        totalPolicies++;
        if (policy.enabled) enabledPolicies++;
        else disabledPolicies++;
      });
    });

    return {
      totalPolicies,
      enabledPolicies,
      disabledPolicies,
      enabledPercentage: totalPolicies > 0 ? Math.round((enabledPolicies / totalPolicies) * 100) : 0,
      disabledPercentage: totalPolicies > 0 ? Math.round((disabledPolicies / totalPolicies) * 100) : 0,
    };
  };

  const getCategoryCount = (category) =>
    (category.subCategories || []).reduce(
      (sum, sub) => sum + (policies[sub.id]?.length || 0),
      0
    );

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-[var(--danger)]/5 text-[var(--danger)] border-[var(--danger)]/30';
      case 'HIGH': return 'bg-[var(--warning)]/5 text-[var(--warning)] border-[var(--warning)]/30';
      case 'MEDIUM': return 'bg-[var(--info)]/5 text-[var(--info)] border-[var(--accent)]/30';
      case 'LOW': return 'bg-[var(--info)]/5 text-[var(--info)] border-[var(--info)]/30';
      default: return 'bg-[var(--surface)] text-[var(--muted)] border-[var(--border)]';
    }
  };

  const getSeverityIcon = (severity) => {
    const size = 'w-4 h-4';
    switch (severity) {
      case 'CRITICAL': return <AlertTriangle className={`${size} text-[var(--danger)]`} strokeWidth={2.5} />;
      case 'HIGH': return <AlertCircle className={`${size} text-[var(--warning)]`} strokeWidth={2.5} />;
      case 'MEDIUM': return <Info className={`${size} text-[var(--accent)]`} strokeWidth={2.5} />;
      case 'LOW': return <Info className={`${size} text-[var(--info)]`} strokeWidth={2.5} />;
      default: return <Info className={`${size} text-[var(--muted)]`} strokeWidth={2.5} />;
    }
  };

  const policyStats = calculatePolicyStats();

  return {
    selectedCategory,
    setSelectedCategory,
    expandedCategories,
    toggleCategory,
    policies,
    handlePolicyToggle,
    handleBulkToggle,
    secretCategories,
    getCategoryCount,
    getSeverityColor,
    getSeverityIcon,
    policyStats,
    unsavedChangesCount,
    savePreferences,
    discardChanges,
  };
};
