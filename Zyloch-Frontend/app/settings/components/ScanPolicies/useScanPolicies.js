// ScanPolicies/useScanPolicies.js
import { useState, useEffect } from 'react';
import scanPoliciesData from '@/data/scanPoliciesData';
import {
  AlertTriangle,
  AlertCircle,
  Info
} from 'lucide-react';
import TechIcon from "@/components/common/TechIcon.js";
import {
  getPolicyConfigurations,
  updatePolicyConfigurations,
} from '@/lib/api/organization';

const cloneState = (value) => {
  if (typeof globalThis.structuredClone === 'function') {
    return globalThis.structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value));
};

// `orgName` is no longer used to address the API — the tenant comes from the
// session — but the prop is kept so callers do not need changing (MT-08).
export const useScanPolicies = ({ orgName } = {}) => {
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [selectedSubCategory, setSelectedSubCategory] = useState(null);
  const [expandedCategories, setExpandedCategories] = useState(['workflow', 'iac', 'secrets']);

  // Function to generate unique IDs for policies with duplicate codes
  const generateUniqueId = (item, index, prefix) => {
    if (item.code === 'AZ-TF-CVE-036') {
      return `${item.code}-${item.name.replace(/\s+/g, '-').toLowerCase()}`;
    }
    return item.code || `${prefix}-${index}`;
  };

  const [policies, setPolicies] = useState(() => ({
    workflow: scanPoliciesData.workflow.map((item, index) => ({
      id: generateUniqueId(item, index, 'workflow'),
      name: item.name,
      description: item.description,
      enabled: true,
      severity: item.severity.toUpperCase()
    })),
    kubernetes: scanPoliciesData.kubernetes.map((item, index) => ({
      id: generateUniqueId(item, index, 'k8s'),
      name: item.name,
      description: item.description,
      enabled: true,
      severity: item.severity.toUpperCase()
    })),
    docker: scanPoliciesData.docker.map((item, index) => ({
      id: generateUniqueId(item, index, 'docker'),
      name: item.name,
      description: item.description,
      enabled: true,
      severity: item.severity?.toUpperCase() || 'MEDIUM'
    })),
    terraform: scanPoliciesData.terraform.map((item, index) => ({
      id: generateUniqueId(item, index, 'tf'),
      name: item.name,
      description: item.description,
      enabled: true,
      severity: item.severity.toUpperCase()
    })),
    azure: scanPoliciesData.terraform
      .filter(item => item.code.startsWith('AZ-SEC-'))
      .map((item, index) => ({
        id: generateUniqueId(item, index, 'azure'),
        name: item.name,
        description: item.description,
        enabled: true,
        severity: item.severity.toUpperCase()
      })),
    gcp: scanPoliciesData.terraform
      .filter(item => item.code.startsWith('GCP-SEC-'))
      .map((item, index) => ({
        id: generateUniqueId(item, index, 'gcp'),
        name: item.name,
        description: item.description,
        enabled: true,
        severity: item.severity.toUpperCase()
      })),
    aws: scanPoliciesData.terraform
      .filter(item => item.code.startsWith('AWS-SEC-'))
      .map((item, index) => ({
        id: generateUniqueId(item, index, 'aws'),
        name: item.name,
        description: item.description,
        enabled: true,
        severity: item.severity.toUpperCase()
      })),
    bicep: (scanPoliciesData.bicep || []).map((item, index) => ({
      id: generateUniqueId(item, index, 'bicep'),
      name: item.name,
      description: item.description,
      enabled: true,
      severity: item.severity?.toUpperCase() || 'MEDIUM'
    })),
    cloudformation: scanPoliciesData.terraform
      .filter(item => item.code.startsWith('AWS-SEC-CFN-') || item.code.startsWith('CFN-SEC-'))
      .map((item, index) => ({
        id: generateUniqueId(item, index, 'cfn'),
        name: item.name,
        description: item.description,
        enabled: true,
        severity: item.severity.toUpperCase()
      })),
    ansible: (scanPoliciesData.ansible || []).map((item, index) => ({
      id: generateUniqueId(item, index, 'ansible'),
      name: item.name,
      description: item.description,
      enabled: true,
      severity: item.severity?.toUpperCase() || 'MEDIUM'
    })),
    cloudformation: (scanPoliciesData.cloudformation || []).map((item, index) => ({
      id: generateUniqueId(item, index, 'cfn'),
      name: item.name,
      description: item.description,
      enabled: true,
      severity: item.severity?.toUpperCase() || 'MEDIUM'
    })),
}));

  const [savedPolicies, setSavedPolicies] = useState(policies);

  // Maps UI subcategory → GHAPP backend scanner key.
  // "terraform" is intentionally excluded — aws/azure/gcp are the real scanners.
  const SUBCATEGORY_TO_SCANNER = {
    workflow:    'workflow',
    kubernetes:  'kubernetes',
    docker:      'docker',
    aws:         'terraform_aws',
    azure:       'terraform_azure',
    gcp:         'terraform_gcp',
    bicep:       'bicep',
    ansible:     'ansible',
    cloudformation: 'cloudformation',
  };

  // Load persisted config through the tenant-scoped backend (MT-08).
  useEffect(() => {
    const load = async () => {
      try {
        const scannersCfg = await getPolicyConfigurations();
        if (!Object.keys(scannersCfg).length) return;
        setPolicies(prev => {
          const updated = { ...prev };
          for (const [subCat, scannerKey] of Object.entries(SUBCATEGORY_TO_SCANNER)) {
            const scannerConfig = scannersCfg[scannerKey] || {};
            const scannerEnabled = scannerConfig.enabled !== false;
            const policyOverrides = scannerConfig.policies || {};
            if (updated[subCat]) {
              updated[subCat] = updated[subCat].map(p => {
                const override = policyOverrides[p.id];
                return {
                  ...p,
                  enabled: scannerEnabled && override !== false && override?.enabled !== false,
                  ...(override?.severity ? { severity: override.severity } : {}),
                };
              });
            }
          }
          setSavedPolicies(updated);
          return updated;
        });
      } catch (e) {
        console.error('Error loading IaC policy config:', e);
      }
    };
    load();
  }, []);

  const saveToApi = async (updatedPolicies) => {
    const scanners = {};
    for (const [subCat, scannerKey] of Object.entries(SUBCATEGORY_TO_SCANNER)) {
      const policyList = updatedPolicies[subCat] || [];
      const policiesPayload = {};
      for (const p of policyList) {
        const entry = {};
        if (!p.enabled) entry.enabled = false;
        if (p.severity) entry.severity = p.severity;
        if (Object.keys(entry).length > 0) policiesPayload[p.id] = entry;
      }
      // When every policy in the subcategory is disabled, mark the scanner as
      // disabled entirely so the backend can short-circuit filtering without
      // relying on exact policy-code matches.
      const allDisabled = policyList.length > 0 && policyList.every(p => !p.enabled);
      scanners[scannerKey] = { enabled: !allDisabled, policies: policiesPayload };
    }
    // Errors surface as a toast: a silently swallowed save left the UI showing
    // toggles that were never persisted (MT-08.4).
    await updatePolicyConfigurations(scanners);
  };

  const scanCategories = [
    {
      id: 'workflow',
      name: 'Workflow',
      icon: <TechIcon name="workflow" size={16} className="text-current" />,
      description: 'CI/CD workflow security',
      subCategories: [
        {
          id: 'workflow',
          name: 'Workflow',
          icon: <TechIcon name="workflow" size={14} className="text-current" />
        }
      ]
    },
    {
      id: 'iac',
      name: 'Infrastructure as Code',
      icon: <TechIcon name="iac" size={16} className="text-current" />,
      description: 'Infrastructure as Code',
      subCategories: [
        { id: 'kubernetes', name: 'Kubernetes', icon: <TechIcon name="kubernetes" size={14} color="#326CE5" /> },
        { id: 'docker', name: 'Docker', icon: <TechIcon name="docker" size={14} color="#2496ED" /> },
        {
          id: 'terraform',
          name: 'Terraform',
          icon: <TechIcon name="terraform" size={14} color="#7B42F6" />,
          subCategories: [
            { id: 'aws', name: 'AWS', icon: <TechIcon name="aws" size={14} color="#FF9900" /> },
            { id: 'azure', name: 'Azure', icon: <TechIcon name="azure" size={14} color="#0078D4" /> },
            { id: 'gcp', name: 'GCP', icon: <TechIcon name="gcp" size={14} color="#4285F4" /> },
          ]
        },
        {
          id: 'cloud',
          name: 'Cloud',
          icon: <TechIcon name="cloud" size={14} className="text-current" />,
          subCategories: [
            {
              id: 'cloud-aws',
              name: 'AWS',
              icon: <TechIcon name="aws" size={14} color="#FF9900" />,
              subCategories: [
                { id: 'cloudformation', name: 'CloudFormation', icon: <TechIcon name="aws" size={14} color="#FF9900" /> }
              ]
            },
            {
              id: 'cloud-azure',
              name: 'Azure',
              icon: <TechIcon name="azure" size={14} color="#0078D4" />,
              subCategories: [
                { id: 'bicep', name: 'Bicep', icon: <TechIcon name="bicep" size={14} color="#0078D4" /> }
              ]
            }
          ]
        },
        { id: 'ansible', name: 'Ansible', icon: <TechIcon name="ansible" size={14} color="#EE0000" /> },
      ]
    },
    {
      id: 'secrets',
      name: 'Secrets',
      icon: <TechIcon name="secrets" size={16} className="text-current" />,
      description: 'DLP, keys/tokens, and generic secrets',
      subCategories: [
        { id: 'dlp-pii', name: 'PII', icon: <TechIcon name="key" size={14} className="text-current" /> },
        { id: 'dlp-pci', name: 'PCI', icon: <TechIcon name="key" size={14} className="text-current" /> },
        { id: 'dlp-phi', name: 'PHI', icon: <TechIcon name="key" size={14} className="text-current" /> },
        { id: 'api-keys', name: 'Keys & Tokens: API Keys', icon: <TechIcon name="key" size={14} className="text-current" /> },
        { id: 'access-tokens', name: 'Keys & Tokens: Access Tokens', icon: <TechIcon name="key" size={14} className="text-current" /> },
        { id: 'credentials', name: 'Keys & Tokens: Credentials', icon: <TechIcon name="key" size={14} className="text-current" /> },
        { id: 'generic-secrets', name: 'Generic Secrets', icon: <TechIcon name="key" size={14} className="text-current" /> },
      ]
    }
  ];

  const countNodePolicies = (node) => {
    if (node.subCategories && node.subCategories.length > 0) {
      return node.subCategories.reduce((s, c) => s + countNodePolicies(c), 0);
    }
    return policies[node.id]?.length || 0;
  };

  const getCategoryCount = (category) =>
    (category.subCategories || []).reduce((sum, subCat) => sum + countNodePolicies(subCat), 0);

  const navGroups = [
    { id: 'pipeline', label: 'Workflow', categories: ['workflow'] },
    { id: 'infra', label: 'Infrastructure', categories: ['iac'] },
    { id: 'data', label: 'Data Protection', categories: ['secrets'] },
  ];

  const handlePolicyToggle = (policyId, subCategory) => {
    setPolicies(prev => ({
      ...prev,
      [subCategory]: (prev[subCategory] || []).map(policy =>
        policy.id === policyId ? { ...policy, enabled: !policy.enabled } : policy
      ),
    }));
  };

  const handleSeverityChange = (policyId, subCategory, severity) => {
    setPolicies(prev => ({
      ...prev,
      [subCategory]: prev[subCategory].map(policy =>
        policy.id === policyId && policy.severity ? { ...policy, severity } : policy
      )
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

        const currentSeverity = (policy.severity || '').toUpperCase();
        const savedSeverity = (savedPolicy.severity || '').toUpperCase();
        if (policy.enabled !== savedPolicy.enabled || currentSeverity !== savedSeverity) {
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

  const getSeverityColor = (severity) => {
    if (!severity) return '';
    switch (severity) {
      case 'CRITICAL': return 'bg-[var(--danger)]/5 text-[var(--danger)] border-[var(--danger)]/30';
      case 'HIGH': return 'bg-[var(--warning)]/5 text-[var(--warning)] border-[var(--warning)]/30';
      case 'MEDIUM': return 'bg-[var(--info)]/5 text-[var(--info)] border-[var(--accent)]/30';
      case 'LOW': return 'bg-[var(--info)]/5 text-[var(--info)] border-[var(--info)]/30';
      default: return 'bg-[var(--surface)] text-[var(--muted)] border-[var(--border)]';
    }
  };

  const getSeverityIcon = (severity) => {
    if (!severity) return null;
    const size = "w-4 h-4";
    switch (severity) {
      case 'CRITICAL': return <AlertTriangle className={`${size} text-[var(--danger)]`} strokeWidth={2.5} />;
      case 'HIGH': return <AlertCircle className={`${size} text-[var(--warning)]`} strokeWidth={2.5} />;
      case 'MEDIUM': return <Info className={`${size} text-[var(--accent)]`} strokeWidth={2.5} />;
      case 'LOW': return <Info className={`${size} text-[var(--info)]`} strokeWidth={2.5} />;
      default: return <Info className={`${size} text-[var(--muted)]`} strokeWidth={2.5} />;
    }
  };

  const calculatePolicyStats = () => {
    let totalPolicies = 0;
    let enabledPolicies = 0;
    let disabledPolicies = 0;

    // Exclude 'terraform' — its items are already counted in 'aws', 'azure', 'gcp' subcategories
    const EXCLUDE_KEYS = new Set(['terraform']);

    Object.entries(policies).forEach(([key, policyList]) => {
      if (EXCLUDE_KEYS.has(key)) return;
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

  const policyStats = calculatePolicyStats();

  return {
    selectedCategory,
    setSelectedCategory,
    selectedSubCategory,
    setSelectedSubCategory,
    expandedCategories,
    toggleCategory,
    policies,
    handlePolicyToggle,
    handleSeverityChange,
    handleBulkToggle,
    getSeverityColor,
    getSeverityIcon,
    scanCategories,
    navGroups,
    policyStats,
    getCategoryCount,
    unsavedChangesCount,
    savePreferences,
    discardChanges
  };
};