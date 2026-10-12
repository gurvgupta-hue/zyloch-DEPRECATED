// components/dashboard/utils/dataProcessor.js
import scanPoliciesData from "@/data/scanPoliciesData";

const normalizePolicyKey = (value) =>
  String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, "-");

const getPolicyLookup = () => {
  const allPolicies = [
    ...(scanPoliciesData?.docker || []),
    ...(scanPoliciesData?.kubernetes || []),
    ...(scanPoliciesData?.terraform || []),
    ...(scanPoliciesData?.workflow || []),
    ...(scanPoliciesData?.bicep || []),
    ...(scanPoliciesData?.ansible || []),
    ...(scanPoliciesData?.cloudformation || []),
  ];

  return allPolicies.reduce((acc, policy) => {
    const keys = [
      policy?.code,
      policy?.checkerKey,
      policy?.mappedIdentifier,
    ].filter(Boolean);

    keys.forEach((key) => {
      acc[key] = policy;
      acc[normalizePolicyKey(key)] = policy;
    });

    return acc;
  }, {});
};

const POLICY_LOOKUP = getPolicyLookup();

// Dockerfiles are almost always literally named "Dockerfile" (no per-service
// suffix), so a repo with multiple Dockerfiles (e.g. backend/Dockerfile,
// frontend/Dockerfile) would otherwise show an indistinguishable
// "Dockerfile" for every row in the findings table. Prefix with the
// immediate parent folder in that case so each row stays identifiable;
// leave any other file name (e.g. Dockerfile.dev, docker-compose.yml) as-is.
const getDockerDisplayFileName = (fullPath, fallback) => {
  if (!fullPath) return fallback;

  const normalized = String(fullPath).replace(/\\/g, "/");
  const parts = normalized.split("/").filter(Boolean);
  const baseName = parts[parts.length - 1] || fallback;

  if (baseName.toLowerCase() === "dockerfile" && parts.length > 1) {
    const parentFolder = parts[parts.length - 2];
    return `${parentFolder}/${baseName}`;
  }

  return baseName || fallback;
};

const getMappedPolicy = (policy = {}) => {
  const lookupKeys = [
    policy?.policy_code,
    policy?.policy_name,
    policy?.checker_key,
    policy?.checkerKey,
    policy?.mapped_identifier,
  ].filter(Boolean);

  for (const key of lookupKeys) {
    if (POLICY_LOOKUP[key]) {
      return POLICY_LOOKUP[key];
    }

    const normalized = normalizePolicyKey(key);
    if (POLICY_LOOKUP[normalized]) {
      return POLICY_LOOKUP[normalized];
    }
  }

  return null;
};

export const processScanData = (latestScan) => {
  if (!latestScan) return null;

  const scanResults = latestScan.scan_results;
  const summary = scanResults?.scan_results?.summary;
  const findings = scanResults?.scans_findings || {};
  const scannerResults = scanResults?.scan_results?.scanner_results || {};

  // Process Docker findings
  const dockerFindings = (findings["Docker-findings"] || []).flatMap(fileFindings => {
    return (fileFindings.violated_policies || []).map(policy => {
      const mappedPolicy = getMappedPolicy(policy);

      return {
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: mappedPolicy?.mappedIdentifier || mappedPolicy?.code || policy.policy_code || "DOCKER-UNKNOWN",
        policyName: mappedPolicy?.checkerKey || policy.policy_name || "docker_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "docker",
        provider: "docker",
        category: mappedPolicy?.category || "Uncategorized",
        title: mappedPolicy?.name || policy.policy_name || policy.description || "Docker security issue",
        description: mappedPolicy?.description || policy.description || "No description provided",
        summary: mappedPolicy?.summary,
        whyFlagged: mappedPolicy?.whyFlagged,
        riskImpact: mappedPolicy?.riskImpact,
        remediationGuidance: mappedPolicy?.remediationGuidance,
        references: mappedPolicy?.references,
        examples: mappedPolicy?.examples,
        checkerKey: mappedPolicy?.checkerKey,
        mappedIdentifier: mappedPolicy?.mappedIdentifier,
        file: getDockerDisplayFileName(fileFindings.file_name, "Dockerfile"),
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        codeBlock: policy.code_block || null,
        remediation: policy.remediation,
      };
    });
  });

  // Process Kubernetes findings
  const kubernetesFindings = (findings["Kubernetes-findings"] || []).flatMap(fileFindings =>
    (fileFindings.violated_policies || []).map(policy => {
      const mappedPolicy = getMappedPolicy(policy);

      return {
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: mappedPolicy?.mappedIdentifier || mappedPolicy?.code || policy.policy_code || "K8S-UNKNOWN",
        policyName: mappedPolicy?.checkerKey || policy.policy_name || "kubernetes_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "kubernetes",
        provider: "kubernetes",
        category: mappedPolicy?.category || "Uncategorized",
        title: mappedPolicy?.name || policy.policy_name || policy.description || "Kubernetes security issue",
        description: mappedPolicy?.description || policy.description || "No description provided",
        summary: mappedPolicy?.summary,
        whyFlagged: mappedPolicy?.whyFlagged,
        riskImpact: mappedPolicy?.riskImpact,
        remediationGuidance: mappedPolicy?.remediationGuidance,
        references: mappedPolicy?.references,
        examples: mappedPolicy?.examples,
        checkerKey: mappedPolicy?.checkerKey,
        mappedIdentifier: mappedPolicy?.mappedIdentifier,
        file: fileFindings.file_name.split("/").pop() || "manifest.yaml",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        codeBlock: policy.code_block || null,
        remediation: policy.remediation,
      };
    })
  );

  // Process Terraform findings
  const terraformAwsFindings = (findings["Terraform_Aws-findings"] || []).flatMap(fileFindings =>
    (fileFindings.violated_policies || []).map(policy => {
      const mappedPolicy = getMappedPolicy(policy);

      return {
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: mappedPolicy?.mappedIdentifier || mappedPolicy?.code || policy.policy_code || "TF-AWS-UNKNOWN",
        policyName: mappedPolicy?.checkerKey || policy.policy_name || "terraform_aws_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "terraform",
        provider: "aws",
        category: mappedPolicy?.category || "Uncategorized",
        title: mappedPolicy?.name || policy.policy_name || policy.description || "Terraform AWS security issue",
        description: mappedPolicy?.description || policy.description || "No description provided",
        summary: mappedPolicy?.summary,
        whyFlagged: mappedPolicy?.whyFlagged,
        riskImpact: mappedPolicy?.riskImpact,
        remediationGuidance: mappedPolicy?.remediationGuidance,
        references: mappedPolicy?.references,
        examples: mappedPolicy?.examples,
        checkerKey: mappedPolicy?.checkerKey,
        mappedIdentifier: mappedPolicy?.mappedIdentifier,
        file: fileFindings.file_name.split("/").pop() || "main.tf",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        codeBlock: policy.code_block || null,
        remediation: policy.remediation,
      };
    })
  );

  const terraformAzureFindings = (findings["Terraform_Azure-findings"] || []).flatMap(fileFindings =>
    (fileFindings.violated_policies || []).map(policy => {
      const mappedPolicy = getMappedPolicy(policy);

      return {
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: mappedPolicy?.mappedIdentifier || mappedPolicy?.code || policy.policy_code || "TF-AZURE-UNKNOWN",
        policyName: mappedPolicy?.checkerKey || policy.policy_name || "terraform_azure_policy",
        severity: (mappedPolicy?.severity || policy.severity || "medium").toLowerCase(),
        type: "terraform",
        provider: "azure",
        category: mappedPolicy?.category || "Uncategorized",
        title: mappedPolicy?.name || policy.policy_name || policy.description || "Terraform Azure security issue",
        description: mappedPolicy?.description || policy.description || "No description provided",
        summary: mappedPolicy?.summary,
        whyFlagged: mappedPolicy?.whyFlagged,
        riskImpact: mappedPolicy?.riskImpact,
        remediationGuidance: mappedPolicy?.remediationGuidance,
        references: mappedPolicy?.references,
        examples: mappedPolicy?.examples,
        checkerKey: mappedPolicy?.checkerKey,
        mappedIdentifier: mappedPolicy?.mappedIdentifier,
        file: fileFindings.file_name.split("/").pop() || "main.tf",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        codeBlock: policy.code_block || null,
        remediation: policy.remediation,
      };
    })
  );

  const terraformGcpFindings = (findings["Terraform_Gcp-findings"] || []).flatMap(fileFindings =>
    (fileFindings.violated_policies || []).map(policy => {
      const mappedPolicy = getMappedPolicy(policy);

      return {
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: mappedPolicy?.mappedIdentifier || mappedPolicy?.code || policy.policy_code || "TF-GCP-UNKNOWN",
        policyName: mappedPolicy?.checkerKey || policy.policy_name || "terraform_gcp_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "terraform",
        provider: "gcp",
        category: mappedPolicy?.category || "Uncategorized",
        title: mappedPolicy?.name || policy.policy_name || policy.description || "Terraform GCP security issue",
        description: mappedPolicy?.description || policy.description || "No description provided",
        summary: mappedPolicy?.summary,
        whyFlagged: mappedPolicy?.whyFlagged,
        riskImpact: mappedPolicy?.riskImpact,
        remediationGuidance: mappedPolicy?.remediationGuidance,
        references: mappedPolicy?.references,
        examples: mappedPolicy?.examples,
        checkerKey: mappedPolicy?.checkerKey,
        mappedIdentifier: mappedPolicy?.mappedIdentifier,
        file: fileFindings.file_name.split("/").pop() || "main.tf",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        codeBlock: policy.code_block || null,
        remediation: policy.remediation,
      };
    })
  );

  const terraformFindings = [
    ...terraformAwsFindings,
    ...terraformAzureFindings,
    ...terraformGcpFindings
  ];

  // Process Bicep and ARM findings (both come through the "Bicep-findings" key;
  // native .bicep files and ARM template .json files are distinguished by extension)
  const bicepFindings = [];
  const armFindings = [];

  (findings["Bicep-findings"] || []).forEach(fileFindings => {
    const isArm = fileFindings.file_name.endsWith(".json");
    (fileFindings.violated_policies || []).forEach(policy => {
      const mappedPolicy = getMappedPolicy(policy);
      const finding = {
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: mappedPolicy?.mappedIdentifier || mappedPolicy?.code || policy.policy_code || (isArm ? "ARM-UNKNOWN" : "BICEP-UNKNOWN"),
        policyName: mappedPolicy?.checkerKey || policy.policy_name || "psrule_azure",
        severity: (mappedPolicy?.severity || policy.severity || "medium").toLowerCase(),
        type: isArm ? "arm" : "bicep",
        provider: "azure",
        category: mappedPolicy?.category || "Azure",
        title: mappedPolicy?.name || policy.policy_name || policy.description || (isArm ? "ARM template security issue" : "Bicep Azure security issue"),
        description: mappedPolicy?.description || policy.description || "No description provided",
        summary: mappedPolicy?.summary,
        whyFlagged: mappedPolicy?.whyFlagged,
        riskImpact: mappedPolicy?.riskImpact,
        remediationGuidance: mappedPolicy?.remediationGuidance,
        references: mappedPolicy?.references,
        examples: mappedPolicy?.examples,
        checkerKey: mappedPolicy?.checkerKey || policy.policy_name,
        mappedIdentifier: mappedPolicy?.code,
        file: fileFindings.file_name.split("/").pop() || (isArm ? "template.json" : "main.bicep"),
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        codeBlock: policy.code_block || null,
        remediation: policy.remediation,
      };
      if (isArm) armFindings.push(finding);
      else bicepFindings.push(finding);
    });
  });

  // Process Ansible findings
  const ansibleFindings = (findings["Ansible-findings"] || []).flatMap(fileFindings =>
    (fileFindings.violated_policies || []).map(policy => {
      const mappedPolicy = getMappedPolicy(policy);

      return {
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: mappedPolicy?.code || policy.policy_code || "ANSIBLE-UNKNOWN",
        policyName: policy.policy_name || "ansible_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "ansible",
        provider: "ansible",
        category: mappedPolicy?.category || "Ansible Security",
        title: mappedPolicy?.name || policy.policy_name || policy.description || "Ansible security issue",
        description: mappedPolicy?.description || policy.description || "No description provided",
        summary: mappedPolicy?.summary,
        whyFlagged: mappedPolicy?.whyFlagged,
        riskImpact: mappedPolicy?.riskImpact,
        remediationGuidance: mappedPolicy?.remediationGuidance,
        references: mappedPolicy?.references,
        examples: mappedPolicy?.examples,
        checkerKey: mappedPolicy?.checkerKey,
        mappedIdentifier: mappedPolicy?.mappedIdentifier,
        file: fileFindings.file_name.split("/").pop() || "playbook.yml",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        codeBlock: policy.code_block || null,
        remediation: policy.remediation,
      };
    })
  );

  // Process CloudFormation findings
  const cloudformationFindings = (findings["Cloudformation-findings"] || []).flatMap(fileFindings =>
    (fileFindings.violated_policies || []).map(policy => {
      const mappedPolicy = getMappedPolicy(policy);

      return {
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: mappedPolicy?.code || policy.policy_code || "CFN-UNKNOWN",
        policyName: policy.policy_name || "cloudformation_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "cloudformation",
        provider: "aws",
        category: mappedPolicy?.category || "CloudFormation Security",
        title: mappedPolicy?.name || policy.policy_name || policy.description || "CloudFormation security issue",
        description: mappedPolicy?.description || policy.description || "No description provided",
        summary: mappedPolicy?.summary,
        whyFlagged: mappedPolicy?.whyFlagged,
        riskImpact: mappedPolicy?.riskImpact,
        remediationGuidance: mappedPolicy?.remediationGuidance,
        references: mappedPolicy?.references,
        examples: mappedPolicy?.examples,
        checkerKey: mappedPolicy?.checkerKey,
        mappedIdentifier: mappedPolicy?.mappedIdentifier,
        file: fileFindings.file_name.split("/").pop() || "template.yaml",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        codeBlock: policy.code_block || null,
        remediation: policy.remediation,
      };
    })
  );

  const allFindings = [
    ...dockerFindings,
    ...kubernetesFindings,
    ...terraformFindings,
    ...bicepFindings,
    ...armFindings,
    ...ansibleFindings,
    ...cloudformationFindings,
  ];

  // Calculate IaC-specific summary
  const iacSummary = {
    totalIssues: allFindings.length,
    totalFiles: new Set(allFindings.map(f => f.fullPath)).size,
    bySeverity: {
      critical: allFindings.filter(f => f.severity === "critical").length,
      high: allFindings.filter(f => f.severity === "high").length,
      medium: allFindings.filter(f => f.severity === "medium").length,
      low: allFindings.filter(f => f.severity === "low").length,
    },
    byType: {
      docker: {
        issues: dockerFindings.length,
        files: new Set(dockerFindings.map(f => f.fullPath)).size,
        filesScanned: scannerResults?.docker?.files_scanned || 0,
      },
      kubernetes: {
        issues: kubernetesFindings.length,
        files: new Set(kubernetesFindings.map(f => f.fullPath)).size,
        filesScanned: scannerResults?.kubernetes?.files_scanned || 0,
      },
      terraform: {
        issues: terraformFindings.length,
        files: new Set(terraformFindings.map(f => f.fullPath)).size,
        filesScanned: (scannerResults?.terraform_aws?.files_scanned || 0) +
          (scannerResults?.terraform_azure?.files_scanned || 0) +
          (scannerResults?.terraform_gcp?.files_scanned || 0),
        providers: {
          aws: terraformAwsFindings.length,
          azure: terraformAzureFindings.length,
          gcp: terraformGcpFindings.length,
        }
      },
      bicep: {
        issues: bicepFindings.length,
        files: new Set(bicepFindings.map(f => f.fullPath)).size,
        filesScanned: scannerResults?.bicep?.files_scanned || 0,
      },
      arm: {
        issues: armFindings.length,
        files: new Set(armFindings.map(f => f.fullPath)).size,
        filesScanned: scannerResults?.bicep?.total_arm_files || new Set(armFindings.map(f => f.fullPath)).size,
      },
      ansible: {
        issues: ansibleFindings.length,
        files: new Set(ansibleFindings.map(f => f.fullPath)).size,
        filesScanned: scannerResults?.ansible?.files_scanned || 0,
      },
      cloudformation: {
        issues: cloudformationFindings.length,
        files: new Set(cloudformationFindings.map(f => f.fullPath)).size,
        filesScanned: scannerResults?.cloudformation?.files_scanned || 0,
      },
    },
  };

  // Prepare chart data
  const severityData = [
    { name: "Critical", value: iacSummary.bySeverity.critical, color: "var(--critical)" },
    { name: "High", value: iacSummary.bySeverity.high, color: "var(--high)" },
    { name: "Medium", value: iacSummary.bySeverity.medium, color: "var(--medium)" },
    { name: "Low", value: iacSummary.bySeverity.low, color: "var(--low)" },
  ].filter(item => item.value > 0);

  const issuesByTypeData = [
    {
      name: "Docker",
      issues: iacSummary.byType.docker.issues,
      files: iacSummary.byType.docker.files,
      filesScanned: iacSummary.byType.docker.filesScanned,
      color: "var(--chart-cyan)",
    },
    {
      name: "Kubernetes",
      issues: iacSummary.byType.kubernetes.issues,
      files: iacSummary.byType.kubernetes.files,
      filesScanned: iacSummary.byType.kubernetes.filesScanned,
      color: "var(--chart-low)",
    },
    {
      name: "Terraform",
      issues: iacSummary.byType.terraform.issues,
      files: iacSummary.byType.terraform.files,
      filesScanned: iacSummary.byType.terraform.filesScanned,
      color: "var(--chart-medium)",
    },
    {
      name: "Bicep",
      issues: iacSummary.byType.bicep.issues,
      files: iacSummary.byType.bicep.files,
      filesScanned: iacSummary.byType.bicep.filesScanned,
      color: "var(--chart-blue)",
    },
    {
      name: "ARM",
      issues: iacSummary.byType.arm.issues,
      files: iacSummary.byType.arm.files,
      filesScanned: iacSummary.byType.arm.filesScanned,
      color: "var(--chart-purple)",
    },
    {
      name: "Ansible",
      issues: iacSummary.byType.ansible.issues,
      files: iacSummary.byType.ansible.files,
      filesScanned: iacSummary.byType.ansible.filesScanned,
      color: "#EE0000",
    },
    {
      name: "CloudFormation",
      issues: iacSummary.byType.cloudformation.issues,
      files: iacSummary.byType.cloudformation.files,
      filesScanned: iacSummary.byType.cloudformation.filesScanned,
      color: "#FF9900",
    },
  ].filter(item => item.issues > 0);

  return {
    ...latestScan,
    iacFindings: allFindings,
    dockerFindings,
    kubernetesFindings,
    terraformFindings,
    terraformAwsFindings,
    terraformAzureFindings,
    terraformGcpFindings,
    bicepFindings,
    armFindings,
    ansibleFindings,
    cloudformationFindings,
    iacSummary,
    severityData,
    issuesByTypeData,
    summary,
    scannerResults,
    scanMetadata: latestScan.scan_metadata,
  };
};