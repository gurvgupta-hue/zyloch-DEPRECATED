import scanPoliciesData from "@/data/scanPoliciesData";

const toSafeString = (value) => String(value || "").trim();

const normalize = (value) =>
    toSafeString(value)
        .toLowerCase()
        .replace(/[\s_]+/g, "-");

const normalizeSeverity = (severity) => {
    const value = toSafeString(severity).toLowerCase();
    if (["critical", "high", "medium", "low"].includes(value)) {
        return value;
    }

    return "medium";
};

const buildAzureTerraformLookup = () => {
    const terraformPolicies = scanPoliciesData?.terraform || [];

    return terraformPolicies.reduce((acc, policy) => {
        const code = toSafeString(policy?.code);
        const name = toSafeString(policy?.name);
        const description = toSafeString(policy?.description);

        [code, normalize(code), name, normalize(name), description, normalize(description)]
            .filter(Boolean)
            .forEach((key) => {
                acc[key] = policy;
            });

        return acc;
    }, {});
};

const AZURE_TERRAFORM_POLICY_LOOKUP = buildAzureTerraformLookup();

export const resolveAzureTerraformPolicy = ({ code, policyName, description, severity } = {}) => {
    const lookupKeys = [
        toSafeString(code),
        normalize(code),
        toSafeString(policyName),
        normalize(policyName),
        toSafeString(description),
        normalize(description),
    ].filter(Boolean);

    for (const key of lookupKeys) {
        const match = AZURE_TERRAFORM_POLICY_LOOKUP[key];
        if (match) {
            return {
                code: match.code || toSafeString(code) || "TF_AZURE_UNKNOWN",
                title: match.name || toSafeString(policyName) || "terraform_azure_policy",
                description: match.description || toSafeString(description) || "No description provided",
                severity: normalizeSeverity(match.severity || severity),
            };
        }
    }

    return {
        code: toSafeString(code) || "TF_AZURE_UNKNOWN",
        title: toSafeString(policyName) || "terraform_azure_policy",
        description: toSafeString(description) || "No description provided",
        severity: normalizeSeverity(severity),
    };
};
