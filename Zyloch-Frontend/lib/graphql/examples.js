export const QUERY_EXAMPLES = [
  {
    name: 'Get All Scans',
    query: `query GetScans {
  scans(limit: 10) {
    scanId
    scanStatus
    createdAt
    metadata {
      organization
      repository
      branch
      commitHash
    }
    summary {
      issuesSummary {
        totalIssues
        critical
        high
        medium
        low
      }
      scoreSummary {
        overallScore
      }
    }
  }
}`,
    variables: {}
  },
  {
    name: 'Latest Scan with Findings',
    query: `query LatestScanFindings($org: String!, $repo: String!, $branch: String!) {
  latestScan(organization: $org, repository: $repo, branch: $branch) {
    scanId
    metadata {
      organization
      repository
      branch
      commitHash
    }
    summary {
      issuesSummary {
        totalIssues
        critical
        high
      }
    }
    dockerResults {
      findingsCount
      findings {
        severity
        description
        file
        line
      }
    }
  }
}`,
    variables: {
      org: "myorg",
      repo: "myrepo",
      branch: "main"
    }
  },
  {
    name: 'Critical Findings',
    query: `query CriticalFindings($org: String) {
  findings(organization: $org, severity: CRITICAL, limit: 50) {
    policy
    severity
    description
    file
    line
  }
}`,
    variables: {
      org: "myorg"
    }
  },
  {
    name: 'Organizations Overview',
    query: `query Organizations {
  organizations {
    name
    scanCount
    repositories
    latestScan {
      scanId
      summary {
        scoreSummary {
          overallScore
        }
      }
    }
  }
}`,
    variables: {}
  },
  {
    name: 'Repository Details',
    query: `query RepositoryDetails($org: String!, $name: String!) {
  repository(organization: $org, name: $name) {
    name
    organization
    scanCount
    branches
    latestScan {
      scanId
      summary {
        issuesSummary {
          totalIssues
          critical
          high
        }
        scoreSummary {
          overallScore
          docker
          kubernetes
          workflow
        }
      }
    }
  }
}`,
    variables: {
      org: "myorg",
      name: "myrepo"
    }
  },
  {
    name: 'Scan with All Scanner Results',
    query: `query ScanWithAllResults($scanId: String!) {
  scan(scanId: $scanId) {
    scanId
    dockerResults {
      findingsCount
      findings {
        severity
        description
      }
    }
    kubernetesResults {
      findingsCount
      findings {
        severity
        description
      }
    }
    workflowResults {
      findingsCount
      findings {
        severity
        description
      }
    }
  }
}`,
    variables: {
      scanId: "scan_id_here"
    }
  }
];
