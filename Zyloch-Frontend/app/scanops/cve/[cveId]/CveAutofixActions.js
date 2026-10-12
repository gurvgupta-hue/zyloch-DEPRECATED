"use client";

import { useState } from "react";
import { GitPullRequest, LoaderCircle, Sparkles, X } from "lucide-react";
import { requestAutofix, createAutofixPr } from "@/lib/api/scans";
import { useNavbar } from "@/hooks/useNavbar";
import { useScanStore } from "@/store/useScanStore";
import styles from "./CveDetailPage.module.css";

// Turns the LLM's markdown-flavoured reply into plain readable paragraphs
// (headings, list markers, emphasis markers and code fences are stripped
// rather than rendered) so the sidebar reads like text, not a code block.
function formatAutofixText(content) {
    const stripInline = (line) =>
        line
            .replace(/`{1,3}/g, "")
            .replace(/\*\*(.*?)\*\*/g, "$1")
            .replace(/__(.*?)__/g, "$1")
            .replace(/\*(.*?)\*/g, "$1")
            .replace(/^#{1,6}\s+/, "")
            .replace(/^\s*[-*+]\s+/, "- ")
            .replace(/^\s*\d+[.)]\s+/, (match) => match.trim() + " ");

    return String(content || "")
        .replace(/\r\n/g, "\n")
        .split("\n")
        .filter((line) => !/^```/.test(line.trim()))
        .map(stripInline)
        .join("\n")
        .replace(/\n{3,}/g, "\n\n")
        .trim();
}

function getSourceContext(report) {
    if (report.codeBlock) return report.codeBlock;
    const packageName = report.packageName;
    const version = report.packageVersion;
    if (!packageName || !version || version.toLowerCase() === "unknown") return "";

    if (report.file.toLowerCase().endsWith("package.json")) {
        return `"${packageName}": "${version}"`;
    }
    if (report.file.toLowerCase().endsWith("requirements.txt")) {
        return `${packageName}==${version}`;
    }
    if (report.file.toLowerCase().endsWith("go.mod")) {
        return `${packageName} ${version}`;
    }
    return "";
}

export default function CveAutofixActions({ report }) {
    const { selectedInstallation, selectedRepo, selectedBranch } = useNavbar();
    const latestScan = useScanStore((state) => state.latestScan);
    const [state, setState] = useState({ status: "idle", content: "", error: "", url: "" });
    const [sidebarOpen, setSidebarOpen] = useState(false);

    const installationId = selectedInstallation?.installationId || latestScan?.installation_id;
    const repository = selectedRepo?.full_name || latestScan?.scan_metadata?.repository_url?.replace(/^.*github\.com\//, "");
    const branch = selectedBranch?.name || latestScan?.scan_metadata?.branch || "main";
    const sourceContext = getSourceContext(report);
    const canGenerate = Boolean(installationId && report.file && sourceContext);
    const canCreatePr = Boolean(state.content && installationId && repository && report.file && sourceContext);

    const handleGenerate = async () => {
        if (!canGenerate || state.status === "loading") return;
        setState({ status: "loading", content: "", error: "", url: "" });
        try {
            const response = await requestAutofix(
                {
                    type: "sbom",
                    policyCode: report.cveId,
                    policyName: `${report.packageName} dependency vulnerability`,
                    description: report.description,
                    severity: report.ossRisk,
                    file: report.file,
                    codeBlock: sourceContext,
                    sbomContext: {
                        package: report.packageName,
                        version: report.packageVersion,
                        ecosystem: report.ecosystem,
                        cve: report.cveId,
                        cvss: report.cvssScore,
                        epss: report.epssScore,
                        kev: report.kev,
                        reachability: report.reachability,
                        affected: report.affected,
                        patched: report.patched,
                    },
                },
                { installationId }
            );
            setState({ status: "success", content: response.content || "", error: "", url: "" });
            setSidebarOpen(true);
        } catch (error) {
            setState({ status: "error", content: "", error: error.message || "Unable to generate autofix", url: "" });
        }
    };

    const handleCreatePr = async () => {
        if (!canCreatePr || state.status === "pr-loading") return;
        setState((current) => ({ ...current, status: "pr-loading", error: "" }));
        try {
            const response = await createAutofixPr(
                { file: report.file, codeBlock: sourceContext },
                state.content,
                { installationId, repository, branch }
            );
            setState((current) => ({ ...current, status: "pr-success", url: response.pr_url || "", error: "" }));
        } catch (error) {
            setState((current) => ({ ...current, status: "error", error: error.message || "Unable to create pull request" }));
        }
    };

    return (
        <div className={styles.autofixActions}>
            {state.content ? (
                <button type="button" className={styles.prBtn} onClick={() => setSidebarOpen(true)}>
                    <span className={styles.prBtnLeft}>
                        <Sparkles size={14} />
                        <span>View Autofix Proposal</span>
                    </span>
                </button>
            ) : (
                <button type="button" className={styles.prBtn} onClick={handleGenerate} disabled={!canGenerate || state.status === "loading"} title={!canGenerate ? "A supported source file and installation are required" : "Generate SBOM autofix"}>
                    <span className={styles.prBtnLeft}>
                        {state.status === "loading" ? <LoaderCircle size={14} className="animate-spin" /> : <Sparkles size={14} />}
                        <span>{state.status === "loading" ? "Generating Autofix" : "Generate Autofix"}</span>
                    </span>
                </button>
            )}
            {state.error ? <p className={styles.autofixError}>{state.error}</p> : null}

            <div
                className={`${styles.autofixOverlay} ${sidebarOpen ? styles.autofixOverlayOpen : ""}`}
                onClick={() => setSidebarOpen(false)}
            />
            <aside className={`${styles.autofixSidebar} ${sidebarOpen ? styles.autofixSidebarOpen : ""}`}>
                <header className={styles.autofixSidebarHeader}>
                    <p className={styles.autofixResponseTitle}>Autofix Proposal</p>
                    <button
                        type="button"
                        className={styles.autofixCloseBtn}
                        onClick={() => setSidebarOpen(false)}
                        aria-label="Close autofix proposal"
                    >
                        <X size={16} />
                    </button>
                </header>

                <div className={styles.autofixSidebarBody}>
                    {formatAutofixText(state.content)
                        .split(/\n{2,}/)
                        .filter(Boolean)
                        .map((paragraph, index) => (
                            <p key={index} className={styles.autofixResponseBody}>
                                {paragraph}
                            </p>
                        ))}
                </div>

                <footer className={styles.autofixSidebarFooter}>
                    <button type="button" className={styles.prBtn} onClick={handleCreatePr} disabled={!canCreatePr || state.status === "pr-loading"}>
                        <span className={styles.prBtnLeft}>
                            {state.status === "pr-loading" ? <LoaderCircle size={14} className="animate-spin" /> : <GitPullRequest size={14} />}
                            <span>{state.status === "pr-loading" ? "Creating Pull Request" : "Create Pull Request"}</span>
                        </span>
                    </button>
                    {state.url ? <a className={styles.prResult} href={state.url} target="_blank" rel="noreferrer">View created pull request</a> : null}
                </footer>
            </aside>
        </div>
    );
}