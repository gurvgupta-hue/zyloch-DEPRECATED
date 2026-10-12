// components/dashboard/FindingDetailsSidebar.jsx
import React, { useEffect, useState } from "react";
import {
    X,
    Copy,
    Check,
    ChevronDown,
    Radar,
    ShieldAlert,
    Wrench,
    BookOpen,
    LoaderCircle,
    WandSparkles,
} from "lucide-react";
import { createAutofixPr, requestAutofix } from "@/lib/api/scans";
import {
    formatSeverityLabel,
    getSeverityBadgeStyle as getSharedSeverityBadgeStyle,
    getSeverityIcon,
} from "../shared/severityVisuals";

const parseMatches = (matches) => {
    if (typeof matches === "string") {
        try {
            return JSON.parse(matches || "[]");
        } catch {
        }
    }

    return Array.isArray(matches) ? matches : [];
};

const getDisplayFileName = (value) => {
    if (!value) return null;
    const normalized = String(value).replace(/\\/g, "/");
    const parts = normalized.split("/").filter(Boolean);
    const baseName = parts[parts.length - 1] || normalized;

    // Dockerfiles are almost always literally named "Dockerfile", so keep the
    // immediate parent folder (e.g. "backend/Dockerfile") to distinguish
    // between multiple Dockerfiles in the same repo instead of collapsing
    // them all down to the same bare "Dockerfile".
    if (baseName.toLowerCase() === "dockerfile" && parts.length > 1) {
        return `${parts[parts.length - 2]}/${baseName}`;
    }

    return baseName;
};

// Section label for the finding's accordion — driven by the finding's
// scannerType where the caller sets one (skill-scanner, cis-agent); falls
// back to the legacy type-based checks for callers that predate that field
// (IaC, Spec Scanner) so their labeling is unchanged.
const getOverviewSectionLabel = (finding) => {
    const scannerType = String(finding.scannerType || "").toLowerCase();
    if (scannerType === "cis-agent" || scannerType === "cis") return "CIS Controls";
    if (scannerType === "skill-scanner") return "AI Security Scanner";
    if (finding.type === "spec-scanner") return "API Discovery";
    return "Infrastructure as Code";
};

const getValidLineNumber = (lineNo) => {
    const parsed = Number(lineNo);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
};

const getSeverityBadgeStyle = (severity) => {
    return getSharedSeverityBadgeStyle(severity);
};

const copyText = async (value) => {
    const text = String(value || "");
    if (!text) return false;

    if (navigator.clipboard?.writeText) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            // Fall back for non-secure origins and browsers that deny clipboard access.
        }
    }

    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.setAttribute("readonly", "");
    textArea.style.position = "fixed";
    textArea.style.opacity = "0";

    document.body.appendChild(textArea);
    textArea.select();

    try {
        return document.execCommand("copy");
    } finally {
        document.body.removeChild(textArea);
    }
};

const parseAutofixBlocks = (content) => {
    const lines = String(content || "").replace(/\r\n/g, "\n").split("\n");
    const blocks = [];
    let textLines = [];
    let codeLines = [];
    let inCodeBlock = false;

    const flushText = () => {
        const text = textLines.join("\n").trim();
        if (text) blocks.push({ type: "text", content: text });
        textLines = [];
    };

    lines.forEach((line) => {
        if (!inCodeBlock && /^```(?:[\w-]+)?\s*$/.test(line.trim())) {
            flushText();
            inCodeBlock = true;
            codeLines = [];
            return;
        }

        if (inCodeBlock && /^```\s*$/.test(line.trim())) {
            blocks.push({ type: "code", content: codeLines.join("\n") });
            codeLines = [];
            inCodeBlock = false;
            return;
        }

        if (inCodeBlock) {
            codeLines.push(line);
        } else if (line.trim()) {
            textLines.push(line);
        } else {
            flushText();
        }
    });

    if (inCodeBlock) blocks.push({ type: "code", content: codeLines.join("\n") });
    flushText();
    return blocks;
};

const AutofixProposal = ({ content }) => {
    const blocks = parseAutofixBlocks(content);

    return (
        <div className="max-h-[520px] space-y-3 overflow-auto p-3 text-sm leading-relaxed text-text-secondary">
            {blocks.map((block, index) => {
                if (block.type === "code") {
                    return (
                        <pre key={index} className="overflow-x-auto rounded-md border border-default bg-[var(--surface)] p-3 font-mono text-xs leading-relaxed text-text">
                            <code>{block.content}</code>
                        </pre>
                    );
                }

                const lines = block.content.split("\n");
                const text = block.content;
                const firstLine = lines[0];
                const heading = firstLine.match(/^(#{1,3})\s+(.+)$/);
                const unorderedList = lines.every((line) => /^\s*[-*+]\s+/.test(line));
                const orderedList = lines.every((line) => /^\s*\d+[.)]\s+/.test(line));

                if (heading) {
                    const Heading = heading[1].length === 1 ? "h3" : "h4";
                    return (
                        <Heading key={index} className="font-semibold text-text">
                            {heading[2]}
                        </Heading>
                    );
                }

                if (unorderedList || orderedList) {
                    const List = orderedList ? "ol" : "ul";
                    return (
                        <List key={index} className={`${orderedList ? "list-decimal" : "list-disc"} space-y-1 pl-5`}>
                            {lines.map((line) => (
                                <li key={line}>{line.replace(/^\s*(?:[-*+]\s+|\d+[.)]\s+)/, "")}</li>
                            ))}
                        </List>
                    );
                }

                return (
                    <p key={index} className="whitespace-pre-wrap">
                        {text.replace(/\*\*(.*?)\*\*/g, "$1").replace(/__(.*?)__/g, "$1")}
                    </p>
                );
            })}
        </div>
    );
};

const AccordionSection = ({
    id,
    title,
    icon: Icon,
    isOpen,
    onToggle,
    children,
}) => {
    return (
        <section className="rounded-xl border border-default bg-[var(--elevated-surface)]">
            <button
                type="button"
                onClick={() => onToggle(id)}
                aria-expanded={isOpen}
                className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors-fast hover:brightness-95"
            >
                <span className="inline-flex items-center gap-2">
                    <Icon className="h-4 w-4 text-muted" />
                    <span className="text-sm font-semibold text-text">{title}</span>
                </span>
                <ChevronDown
                    className={`h-4 w-4 text-muted transition-transform duration-300 ${isOpen ? "rotate-180" : ""}`}
                />
            </button>

            <div
                className={`grid transition-all duration-300 ease-in-out ${isOpen ? "grid-rows-[1fr]" : "grid-rows-[0fr]"}`}
            >
                <div className="overflow-hidden">
                    <div className="space-y-4 border-t border-[var(--border)] px-4 py-4">{children}</div>
                </div>
            </div>
        </section>
    );
};

const CopyCodeButton = ({ code }) => {
    const [copied, setCopied] = useState(false);
    const handleCopy = async () => {
        if (await copyText(code)) {
            setCopied(true);
            setTimeout(() => setCopied(false), 1800);
        }
    };
    return (
        <button
            type="button"
            onClick={handleCopy}
            className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-default bg-[var(--surface)] text-muted transition-colors-fast hover:border-hover hover:text-text"
            title="Copy code"
            aria-label="Copy code"
        >
            {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
    );
};

const CodeBlockViewer = ({ code, startLineNum, targetLineNum }) => {
    const lines = (code || "").split("\n");
    return (
        <div className="overflow-hidden rounded-md border border-default bg-[var(--surface)]">
            <pre className="overflow-x-auto p-3 text-xs leading-relaxed">
                {lines.map((line, i) => {
                    const lineNum = startLineNum != null ? startLineNum + i : null;
                    const isTarget = lineNum != null && lineNum === targetLineNum;
                    return (
                        <div
                            key={i}
                            className={`flex gap-3 rounded px-1 -mx-1 ${isTarget ? "bg-[color-mix(in_srgb,var(--warning)_12%,transparent)]" : ""
                                }`}
                        >
                            {lineNum != null && (
                                <span className={`select-none w-7 shrink-0 text-right font-mono ${isTarget ? "font-semibold text-[var(--warning)]" : "opacity-40 text-muted"
                                    }`}>
                                    {lineNum}
                                </span>
                            )}
                            <code className={isTarget ? "text-text font-medium" : "text-text-secondary"}>
                                {line || "\u00A0"}
                            </code>
                        </div>
                    );
                })}
            </pre>
        </div>
    );
};

const FindingDetailsSidebar = ({ finding, repositoryContext, isOpen, onClose }) => {
    const [copiedCode, setCopiedCode] = useState(false);
    const [autofixState, setAutofixState] = useState({ findingId: null, status: "idle", content: "", error: "" });
    const [prState, setPrState] = useState({ findingId: null, status: "idle", url: "", error: "" });
    const [expandedSections, setExpandedSections] = useState({
        overview: true,
        remediation: false,
    });

    useEffect(() => {
        if (!finding) return;
        const hasExamples = Boolean(finding.examples?.bad || finding.examples?.good);
        setExpandedSections((prev) => ({
            ...prev,
            overview: true,
            remediation: hasExamples ? true : prev.remediation,
        }));
    }, [finding]);

    if (!finding) return null;

    const severityKey = String(finding.severity || "low").toLowerCase();
    const severityIcon = getSeverityIcon(severityKey);
    const currentAutofix = autofixState.findingId === finding.id ? autofixState : { status: "idle", content: "", error: "" };
    const currentPr = prState.findingId === finding.id ? prState : { status: "idle", url: "", error: "" };
    const isPrPermissionError = currentPr.status === "error" && currentPr.error && (
        currentPr.error.toLowerCase().includes("permission") ||
        currentPr.error.toLowerCase().includes("authorized") ||
        currentPr.error.toLowerCase().includes("forbidden")
    );
    const canCreatePr = Boolean(
        currentAutofix.content &&
        repositoryContext?.installationId &&
        repositoryContext?.repository
    );

    const matches = parseMatches(finding.matches);

    const affectedCode = matches[0]?.content || "";
    const codeBlock = finding.codeBlock || null;
    const autofixSource = codeBlock || affectedCode || "";
    // Autofix is tenant-scoped: the request is resolved against the installation's
    // owning tenant, so without an installation there is nothing to authorise against.
    const canAutofix = Boolean(autofixSource && repositoryContext?.installationId);
    const matchLineStart = getValidLineNumber(matches[0]?.line_start);
    const matchLineEnd = getValidLineNumber(matches[0]?.line_end);
    const fallbackLine = getValidLineNumber(finding.lineNo);
    const highlightCapturedLines = Boolean(codeBlock) && finding.codeBlockCaptured !== false;
    const codeBlockStartLine =
        highlightCapturedLines && fallbackLine ? Math.max(1, fallbackLine - 2) : null;
    const showSourceContext =
        Boolean(codeBlock) ||
        Boolean(getDisplayFileName(finding.file || finding.fullPath) && fallbackLine);

    const lineLabel = (() => {
        if (matchLineStart && matchLineEnd && matchLineEnd > matchLineStart) {
            return `Lines ${matchLineStart}-${matchLineEnd}`;
        }
        if (matchLineStart) return `Line ${matchLineStart}`;
        if (fallbackLine) return `Line ${fallbackLine}`;
        return null;
    })();

    const metadataChips = [
        finding.category ? { label: "Category", value: finding.category } : null,
        finding.checkerKey ? { label: "Checker", value: finding.checkerKey, mono: true } : null,
        finding.mappedIdentifier
            ? { label: "Mapped ID", value: finding.mappedIdentifier, mono: true }
            : null,
        getDisplayFileName(finding.file || finding.fullPath)
            ? { label: "File", value: getDisplayFileName(finding.file || finding.fullPath), mono: true }
            : null,
    ].filter(Boolean);

    const overviewBlocks = [
        {
            key: "description",
            title: "Description",
            value: finding.description || finding.summary,
            icon: BookOpen,
        },
        {
            key: "why",
            title: "Why This Was Flagged",
            value: finding.whyFlagged,
            icon: ShieldAlert,
        },
        {
            key: "risk",
            title: "Risk & Impact",
            value: finding.riskImpact,
            icon: Radar,
        },
    ].filter((item) => Boolean(item.value));

    const toggleSection = (sectionId) => {
        setExpandedSections((prev) => ({
            ...prev,
            [sectionId]: !prev[sectionId],
        }));
    };

    const handleCopyCode = async () => {
        if (await copyText(affectedCode)) {
            setCopiedCode(true);
            setTimeout(() => setCopiedCode(false), 1800);
        }
    };

    const handleAutofix = async () => {
        if (!autofixSource || currentAutofix.status === "loading") return;
        setAutofixState({ findingId: finding.id, status: "loading", content: "", error: "" });
        try {
            const response = await requestAutofix(
                { ...finding, codeBlock: autofixSource },
                { installationId: repositoryContext?.installationId }
            );
            setAutofixState({
                findingId: finding.id,
                status: "success",
                content: response.content || "",
                error: "",
            });
        } catch (error) {
            setAutofixState({
                findingId: finding.id,
                status: "error",
                content: "",
                error: error instanceof Error ? error.message : "Unable to generate autofix",
            });
        }
    };

    const handleCreatePr = async () => {
        if (!currentAutofix.content || currentPr.status === "loading") return;
        setPrState({ findingId: finding.id, status: "loading", url: "", error: "" });
        try {
            const response = await createAutofixPr(
                { ...finding, codeBlock: autofixSource },
                currentAutofix.content,
                repositoryContext
            );
            setPrState({ findingId: finding.id, status: "success", url: response.pr_url || "", error: "" });
        } catch (error) {
            setPrState({
                findingId: finding.id,
                status: "error",
                url: "",
                error: error instanceof Error ? error.message : "Unable to create pull request",
            });
        }
    };

    return (
        <>
            <div
                className={`fixed inset-0 z-[90] bg-black/50 backdrop-blur-sm transition-opacity duration-300 ${isOpen ? "opacity-100" : "pointer-events-none opacity-0"
                    }`}
                onClick={onClose}
            />

            <aside
                className={`fixed right-0 top-0 z-[100] h-screen w-[560px] max-w-full transform overflow-y-auto border-l border-default bg-[var(--surface)] shadow-2 transition-transform duration-300 ease-in-out ${isOpen ? "translate-x-0" : "translate-x-full"}`}
            >
                <header className="sticky top-0 z-10 flex items-center justify-between border-b border-default bg-[var(--surface)] px-5 py-3 backdrop-blur">
                    <div className="flex min-w-0 items-center gap-2">
                        <span
                            className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-semibold tracking-wider"
                            style={getSeverityBadgeStyle(severityKey)}
                        >
                            {React.createElement(severityIcon, { className: "h-3.5 w-3.5" })}
                            {formatSeverityLabel(severityKey).toUpperCase()}
                        </span>
                        <span className="truncate font-mono text-xs text-muted">{finding.policyCode || "N/A"}</span>
                    </div>

                    <button
                        type="button"
                        onClick={onClose}
                        aria-label="Close details"
                        className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-default bg-[var(--surface)] text-muted transition-colors-fast hover:border-hover hover:text-text"
                    >
                        <X className="h-4 w-4" />
                    </button>
                </header>

                <div className="space-y-5 px-5 py-5">
                    <section className="rounded-xl border border-default bg-[var(--elevated-surface)] p-4">
                        <h2 className="text-lg font-semibold leading-snug text-text break-words">{finding.title || finding.description || "Security Finding"}</h2>

                        <div className="mt-3 flex flex-wrap items-center gap-2">
                            {metadataChips.map((chip) => (
                                <span
                                    key={`${chip.label}-${chip.value}`}
                                    className={`inline-flex items-center rounded-full border border-default bg-surface px-2.5 py-1 text-xs text-text ${chip.mono ? "font-mono" : "font-medium"
                                        }`}
                                >
                                    <span className="text-muted">{chip.label}:&nbsp;</span>
                                    <span className="max-w-[220px] truncate">{chip.value}</span>
                                </span>
                            ))}

                            {lineLabel && (
                                <span className="inline-flex items-center rounded-full border border-default bg-surface px-2.5 py-1 font-mono text-xs font-semibold text-text-secondary">
                                    {lineLabel}
                                </span>
                            )}
                        </div>
                    </section>

                    <AccordionSection
                        id="overview"
                        title={getOverviewSectionLabel(finding)}
                        icon={Radar}
                        isOpen={expandedSections.overview}
                        onToggle={toggleSection}
                    >
                        {showSourceContext && (
                            <article className="rounded-lg border border-default bg-[var(--elevated-surface)] p-3">
                                <div className="mb-2 flex items-center justify-between gap-3">
                                    <div className="min-w-0">
                                        <p className="text-xs font-semibold tracking-wide text-muted uppercase">Source Context</p>
                                        {codeBlock && finding.codeBlockCaptured === false && (
                                            <p className="mt-0.5 text-[11px] text-muted">
                                                Reconstructed from endpoint metadata
                                            </p>
                                        )}
                                    </div>
                                    {codeBlock ? <CopyCodeButton code={codeBlock} /> : null}
                                </div>
                                {codeBlock ? (
                                    <CodeBlockViewer
                                        code={codeBlock}
                                        startLineNum={codeBlockStartLine}
                                        targetLineNum={highlightCapturedLines ? fallbackLine : null}
                                    />
                                ) : (
                                    <div className="rounded-md border border-dashed border-default bg-[var(--surface)] px-3 py-4">
                                        <p className="font-mono text-xs font-medium text-text">
                                            {getDisplayFileName(finding.file || finding.fullPath)}
                                            {fallbackLine ? `:${fallbackLine}` : ""}
                                        </p>
                                        <p className="mt-1 text-xs leading-relaxed text-muted">
                                            Source snippet unavailable for this scan. Re-run API Discovery to capture surrounding code.
                                        </p>
                                    </div>
                                )}
                            </article>
                        )}

                        {overviewBlocks.length > 0 ? (
                            overviewBlocks.map((block) => (
                                <article key={block.key} className="rounded-lg border border-default bg-[var(--elevated-surface)] p-3">
                                    <p className="mb-1 inline-flex items-center gap-2 text-xs font-semibold tracking-wide text-muted uppercase">
                                        <block.icon className="h-3.5 w-3.5" />
                                        {block.title}
                                    </p>
                                    <p className="text-sm leading-relaxed text-text-secondary whitespace-pre-wrap">{block.value}</p>
                                </article>
                            ))
                        ) : (
                            <p className="text-sm text-muted">
                                No {getOverviewSectionLabel(finding)} details available for this finding.
                            </p>
                        )}



                        {affectedCode && (
                            <article className="rounded-lg border border-default bg-[var(--elevated-surface)] p-3">
                                <div className="mb-2 flex items-center justify-between gap-3">
                                    <p className="text-xs font-semibold tracking-wide text-muted uppercase">Affected Code</p>
                                    <button
                                        type="button"
                                        onClick={handleCopyCode}
                                        className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-default bg-[var(--surface)] text-muted transition-colors-fast hover:border-hover hover:text-text"
                                        title="Copy code"
                                        aria-label="Copy code"
                                    >
                                        {copiedCode ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
                                    </button>
                                </div>

                                <div className="overflow-hidden rounded-md border border-default bg-[var(--surface)]">
                                    <pre className="overflow-x-auto p-3 text-xs leading-relaxed text-text-secondary">
                                        <code>{affectedCode}</code>
                                    </pre>
                                </div>
                            </article>
                        )}
                    </AccordionSection>

                    {finding.payload && (finding.payload.requestBody || finding.payload.responses || finding.payload.examples) && (
                        <section className="rounded-xl border border-default bg-[var(--elevated-surface)] p-4">
                            <p className="mb-3 inline-flex items-center gap-2 text-xs font-semibold tracking-wide text-muted uppercase">
                                <ShieldAlert className="h-3.5 w-3.5" />
                                Request / Response Payload
                            </p>
                            <div className="space-y-3">
                                {finding.payload.requestBody && (
                                    <div>
                                        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">Request Body</p>
                                        <textarea
                                            readOnly
                                            spellCheck={false}
                                            value={JSON.stringify(finding.payload.requestBody, null, 2)}
                                            rows={Math.min(12, JSON.stringify(finding.payload.requestBody, null, 2).split("\n").length + 1)}
                                            className="w-full resize-y rounded-lg border border-default bg-[var(--surface)] p-3 font-mono text-xs leading-relaxed text-text-secondary focus:outline-none focus:ring-1 focus:ring-[var(--color-primary)]"
                                        />
                                    </div>
                                )}
                                {finding.payload.responses && (
                                    <div>
                                        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">Responses</p>
                                        <textarea
                                            readOnly
                                            spellCheck={false}
                                            value={JSON.stringify(finding.payload.responses, null, 2)}
                                            rows={Math.min(12, JSON.stringify(finding.payload.responses, null, 2).split("\n").length + 1)}
                                            className="w-full resize-y rounded-lg border border-default bg-[var(--surface)] p-3 font-mono text-xs leading-relaxed text-text-secondary focus:outline-none focus:ring-1 focus:ring-[var(--color-primary)]"
                                        />
                                    </div>
                                )}
                                {finding.payload.examples && (
                                    <div>
                                        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">Examples</p>
                                        <textarea
                                            readOnly
                                            spellCheck={false}
                                            value={JSON.stringify(finding.payload.examples, null, 2)}
                                            rows={Math.min(10, JSON.stringify(finding.payload.examples, null, 2).split("\n").length + 1)}
                                            className="w-full resize-y rounded-lg border border-default bg-[var(--surface)] p-3 font-mono text-xs leading-relaxed text-text-secondary focus:outline-none focus:ring-1 focus:ring-[var(--color-primary)]"
                                        />
                                    </div>
                                )}
                            </div>
                        </section>
                    )}

                    {Array.isArray(finding.payloadViolations) && finding.payloadViolations.length > 0 && (
                        <section className="rounded-xl border border-default bg-[var(--elevated-surface)] p-4">
                            <p className="mb-3 inline-flex items-center gap-2 text-xs font-semibold tracking-wide text-muted uppercase">
                                <ShieldAlert className="h-3.5 w-3.5" />
                                Payload Validation ({finding.payloadViolations.length})
                            </p>
                            <textarea
                                readOnly
                                spellCheck={false}
                                value={JSON.stringify(
                                    finding.payloadViolations.length === 1
                                        ? finding.payloadViolations[0]
                                        : finding.payloadViolations,
                                    null,
                                    2
                                )}
                                rows={Math.min(
                                    24,
                                    JSON.stringify(
                                        finding.payloadViolations.length === 1
                                            ? finding.payloadViolations[0]
                                            : finding.payloadViolations,
                                        null,
                                        2
                                    ).split("\n").length + 1
                                )}
                                className="w-full resize-y rounded-lg border border-default bg-[var(--surface)] p-3 font-mono text-xs leading-relaxed text-text-secondary focus:outline-none focus:ring-1 focus:ring-[var(--color-primary)]"
                            />
                        </section>
                    )}

                    <AccordionSection
                        id="remediation"
                        title="Remediation Plan"
                        icon={Wrench}
                        isOpen={expandedSections.remediation}
                        onToggle={toggleSection}
                    >
                        <article className="rounded-lg border border-default bg-[var(--elevated-surface)] p-3">
                            <div className="flex items-start justify-between gap-3">
                                <div>
                                    <p className="inline-flex items-center gap-2 text-xs font-semibold tracking-wide text-muted uppercase">
                                        <WandSparkles className="h-3.5 w-3.5" />
                                        Autofix Suggestion
                                    </p>
                                    <p className="mt-1 text-xs leading-relaxed text-muted">
                                        Generate a proposed fix from this finding and its source context for review.
                                    </p>
                                </div>
                                <button
                                    type="button"
                                    onClick={handleAutofix}
                                    disabled={!canAutofix || currentAutofix.status === "loading"}
                                    className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-default bg-[var(--surface)] px-2.5 py-1.5 text-xs font-semibold text-text transition-colors-fast hover:border-hover hover:text-text disabled:cursor-not-allowed disabled:opacity-50"
                                    title={
                                        !autofixSource
                                            ? "Source context is required"
                                            : !repositoryContext?.installationId
                                                ? "Repository installation context is required"
                                                : "Generate autofix suggestion"
                                    }
                                >
                                    {currentAutofix.status === "loading" ? (
                                        <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
                                    ) : (
                                        <WandSparkles className="h-3.5 w-3.5" />
                                    )}
                                    {currentAutofix.status === "loading" ? "Generating" : "Ask for Autofix"}
                                </button>
                            </div>

                            {currentAutofix.status === "error" && (
                                <p className="mt-3 rounded-md border border-critical/30 bg-critical/10 p-2 text-xs text-critical">
                                    {currentAutofix.error}
                                </p>
                            )}

                            {currentAutofix.status === "success" && currentAutofix.content && (
                                <div className="mt-3 overflow-hidden rounded-md border border-default bg-[var(--surface)]">
                                    <div className="flex items-center justify-between border-b border-default px-3 py-2">
                                        <span className="text-xs font-semibold text-text">Generated proposal</span>
                                        <CopyCodeButton code={currentAutofix.content} />
                                    </div>
                                    <AutofixProposal content={currentAutofix.content} />
                                    <div className="border-t border-default p-3">
                                        <button
                                            type="button"
                                            onClick={handleCreatePr}
                                            disabled={!canCreatePr || currentPr.status === "loading" || currentPr.status === "success"}
                                            className="w-full rounded-md px-3 py-2 text-sm font-semibold text-white shadow-sm transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
                                            style={{
                                                backgroundColor: "#4f46e5",
                                                border: "1px solid #3730a3",
                                            }}
                                        >
                                            {currentPr.status === "loading" ? "Creating Pull Request..." : "Create Pull Request"}
                                        </button>
                                        {currentPr.status === "success" && currentPr.url && (
                                            <a
                                                href={currentPr.url}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="mt-2 block text-center text-xs font-medium text-primary underline-offset-2 hover:underline"
                                            >
                                                View Pull Request
                                            </a>
                                        )}
                                        {currentPr.status === "error" && (
                                            <div
                                                role="alert"
                                                className="mt-2 rounded-md border border-amber-500/40 bg-amber-50 p-3 text-xs text-amber-950"
                                            >
                                                <p className="font-semibold">Pull request could not be created</p>
                                                <p className="mt-1 leading-relaxed">{currentPr.error}</p>
                                                {isPrPermissionError && (
                                                    <p className="mt-2 leading-relaxed text-amber-900/80">
                                                        Ask a GitHub App administrator to grant repository Contents and Pull
                                                        requests write access, then approve the updated installation permissions.
                                                    </p>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                        </article>

                    </AccordionSection>
                </div>
            </aside>
        </>
    );
};

export default FindingDetailsSidebar;
