import {
    extractAffectedFromDescription,
    extractPatchedFromDescription,
    resolveAffectedValue,
    resolvePatchedValue,
    resolveReport,
} from "@/app/scanops/cve/[cveId]/page";

describe("CVE detail page version resolution", () => {
    const advisoryDescription = "Budibase is an open-source low-code platform. Prior to 3.3.0, fetchToken in the OAuth2 SDK makes a POST to a builder-supplied URL.";

    test("extracts affected version from natural-language advisory text", () => {
        expect(extractAffectedFromDescription(advisoryDescription)).toBe("< 3.3.0");
    });

    test("extracts patched version from natural-language advisory text", () => {
        expect(extractPatchedFromDescription(advisoryDescription)).toBe("3.3.0");
    });

    test("falls back to advisory text when affectedVersion is blank", () => {
        expect(
            resolveAffectedValue({
                affectedVersion: "",
                description: advisoryDescription,
            }),
        ).toBe("< 3.3.0");
    });

    test("ignores placeholder fixedVersion and falls back to advisory text", () => {
        expect(
            resolvePatchedValue({
                fixedVersion: "Unknown",
                description: advisoryDescription,
            }),
        ).toBe("3.3.0");
    });

    test("prefers explicit version fields over advisory-derived values", () => {
        expect(
            resolveReport("CVE-2026-48153", {
                pkg: "node-fetch",
                version: "3.3.2",
                affectedVersion: "<= 3.2.9",
                fixedVersion: "3.3.1",
                description: advisoryDescription,
            }),
        ).toEqual(
            expect.objectContaining({
                affected: "<= 3.2.9",
                patched: "3.3.1",
            }),
        );
    });

    test("resolves affected and patched in the full report for the current regression case", () => {
        expect(
            resolveReport("CVE-2026-48153", {
                pkg: "node-fetch",
                version: "3.3.2",
                affectedVersion: "",
                fixedVersion: "",
                description: advisoryDescription,
                severity: "High",
                priority: "High",
            }),
        ).toEqual(
            expect.objectContaining({
                affected: "< 3.3.0",
                patched: "3.3.0",
            }),
        );
    });
});