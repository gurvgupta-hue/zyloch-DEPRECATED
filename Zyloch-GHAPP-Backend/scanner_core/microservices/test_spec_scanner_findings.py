"""Unit tests for spec-scanner findings shape (endpoint vs source file)."""
from __future__ import annotations

from scanner_core.base_scanner import BaseScanner, ScanFinding, ScanSeverity
from scanner_core.microservices.spec_scanner import (
    _attach_code_blocks_to_violations,
    _build_findings,
)


class _ProbeScanner(BaseScanner):
    def scan(self, request):  # pragma: no cover - unused
        raise NotImplementedError


def test_build_findings_keeps_endpoint_in_file_and_sets_source_file():
    payload = {
        "apis": [
            {
                "method": "POST",
                "path": "/api/order",
                "file": "app/routes/order.py",
                "line": 42,
            }
        ],
        "apiViolations": [
            {
                "violationId": "OWASP-API2-AUTH",
                "severity": "CRITICAL",
                "message": "Authentication missing on POST /api/order",
                "method": "POST",
                "path": "/api/order",
            }
        ],
        "payloadViolations": [],
    }

    findings = _build_findings(payload)
    assert len(findings) == 1
    finding = findings[0]
    # file_name stays endpoint
    assert finding.file == "POST /api/order"
    assert finding.source_file == "app/routes/order.py"
    assert finding.line == "42"


def test_build_findings_prefers_violation_file_line_over_apis_lookup():
    payload = {
        "apis": [
            {
                "method": "GET",
                "path": "/users",
                "file": "fallback.py",
                "line": 1,
            }
        ],
        "apiViolations": [
            {
                "violationId": "OWASP-API1",
                "severity": "HIGH",
                "message": "BOLA on GET /users",
                "method": "GET",
                "path": "/users",
                "file": "handlers/users.py",
                "line": 99,
            }
        ],
    }
    findings = _build_findings(payload)
    assert findings[0].source_file == "handlers/users.py"
    assert findings[0].line == "99"


def test_populate_code_blocks_uses_source_file_under_base_path(tmp_path):
    source = tmp_path / "UserController.java"
    source.write_text(
        "\n".join(
            [
                "package com.example;",
                "",
                "@RestController",
                "public class UserController {",
                "  @GetMapping(\"/api/user/{id}\")",
                "  public User getUser(@PathVariable Long id) {",
                "    return userService.findById(id);",
                "  }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    finding = ScanFinding(
        policy="OWASP-API1",
        severity=ScanSeverity.CRITICAL,
        description="Potential BOLA",
        file="GET /api/user/{id}",
        line="6",
        source_file="UserController.java",
    )
    _ProbeScanner("spec-scanner")._populate_code_blocks(
        [finding], base_path=str(tmp_path)
    )

    assert finding.code_block is not None
    assert "@GetMapping" in finding.code_block
    assert "return userService.findById(id);" in finding.code_block


def test_attach_code_blocks_to_violations_copies_onto_api_and_payload():
    payload = {
        "apiViolations": [
            {"violationId": "OWASP-API1", "method": "GET", "path": "/users"},
        ],
        "payloadViolations": [
            {"rule": "SCHEMA-001", "method": "POST", "path": "/users"},
        ],
    }
    findings = [
        ScanFinding(
            policy="OWASP-API1",
            severity=ScanSeverity.CRITICAL,
            description="BOLA",
            file="GET /users",
            line="1",
            code_block="code-a",
        ),
        ScanFinding(
            policy="SCHEMA-001",
            severity=ScanSeverity.MEDIUM,
            description="schema",
            file="POST /users",
            line="2",
            code_block="code-b",
        ),
    ]

    _attach_code_blocks_to_violations(payload, findings)

    assert payload["apiViolations"][0]["code_block"] == "code-a"
    assert payload["payloadViolations"][0]["code_block"] == "code-b"
