from scanner_core.microservices.docker_scanner import DockerScanner
from scanner_core.models.violation import DockerSecurityViolation


def make_violation(line_number, message="Use a pinned image tag"):
    return DockerSecurityViolation(
        cve_id="DOCKER-SEC-001",
        severity="medium",
        resource_name="repo/Dockerfile",
        resource_type="Dockerfile",
        instruction="FROM ubuntu",
        line_number=line_number,
        message=message,
        metadata={"checker": "LatestTagChecker"},
    )


def test_deduplicate_violations_removes_exact_duplicates():
    duplicate = make_violation(1)

    unique = DockerScanner._deduplicate_violations([duplicate, duplicate])

    assert unique == [duplicate]


def test_deduplicate_violations_keeps_same_policy_on_different_lines():
    first = make_violation(1)
    second = make_violation(2)

    unique = DockerScanner._deduplicate_violations([first, second])

    assert unique == [first, second]