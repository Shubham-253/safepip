"""
SecurityReport — aggregates all check results into a structured report
with a clear pass/fail decision and human-readable output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List
from .checks import CheckResult


@dataclass
class SecurityReport:
    package: str
    version: str
    results: List[CheckResult] = field(default_factory=list)

    @property
    def critical_failures(self) -> List[CheckResult]:
        return [r for r in self.results if not r.passed and r.severity == "critical"]

    @property
    def warnings(self) -> List[CheckResult]:
        return [r for r in self.results if not r.passed and r.severity == "warning"]

    @property
    def passed_checks(self) -> List[CheckResult]:
        return [r for r in self.results if r.passed]

    @property
    def safe_to_install(self) -> bool:
        """True only if zero critical failures."""
        return len(self.critical_failures) == 0

    @property
    def risk_level(self) -> str:
        if self.critical_failures:
            return "CRITICAL"
        if self.warnings:
            return "MODERATE"
        return "LOW"

    def summary(self) -> str:
        lines = [
            "",
            "━" * 60,
            f"  safepip Security Report",
            f"  Package : {self.package}=={self.version}",
            f"  Risk    : {self.risk_level}",
            f"  Verdict : {'✅ SAFE TO INSTALL' if self.safe_to_install else '🚨 DO NOT INSTALL'}",
            "━" * 60,
        ]

        if self.critical_failures:
            lines.append("\n🚨 CRITICAL FAILURES:")
            for r in self.critical_failures:
                lines.append(f"   • {r.message}")

        if self.warnings:
            lines.append("\n⚠️  WARNINGS:")
            for r in self.warnings:
                lines.append(f"   • {r.message}")

        if self.passed_checks:
            lines.append("\n✅ PASSED CHECKS:")
            for r in self.passed_checks:
                lines.append(f"   • [{r.name}] {r.message}")

        lines.append("━" * 60)
        lines.append("")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "safe_to_install": self.safe_to_install,
            "risk_level": self.risk_level,
            "critical_failures": [
                {"name": r.name, "message": r.message, "detail": r.detail}
                for r in self.critical_failures
            ],
            "warnings": [
                {"name": r.name, "message": r.message, "detail": r.detail}
                for r in self.warnings
            ],
            "passed": [
                {"name": r.name, "message": r.message}
                for r in self.passed_checks
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
