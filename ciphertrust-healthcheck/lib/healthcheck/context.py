"""Finding and report context."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Finding:
    area: str
    code: str
    severity: str  # CRITICAL | WARNING | INFO
    message: str


@dataclass
class ReportCtx:
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)

    def add(
        self,
        area: str,
        code: str,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            Finding(area=area, code=code, severity=severity, message=message)
        )

    def section(self, name: str, result: str, detail: Any, status: int | None = 200) -> None:
        self.sections.append(
            {"name": name, "result": result, "status": status, "detail": detail}
        )
