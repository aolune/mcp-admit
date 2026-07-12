from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from mcp_admit import __version__

REPORT_SCHEMA_VERSION = "mcp-admit.report.v1"
INSPECTION_SCHEMA_VERSION = "mcp-admit.inspection.v1"
RUNTIME_POLICY_SCHEMA_VERSION = "mcp-admit.runtime-policy.v1"
AUDIT_SCHEMA_VERSION = "mcp-admit.audit.v1"
ADMISSION_SCHEMA_VERSION = "mcp-admit.admission.v1"
INVENTORY_SCHEMA_VERSION = "mcp-admit.inventory.v1"
RELEASE_CHECK_SCHEMA_VERSION = "mcp-admit.release-check.v1"

Severity = Literal["info", "low", "medium", "high", "critical"]
RiskLevel = Literal["L0", "L1", "L2", "L3", "L4"]
PolicyAction = Literal[
    "allow",
    "allow_with_constraints",
    "require_approval",
    "deny",
    "quarantine",
]
ExecutionStatus = Literal[
    "blocked_missing_allow_exec",
    "blocked_command_not_allowlisted",
    "blocked_env_not_allowlisted",
    "success",
    "protocol_error",
    "timeout",
    "unsupported_transport",
]
AdmissionDecision = Literal[
    "allow",
    "allow_with_constraints",
    "review",
    "deny",
    "quarantine",
]
PolicyEffectAction = Literal["ignored", "downgraded", "expired"]
ApprovalStatus = Literal["approved", "pending", "unknown", "expired", "drifted"]
ReleaseCheckStatus = Literal["pass", "fail"]


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    capability: str = "unknown"
    location: str
    evidence: str
    reason: str
    recommendation: str
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: RiskLevel
    policy_action: PolicyAction = "allow_with_constraints"
    confidence: float = Field(ge=0, le=1)
    owasp: list[str] = Field(default_factory=list)
    related_finding_ids: list[str] = Field(default_factory=list)


class ToolDefinition(BaseModel):
    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=dict)
    source_type: Literal["manifest", "markdown"] = "manifest"


class PolicyDecision(BaseModel):
    action: PolicyAction
    require_approval: bool = False
    sandbox: bool = False
    network: Literal["allow", "restricted", "deny"] = "allow"
    notes: list[str] = Field(default_factory=list)


class RiskFactor(BaseModel):
    id: str
    score: int = Field(ge=0, le=100)
    reason: str
    capabilities: list[str] = Field(default_factory=list)
    source_finding_ids: list[str] = Field(default_factory=list)
    occurrences: int = Field(default=1, ge=1)


class ScanSummary(BaseModel):
    total_findings: int
    max_severity: Severity
    risk_score: int
    tool_risk_level: RiskLevel
    gate_result: Literal["pass", "warn", "fail"]
    approval_required: bool
    sandbox_required: bool
    egress_review_required: bool
    credential_review_required: bool
    recommended_policy: PolicyDecision
    risk_score_method: Literal["max_finding_with_composition"] = "max_finding_with_composition"
    risk_factors: list[RiskFactor] = Field(default_factory=list)


class PolicyContext(BaseModel):
    profile: str | None = None
    fail_on: Severity | None = None
    deny_capabilities: list[str] = Field(default_factory=list)
    require_approval_levels: list[RiskLevel] = Field(default_factory=list)
    allow_exec_command_count: int = Field(default=0, ge=0)
    waiver_count: int = Field(default=0, ge=0)
    policy_effect_count: int = Field(default=0, ge=0)


class RuleExplanation(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    capability: str
    risk_level: RiskLevel
    policy_action: PolicyAction
    description: str
    recommendation: str
    owasp: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    schema_version: Literal["mcp-admit.report.v1"] = REPORT_SCHEMA_VERSION
    tool_version: str = __version__
    target: str
    findings: list[Finding]
    summary: ScanSummary
    policy_context: PolicyContext = Field(default_factory=PolicyContext)
    policy_effects: list["PolicyEffect"] = Field(default_factory=list)
    rule_explanations: list[RuleExplanation] = Field(default_factory=list)


class PolicyEffect(BaseModel):
    action: PolicyEffectAction
    finding_id: str
    location: str
    reason: str
    policy_ref: str


class InspectionExecution(BaseModel):
    status: ExecutionStatus
    server: str
    transport: str
    launch: str = ""
    finding_id: str | None = None
    allowed_env_keys: list[str] = Field(default_factory=list)
    blocked_env_keys: list[str] = Field(default_factory=list)
    message: str


class LiveToolSummary(BaseModel):
    name: str
    description: str = ""
    input_properties: list[str] = Field(default_factory=list)
    required: list[str] = Field(default_factory=list)
    allows_additional_properties: bool | None = None


class InspectionReport(BaseModel):
    schema_version: Literal["mcp-admit.inspection.v1"] = INSPECTION_SCHEMA_VERSION
    tool_version: str = __version__
    target: str
    server: str
    execution: InspectionExecution
    live_tools: list[LiveToolSummary] = Field(default_factory=list)
    static_result: ScanResult
    live_result: ScanResult | None = None


class RuntimePolicyRule(BaseModel):
    id: str
    scope: Literal["default", "capability", "finding"]
    match: dict[str, Any] = Field(default_factory=dict)
    action: PolicyAction
    require_approval: bool
    sandbox: bool
    network: Literal["allow", "restricted", "deny"]
    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    finding_ids: list[str] = Field(default_factory=list)
    reason: str


class RuntimePolicyReport(BaseModel):
    schema_version: Literal["mcp-admit.runtime-policy.v1"] = RUNTIME_POLICY_SCHEMA_VERSION
    tool_version: str = __version__
    target: str
    source_schema_version: str
    default_action: PolicyAction
    rules: list[RuntimePolicyRule]
    notes: list[str] = Field(default_factory=list)


class AuditItem(BaseModel):
    id: str
    title: str
    status: Literal["pass", "warn", "fail"]
    detail: str


class AuditReport(BaseModel):
    schema_version: Literal["mcp-admit.audit.v1"] = AUDIT_SCHEMA_VERSION
    tool_version: str = __version__
    target: str
    gate_result: Literal["pass", "warn", "fail"]
    runtime_policy: RuntimePolicyReport
    scan_summary: ScanSummary
    policy_context: PolicyContext = Field(default_factory=PolicyContext)
    policy_effects: list[PolicyEffect] = Field(default_factory=list)
    rule_explanations: list[RuleExplanation] = Field(default_factory=list)
    items: list[AuditItem]
    next_actions: list[str] = Field(default_factory=list)


class AdmissionSubject(BaseModel):
    target: str
    server: str = ""
    service: str = "unknown"
    owner: str = "unknown"
    environment: str = "unknown"
    request_id: str = ""


class AdmissionControl(BaseModel):
    id: str
    title: str
    required: bool
    status: Literal["pass", "warn", "fail"]
    detail: str


class AdmissionInputReport(BaseModel):
    schema_version: Literal["mcp-admit.admission.v1"] = ADMISSION_SCHEMA_VERSION
    tool_version: str = __version__
    subject: AdmissionSubject
    decision: AdmissionDecision
    decision_reason: str = ""
    approval: "ApprovalDecision | None" = None
    gate_result: Literal["pass", "warn", "fail"]
    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    capabilities: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    policy_context: PolicyContext = Field(default_factory=PolicyContext)
    policy_effects: list[PolicyEffect] = Field(default_factory=list)
    rule_explanations: list[RuleExplanation] = Field(default_factory=list)
    controls: list[AdmissionControl]
    runtime_policy: RuntimePolicyReport
    audit: AuditReport
    scan_summary: ScanSummary


class DiscoveredServer(BaseModel):
    client: str
    source: str
    name: str
    location: str
    transport: str = "unknown"
    command: str = ""
    url: str = ""
    package: str = ""
    env_keys: list[str] = Field(default_factory=list)


class DiscoveryReport(BaseModel):
    target: str
    total_servers: int
    clients: list[str] = Field(default_factory=list)
    servers: list[DiscoveredServer] = Field(default_factory=list)


class ApprovalRecord(BaseModel):
    id: str
    status: Literal["pending", "approved"] = "approved"
    client: str = ""
    source: str = ""
    name: str
    definition_hash: str
    approved_by: str
    reason: str
    expires: str = ""
    allowed_capabilities: list[str] = Field(default_factory=list)


class ApprovalDecision(BaseModel):
    status: ApprovalStatus
    approval_id: str = ""
    reason: str


class InventoryServerReport(BaseModel):
    server: DiscoveredServer
    summary: ScanSummary
    finding_ids: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    definition_hash: str
    approval: ApprovalDecision = Field(
        default_factory=lambda: ApprovalDecision(status="unknown", reason="No approval registry provided.")
    )


class InventoryReport(BaseModel):
    schema_version: Literal["mcp-admit.inventory.v1"] = INVENTORY_SCHEMA_VERSION
    tool_version: str = __version__
    target: str
    total_servers: int
    clients: list[str] = Field(default_factory=list)
    servers: list[InventoryServerReport] = Field(default_factory=list)


class ReviewPackReport(BaseModel):
    target: str
    output_dir: str
    files: list[str] = Field(default_factory=list)
    inventory: InventoryReport
    scan_summary: ScanSummary


class ReleaseCheckItem(BaseModel):
    id: str
    status: ReleaseCheckStatus
    detail: str


class ReleaseCheckReport(BaseModel):
    schema_version: Literal["mcp-admit.release-check.v1"] = RELEASE_CHECK_SCHEMA_VERSION
    tool_version: str = __version__
    status: ReleaseCheckStatus
    items: list[ReleaseCheckItem]
