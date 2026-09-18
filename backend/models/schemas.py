from pydantic import BaseModel
from typing import Any, Optional


class Signal(BaseModel):
    name: str
    severity: str          # "low" | "medium" | "high" | "critical"
    weight: float
    explanation: str


class AuthResult(BaseModel):
    spf: str = "unknown"      # pass/fail/neutral/softfail/none/unknown
    dkim: str = "unknown"     # pass/fail/none/unknown
    dmarc: str = "unknown"    # pass/fail/none/unknown
    alignment_issue: Optional[str] = None


class UrlIndicator(BaseModel):
    url: str
    visible_text: Optional[str] = None
    domain: Optional[str] = None
    is_ip_based: bool = False
    is_shortener: bool = False
    suspicious_tld: bool = False
    obfuscated: bool = False
    lookalike_of: Optional[str] = None
    notes: list[str] = []


class DomainIntel(BaseModel):
    domain: str
    a_records: list[str] | str = "unavailable"
    mx_records: list[str] | str = "unavailable"
    ns_records: list[str] | str = "unavailable"
    rdap: dict | str = "unavailable"
    age_days: Optional[int] | str = "unavailable"
    reputation: dict | str = "unavailable"


class InfrastructureNode(BaseModel):
    ip: str
    asn: str | None = "unavailable"
    isp: str | None = "unavailable"
    country: str | None = "unavailable"
    region: str | None = "unavailable"
    city: str | None = "unavailable"
    hosting: str | None = "unavailable"
    vpn_proxy_tor: str | None = "unavailable"
    reputation: dict | str = "unavailable"
    role: str = "observed_relay"   # observed_relay | earliest_observable_external_ip


class CampaignInfo(BaseModel):
    status: str = "not_evaluated"     # not_evaluated | isolated | possible_campaign
    campaign_id: Optional[str] = None
    shared_indicators: list[str] = []
    related_case_count: int = 0


class EvidenceBlock(BaseModel):
    sha256: str
    input_type: str            # "pasted_text" | "eml_upload"
    analysis_version: str
    timestamp: str
    indicators_extracted: int


class AnalyzeResponse(BaseModel):
    case_id: str
    classification: str
    risk_score: int
    confidence: int
    signals: list[Signal] = []
    content_analysis: dict[str, Any] = {}
    headers: dict[str, Any] = {}
    authentication: AuthResult = AuthResult()
    urls: list[UrlIndicator] = []
    domains: list[DomainIntel] = []
    infrastructure: list[InfrastructureNode] = []
    relay_path: list[dict] = []
    campaign: CampaignInfo = CampaignInfo()
    evidence: EvidenceBlock
    limitations: list[str] = []
    mode: str = "live"          # "live" | "demo"
