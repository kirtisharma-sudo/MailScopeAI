"""
Parses the ACTUAL `Authentication-Results` header(s) for SPF/DKIM/DMARC
verdicts. States are explicit and never conflated:

  pass / fail / neutral / softfail / temperror / permerror  -> an actual verdict was reported
  none        -> Authentication-Results WAS present, but did not report a
                 verdict for this mechanism (e.g. no SPF record published)
  unavailable -> no Authentication-Results header was present AT ALL, so
                 nothing could be evaluated — this is NOT the same as "fail"
                 and must never be scored as if it were (see risk_engine.py)
  unknown     -> Authentication-Results was present but couldn't be parsed

A single failing mechanism never triggers a phishing verdict on its own;
that combination happens later in risk_engine.py.
"""
import re
from services.email_parser import ParsedEmail

_SPF_RE = re.compile(r"spf=(pass|fail|neutral|softfail|none|temperror|permerror)", re.I)
_DKIM_RE = re.compile(r"dkim=(pass|fail|none|neutral|temperror|permerror)", re.I)
_DMARC_RE = re.compile(r"dmarc=(pass|fail|none|temperror|permerror)", re.I)
_DKIM_DOMAIN_RE = re.compile(r"dkim=\w+.*?header\.d=([\w.\-]+)", re.I)
_SPF_DOMAIN_RE = re.compile(r"spf=\w+.*?smtp\.mailfrom=([\w.\-@]+)", re.I)


def analyze_authentication(parsed: ParsedEmail) -> dict:
    combined = " ".join(parsed.authentication_results)

    def _first(pattern: re.Pattern) -> str | None:
        m = pattern.search(combined)
        return m.group(1).lower() if m else None

    if not parsed.authentication_results:
        spf = dkim = dmarc = "unavailable"
    else:
        spf = _first(_SPF_RE) or "unknown"
        dkim = _first(_DKIM_RE) or "unknown"
        dmarc = _first(_DMARC_RE) or "unknown"

    dkim_domain_match = _DKIM_DOMAIN_RE.search(combined)
    dkim_domain = dkim_domain_match.group(1).lower() if dkim_domain_match else None

    from_domain = None
    if parsed.from_addr and "@" in parsed.from_addr:
        from_domain = parsed.from_addr.split("@")[-1].strip().strip(">").lower()

    alignment_issue = None
    if dkim_domain and from_domain and dkim_domain != from_domain:
        alignment_issue = f"DKIM d= domain ('{dkim_domain}') does not align with the From domain ('{from_domain}')."

    def _details(mechanism: str, status: str) -> str:
        if status == "unavailable":
            return f"No Authentication-Results header was present, so {mechanism.upper()} could not be evaluated. This is NOT a failure — it is missing information."
        if status == "none":
            return f"Authentication-Results was present but reported no {mechanism.upper()} result."
        if status == "unknown":
            return f"Authentication-Results was present but no recognizable {mechanism.upper()} verdict could be parsed from it."
        return f"{mechanism.upper()} evaluated to '{status}' by the receiving mail server (as reported in Authentication-Results)."

    return {
        # --- existing top-level fields (unchanged shape/consumers) ---
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "alignment_issue": alignment_issue,
        "raw_authentication_results": parsed.authentication_results or "not_present",
        # --- additive structured detail (SECTION 6), does not replace the above ---
        "spf_details": _details("spf", spf),
        "dkim_details": _details("dkim", dkim),
        "dmarc_details": _details("dmarc", dmarc),
        "note": "Authentication results are one input among several; SPF/DKIM/DMARC failure alone does not imply phishing, "
                "and a DMARC pass alone does not imply legitimacy. Missing authentication data ('unavailable') is not treated as a failure.",
    }


def auth_signals(auth: dict) -> list[dict]:
    """Each ACTUAL failing mechanism contributes a modest, explainable
    signal. Missing/unavailable authentication data contributes ZERO risk
    weight — see requirement: 'missing authentication must NOT automatically
    become FAIL'. Its absence is instead surfaced as a limitation
    (reduces confidence, not risk_score) by the caller in routes/analyze.py."""
    signals = []
    if auth["spf"] == "fail":
        signals.append({"name": "spf_fail", "severity": "medium", "weight": 8,
                         "explanation": "SPF check failed for the sending domain."})
    if auth["dkim"] == "fail":
        signals.append({"name": "dkim_fail", "severity": "medium", "weight": 8,
                         "explanation": "DKIM signature verification failed."})
    if auth["dmarc"] == "fail":
        signals.append({"name": "dmarc_fail", "severity": "high", "weight": 12,
                         "explanation": "DMARC policy evaluation failed, indicating SPF/DKIM did not align with the From domain."})
    if auth["alignment_issue"]:
        signals.append({"name": "dkim_alignment_issue", "severity": "medium", "weight": 7,
                         "explanation": auth["alignment_issue"]})
    return signals
