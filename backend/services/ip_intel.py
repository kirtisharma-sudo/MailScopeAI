"""
IMPORTANT: geolocation and network intelligence returned here are CONTEXTUAL
evidence about observed infrastructure — never an attacker's identity or
location. All external calls degrade to "unavailable" on failure/missing key.
"""
import ipaddress
import requests
from config import get_settings

settings = get_settings()
_UNAVAILABLE = "unavailable"


def is_plausible_ip(ip: str) -> bool:
    """Cheap local validation before spending a network round-trip."""
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def _ipinfo(ip: str) -> dict | str:
    if not settings.IPINFO_TOKEN:
        return _UNAVAILABLE
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}", params={"token": settings.IPINFO_TOKEN}, timeout=5)
        if resp.status_code == 200:
            return resp.json()
        return _UNAVAILABLE
    except Exception:
        return _UNAVAILABLE


def _abuseipdb(ip: str) -> dict | str:
    if not settings.ABUSEIPDB_API_KEY:
        return _UNAVAILABLE
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip},
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json().get("data", {})
        return _UNAVAILABLE
    except Exception:
        return _UNAVAILABLE


def _build_interpretation(country, hosting, vpn_hint, reputation) -> list[dict]:
    notes = []
    if country != _UNAVAILABLE and country:
        notes.append({
            "observation": f"Observed infrastructure geolocates approximately to {country}.",
            "interpretation": "This reflects the network infrastructure's registered/observed location, not the identity or physical location of any individual.",
        })
    if hosting not in (_UNAVAILABLE, None, False):
        notes.append({
            "observation": "Observed IP is associated with cloud/hosting infrastructure.",
            "interpretation": "Cloud-hosted infrastructure is shared by many unrelated tenants and may reduce confidence in any direct attribution.",
        })
    if vpn_hint == "yes":
        notes.append({
            "observation": "Observed IP is flagged as VPN/proxy/Tor infrastructure by the lookup provider.",
            "interpretation": "This can obscure the true origin of a message and is contextual evidence, not proof of intent.",
        })
    if isinstance(reputation, dict) and reputation.get("abuseConfidenceScore", 0) and reputation["abuseConfidenceScore"] >= 50:
        notes.append({
            "observation": f"Third-party abuse confidence score is {reputation['abuseConfidenceScore']}%.",
            "interpretation": "Elevated abuse reports are contextual evidence and should be combined with header/content/URL findings, not used alone.",
        })
    return notes


def gather_ip_intel(ip: str) -> dict:
    if not is_plausible_ip(ip):
        return {
            "ip": ip, "asn": _UNAVAILABLE, "isp": _UNAVAILABLE, "country": _UNAVAILABLE,
            "region": _UNAVAILABLE, "city": _UNAVAILABLE, "hosting": _UNAVAILABLE,
            "vpn_proxy_tor": _UNAVAILABLE, "reputation": _UNAVAILABLE, "role": "observed_relay",
            "interpretation": [], "note": "Value failed basic IP-address format validation; no external lookups were attempted.",
        }

    info = _ipinfo(ip)
    abuse = _abuseipdb(ip)

    country = info.get("country") if isinstance(info, dict) else _UNAVAILABLE
    region = info.get("region") if isinstance(info, dict) else _UNAVAILABLE
    city = info.get("city") if isinstance(info, dict) else _UNAVAILABLE
    org = info.get("org") if isinstance(info, dict) else _UNAVAILABLE
    asn = org.split(" ")[0] if isinstance(org, str) and org.startswith("AS") else _UNAVAILABLE
    isp = " ".join(org.split(" ")[1:]) if isinstance(org, str) and org.startswith("AS") else (org or _UNAVAILABLE)

    hosting = (info.get("privacy", {}).get("hosting") if isinstance(info, dict) and "privacy" in info else _UNAVAILABLE)
    vpn_hint = _UNAVAILABLE
    if isinstance(info, dict) and "privacy" in info:
        p = info["privacy"]
        vpn_hint = "yes" if any(p.get(k) for k in ("vpn", "proxy", "tor")) else "no"

    return {
        "ip": ip,
        "asn": asn,
        "isp": isp,
        "country": country,
        "region": region,
        "city": city,
        "hosting": hosting,
        "vpn_proxy_tor": vpn_hint,
        "reputation": abuse,
        "role": "observed_relay",
        "interpretation": _build_interpretation(country, hosting, vpn_hint, abuse),
        "note": "Geolocation reflects the approximate location of the observed network infrastructure, "
                "not the identity or location of any individual.",
    }


def network_signals(infra: list[dict]) -> list[dict]:
    signals = []
    for node in infra:
        rep = node.get("reputation")
        if isinstance(rep, dict) and rep.get("abuseConfidenceScore", 0) and rep["abuseConfidenceScore"] >= 50:
            signals.append({
                "name": "ip_abuse_reports",
                "severity": "medium",
                "weight": 10,
                "explanation": f"Observed IP {node['ip']} has a third-party abuse confidence score of {rep['abuseConfidenceScore']}%.",
            })
        if node.get("vpn_proxy_tor") == "yes":
            signals.append({
                "name": "vpn_proxy_tor_infrastructure",
                "severity": "low",
                "weight": 5,
                "explanation": f"Observed IP {node['ip']} is flagged as VPN/proxy/Tor infrastructure by the lookup provider.",
            })
    return signals
