"""
Feature #9 — AlienVault OTX Threat Intelligence
Checks if the domain appears in threat actor reports, malware campaigns, or C2 infrastructure.
Uses the OTX public API (no key required for domain/general endpoint).
"""
import logging
from dataclasses import dataclass, field
from typing import Optional, List

import httpx

logger = logging.getLogger(__name__)


@dataclass
class OTXResult:
    pulse_count: int = 0
    threat_types: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    adversaries: List[str] = field(default_factory=list)
    country: Optional[str] = None
    first_seen: Optional[str] = None
    alexa_rank: Optional[int] = None
    is_known_malicious: bool = False
    error: Optional[str] = None


class OTXScanner:
    """
    AlienVault OTX threat correlation.
    Returns pulse_count > 0 if domain has appeared in threat intel reports.
    A high pulse_count strongly indicates malicious use (C2, phishing, malware).
    """
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators/domain"

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self) -> OTXResult:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.BASE_URL}/{self.domain}/general",
                    headers={
                        "User-Agent": "Mozilla/5.0 (compatible; SHODH/1.0)",
                        "Accept": "application/json",
                    },
                    timeout=25.0,
                )
                if resp.status_code == 404:
                    return OTXResult(pulse_count=0, is_known_malicious=False)
                if resp.status_code != 200:
                    return OTXResult(error=f"OTX API returned HTTP {resp.status_code}")

                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                pulse_count = pulse_info.get("count", len(pulses))

                # Tags → threat types
                threat_types = list(dict.fromkeys(
                    tag.lower()
                    for pulse in pulses
                    for tag in pulse.get("tags", [])
                    if tag
                ))[:15]

                # Malware families
                malware_families = list(dict.fromkeys(
                    m.get("display_name") or m.get("id", "")
                    for pulse in pulses
                    for m in pulse.get("malware_families", [])
                    if m.get("display_name") or m.get("id")
                ))[:10]

                # Adversaries / threat actor names
                adversaries = list(dict.fromkeys(
                    a.get("display_name") or a.get("id", "")
                    for pulse in pulses
                    for a in (pulse.get("adversary") if isinstance(pulse.get("adversary"), list) else [])
                    if isinstance(a, dict) and (a.get("display_name") or a.get("id"))
                ))[:10]

                # Alexa rank (can be None or 0)
                alexa_raw = data.get("alexa")
                alexa_rank: Optional[int] = None
                if isinstance(alexa_raw, int) and alexa_raw > 0:
                    alexa_rank = alexa_raw
                elif isinstance(alexa_raw, str) and alexa_raw.isdigit():
                    alexa_rank = int(alexa_raw)

                return OTXResult(
                    pulse_count=pulse_count,
                    threat_types=threat_types,
                    malware_families=malware_families,
                    adversaries=adversaries,
                    country=data.get("country_name"),
                    first_seen=data.get("first_seen"),
                    alexa_rank=alexa_rank,
                    is_known_malicious=pulse_count > 0,
                )
        except Exception as exc:
            logger.error(f"OTXScanner error for {self.domain}: {exc}")
            return OTXResult(error=str(exc))
