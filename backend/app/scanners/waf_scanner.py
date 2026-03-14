import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class WAFScanResult:
    hostname: str
    detected: bool = False
    waf_name: Optional[str] = None
    manufacturer: Optional[str] = None
    error: Optional[str] = None


class WAFScanner:
    """
    Detects WAF/CDN protecting a hostname using wafw00f.
    wafw00f is run synchronously in a thread executor to avoid blocking.
    """

    def __init__(self, hostname: str, timeout: int = 10):
        self.hostname = hostname
        self.timeout = timeout

    async def run(self) -> WAFScanResult:
        result = WAFScanResult(hostname=self.hostname)
        try:
            data = await asyncio.to_thread(self._sync_detect, self.hostname, self.timeout)
            if data:
                result.detected = True
                result.waf_name = data.get("name")
                result.manufacturer = data.get("manufacturer")
                logger.debug(
                    f"WAFScanner: {self.hostname} → {result.waf_name} ({result.manufacturer})"
                )
            else:
                logger.debug(f"WAFScanner: {self.hostname} → no WAF detected")
        except Exception as e:
            result.error = str(e)
            logger.debug(f"WAFScanner error for {self.hostname}: {e}")
        return result

    @staticmethod
    def _sync_detect(hostname: str, timeout: int) -> Optional[dict]:
        """
        Synchronous wafw00f detection — runs in thread executor.
        Returns dict with name/manufacturer, or None if no WAF found.
        """
        from wafw00f.main import WAFW00F

        # Try HTTPS first, fall back to HTTP
        for scheme in ("https", "http"):
            try:
                target = f"{scheme}://{hostname}"
                waf = WAFW00F(target, timeout=timeout, debuglevel=0)
                waf_names, _ = waf.identwaf()
                if waf_names:
                    raw = waf_names[0]
                    # Format: "WAFName (Manufacturer)"
                    m = re.match(r"^(.*?)\s*\((.*?)\)$", raw)
                    if m:
                        return {"name": m.group(1).strip(), "manufacturer": m.group(2).strip()}
                    return {"name": raw.strip(), "manufacturer": None}
            except Exception:
                continue
        return None
