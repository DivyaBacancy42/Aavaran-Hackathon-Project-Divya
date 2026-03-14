import asyncio
import logging
import re
import ssl
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# Common ports to probe — ordered by likelihood of being open
COMMON_PORTS = [
    # ── Web ──────────────────────────────────────────────────────────────────
    80, 443, 8080, 8443, 8000, 8888, 8001, 8081, 8082, 8083, 8086, 8099,
    9090, 9091, 3000, 4000, 4200, 5000,
    # ── Remote access ────────────────────────────────────────────────────────
    22, 23, 3389, 5900, 5901,
    # ── Mail ─────────────────────────────────────────────────────────────────
    25, 110, 143, 465, 587, 993, 995,
    # ── File / network services ───────────────────────────────────────────────
    21, 53, 445, 139, 111,
    # ── Databases ────────────────────────────────────────────────────────────
    1433, 1521, 3306, 5432, 5984, 6379, 7474, 9042, 9200, 9300, 27017, 28017,
    11211,
    # ── Message queues / streaming ────────────────────────────────────────────
    2181, 4369, 5672, 9092, 15672, 61613, 61616, 8161,
    # ── DevOps / container infra ──────────────────────────────────────────────
    2375, 2376, 4243,           # Docker daemon
    6443, 8001, 10250, 10255, 10256, 16443,  # Kubernetes
    2379, 2380, 4001,           # etcd
    8500, 8600,                 # Consul
    # ── Observability / SIEM ──────────────────────────────────────────────────
    3100, 5044, 5601, 9090, 9091, 9093, 9200, 9600,
    # ── Proxy / misc infra ────────────────────────────────────────────────────
    3128, 1080, 8118,
    # ── Big data / analytics ─────────────────────────────────────────────────
    4040, 4044, 8088, 50070, 50030,
    # ── App servers ──────────────────────────────────────────────────────────
    4848, 7001, 7002, 7777, 9990, 9999,
]
# Deduplicate while preserving order
_seen: set = set()
COMMON_PORTS = [p for p in COMMON_PORTS if not (p in _seen or _seen.add(p))]  # type: ignore[func-returns-value]
del _seen

PORT_SERVICES = {
    # Web / HTTP
    80:    "HTTP",
    443:   "HTTPS",
    8000:  "HTTP-Dev",
    8001:  "HTTP-Alt",
    8080:  "HTTP-Proxy",
    8081:  "HTTP-Alt",
    8082:  "HTTP-Alt",
    8083:  "HTTP-Alt / InfluxDB",
    8086:  "InfluxDB",
    8088:  "YARN ResourceManager",
    8099:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter / HTTP-Alt",
    9090:  "Prometheus / HTTP-Alt",
    9091:  "Prometheus Pushgateway",
    9093:  "Alertmanager",
    3000:  "Grafana / Node-Dev",
    4000:  "HTTP-Dev",
    4200:  "Angular-Dev",
    5000:  "Flask-Dev / Docker Registry",
    # Remote access
    22:    "SSH",
    23:    "Telnet",
    3389:  "RDP",
    5900:  "VNC",
    5901:  "VNC-1",
    # Mail
    25:    "SMTP",
    110:   "POP3",
    143:   "IMAP",
    465:   "SMTPS",
    587:   "SMTP-Submission",
    993:   "IMAPS",
    995:   "POP3S",
    # File / network
    21:    "FTP",
    53:    "DNS",
    111:   "RPC",
    139:   "NetBIOS",
    445:   "SMB",
    # Databases
    1433:  "MSSQL",
    1521:  "Oracle",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    5984:  "CouchDB",
    6379:  "Redis",
    7474:  "Neo4j",
    9042:  "Cassandra",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch Transport",
    11211: "Memcached",
    27017: "MongoDB",
    28017: "MongoDB HTTP",
    # Message queues
    2181:  "Zookeeper",
    4369:  "Erlang EPMD (RabbitMQ)",
    5672:  "RabbitMQ AMQP",
    8161:  "ActiveMQ Admin",
    9092:  "Kafka",
    15672: "RabbitMQ Management",
    61613: "ActiveMQ STOMP",
    61616: "ActiveMQ OpenWire",
    # Containers / orchestration
    2375:  "Docker (unencrypted)",
    2376:  "Docker TLS",
    4243:  "Docker (alt)",
    6443:  "Kubernetes API",
    8001:  "Kubernetes Proxy",
    10250: "Kubernetes Kubelet",
    10255: "Kubernetes Kubelet (read-only)",
    10256: "Kube-proxy",
    16443: "microk8s Kubernetes API",
    # etcd
    2379:  "etcd client",
    2380:  "etcd peer",
    4001:  "etcd (legacy)",
    # Service mesh / config
    8500:  "Consul HTTP",
    8600:  "Consul DNS",
    # Observability
    3100:  "Loki",
    5044:  "Logstash Beats",
    5601:  "Kibana",
    9600:  "Logstash Monitoring",
    # Proxy
    1080:  "SOCKS Proxy",
    3128:  "Squid Proxy",
    8118:  "Privoxy",
    # Big data
    4040:  "Spark UI",
    4044:  "Spark History",
    50070: "Hadoop NameNode",
    50030: "Hadoop JobTracker",
    # Java app servers
    4848:  "GlassFish Admin",
    7001:  "WebLogic",
    7002:  "WebLogic SSL",
    7777:  "WebLogic HTTP",
    9990:  "WildFly Admin",
    9999:  "JBoss / Admin",
}

# Ports that speak TLS natively — wrap with ssl context
_TLS_PORTS = {443, 465, 587, 993, 995, 2376, 6443, 7002, 8443, 10250, 16443}

# Ports where we send an HTTP HEAD probe to get a Server header
_HTTP_PROBE_PORTS = {
    80, 443, 3000, 4000, 4040, 4044, 4200, 4848, 5000, 5601, 5984,
    7001, 7002, 7474, 7777, 8000, 8001, 8080, 8081, 8082, 8083, 8086,
    8088, 8099, 8161, 8443, 8500, 8888, 9090, 9091, 9093, 9200, 9990,
    9999, 15672, 28017, 50070, 50030,
}

# Banner-read timeout (seconds) — kept short to avoid blocking scan
_BANNER_TIMEOUT = 3.0

# ── Version extraction patterns ────────────────────────────────────────────────
# Each entry: (regex, group_index_for_version)
_VERSION_PATTERNS = [
    # SSH: "SSH-2.0-OpenSSH_8.9p1"
    (re.compile(r"SSH-[\d.]+-(\S+)", re.IGNORECASE), 1),
    # FTP: "220 FileZilla Server 1.7.0"
    (re.compile(r"^220[- ].*?([\w.]+)\s+([\d.]+)", re.IGNORECASE), 2),
    # SMTP similar
    (re.compile(r"^220[- ]\S+\s+(.+?)(?:\s+ready|\s+ESMTP|$)", re.IGNORECASE), 1),
    # HTTP Server header: "nginx/1.22.1" or "Apache/2.4.54"
    (re.compile(r"Server:\s*(\S+/[\d.]+)", re.IGNORECASE), 1),
    # Redis: "+PONG" or "-ERR … Redis …"
    (re.compile(r"redis_version:([\d.]+)", re.IGNORECASE), 1),
    # Elasticsearch: "\"version\":{\"number\":\"8.6.0\""
    (re.compile(r'"number"\s*:\s*"([\d.]+)"'), 1),
    # Generic: "product/version" anywhere in banner
    (re.compile(r"([\w.\-]+)/([\d]+\.[\d]+(?:\.[\d]+)?)"), 2),
]


def _extract_version(banner: str) -> Optional[str]:
    """Try each pattern; return the first version string found."""
    for pattern, grp in _VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            try:
                ver = m.group(grp).strip()
                if ver and len(ver) < 80:
                    return ver
            except IndexError:
                continue
    return None


def _get_probe(port: int) -> Optional[bytes]:
    """Return bytes to send after connection to elicit a banner."""
    if port in _HTTP_PROBE_PORTS:
        return b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
    if port == 6379:  # Redis
        return b"PING\r\n"
    if port == 9200:  # Elasticsearch
        return b"GET / HTTP/1.0\r\n\r\n"
    return None  # Many services (SSH, FTP, SMTP) send banner unprompted


@dataclass
class OpenPort:
    hostname: str
    port_number: int
    protocol: str = "tcp"
    service: str = ""
    banner: Optional[str] = None
    version: Optional[str] = None


@dataclass
class PortScanResult:
    open_ports: List[OpenPort] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class PortScanner:
    """
    Async TCP connect scanner + service banner grabber.
    Checks COMMON_PORTS on each host; after connecting reads up to 512 bytes
    to extract the service banner and version string.
    No external tools required.
    """

    def __init__(self, hostnames: List[str], timeout: float = 1.5):
        self.hostnames = list(set(filter(None, hostnames)))
        self.timeout = timeout

    async def _check_port(self, hostname: str, port: int) -> Optional[OpenPort]:
        reader: Optional[asyncio.StreamReader] = None
        writer: Optional[asyncio.StreamWriter] = None
        try:
            # ── 1. Connect ────────────────────────────────────────────────────
            if port in _TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=ctx),
                    timeout=self.timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port),
                    timeout=self.timeout,
                )

            # ── 2. Send probe if needed ───────────────────────────────────────
            probe = _get_probe(port)
            if probe:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=1.0)

            # ── 3. Read banner (up to 512 bytes) ─────────────────────────────
            raw_banner: Optional[str] = None
            version: Optional[str] = None
            try:
                data = await asyncio.wait_for(
                    reader.read(512), timeout=_BANNER_TIMEOUT
                )
                if data:
                    raw_banner = data.decode("utf-8", errors="replace").replace("\x00", "").strip()
                    # Collapse whitespace for storage; keep first 300 chars
                    raw_banner = " ".join(raw_banner.split())[:300] or None
                    if raw_banner:
                        version = _extract_version(raw_banner)
            except asyncio.TimeoutError:
                pass  # No banner within timeout — port still open

            return OpenPort(
                hostname=hostname,
                port_number=port,
                service=PORT_SERVICES.get(port, ""),
                banner=raw_banner,
                version=version,
            )

        except Exception:
            return None
        finally:
            if writer:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass

    async def run(self) -> PortScanResult:
        result = PortScanResult()
        if not self.hostnames:
            return result

        sem = asyncio.Semaphore(40)  # Reduced from 60 — banner reads hold connections longer

        async def scan(hostname: str, port: int):
            async with sem:
                found = await self._check_port(hostname, port)
                if found:
                    result.open_ports.append(found)
                    logger.debug(
                        f"PortScanner: open {hostname}:{port} ({found.service})"
                        + (f" ver={found.version}" if found.version else "")
                    )

        tasks = [scan(h, p) for h in self.hostnames for p in COMMON_PORTS]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(
            f"PortScanner: {len(result.open_ports)} open ports "
            f"across {len(self.hostnames)} hosts"
        )
        return result
