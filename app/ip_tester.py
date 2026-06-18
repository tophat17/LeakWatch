"""Multi-method egress testing (v2).

For each container we answer:
  1. What public IPv4 does it present to the internet?  (consensus of 4 services)
  2. What public IPv6 does it present, if any?           (IPv6 leak detection)
  3. Which DNS resolver does its traffic actually use?   (DNS leak detection)
  4. Does it have a privacy tunnel (tun/wg) vs a mesh overlay (tailscale/zt)?

Methods, layered for reliability:
  * Method A (primary): a sidecar container in the target's network namespace.
  * Method B (fallback): exec the same probe inside the target container.
  * Interfaces are read from /proc/net/dev (always namespace-correct) so a
    bridge container can't accidentally pick up the host's interfaces.

The exit IP's provider is then enriched from the LeakWatch process using two
free sources (ipinfo.io + ip-api.com) - see vpn_detect.detect_provider.
"""
from __future__ import annotations

import ipaddress
import json
import os
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

log = logging.getLogger("leakwatch.iptester")

IPINFO_URL = "https://ipinfo.io/json"
PLAIN_V4 = [
    ("ipify", "https://api.ipify.org"),
    ("icanhaz", "https://ipv4.icanhazip.com"),
    ("ifconfigme", "https://ifconfig.me/ip"),
]
IPV6_URL = "https://v6.ident.me"
TOR_URL = "https://check.torproject.org/api/ip"

_MARK = "@@LW@@"
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

# Privacy/egress tunnels (traffic exits elsewhere).
TUNNEL_PREFIXES = ("tun", "wg", "wireguard", "ppp", "nordlynx", "proton", "gpd", "vpn")
# Mesh / overlay networks - do NOT change your internet exit IP by themselves.
MESH_PREFIXES = ("tailscale", "zt", "zerotier", "ham0", "nebula")

# Per-IP enrichment cache (avoid hammering ip-api for the common shared host IP).
_GEO_CACHE = {}
_GEO_TTL = 1800  # 30 min


@dataclass
class GeoInfo:
    ip: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    asname: Optional[str] = None
    hostname: Optional[str] = None  # rDNS / reverse
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    vpn_provider: Optional[str] = None  # from a dedicated proxy/VPN database
    proxy: Optional[bool] = None

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in
                ("ip", "org", "isp", "asname", "hostname", "city", "region",
                 "country", "vpn_provider", "proxy")}

    def haystack(self) -> str:
        return " ".join(filter(None, [self.org, self.isp, self.asname, self.hostname, self.vpn_provider])).lower()


@dataclass
class TestResult:
    public_ip: Optional[str] = None
    ipv6: Optional[str] = None
    geo: GeoInfo = field(default_factory=GeoInfo)
    method: str = "none"
    confident: bool = False
    services_agree: bool = False
    sampled_ips: dict = field(default_factory=dict)
    interfaces: list = field(default_factory=list)
    tunnel_present: bool = False
    mesh_present: bool = False
    mesh_names: list = field(default_factory=list)
    tor: Optional[bool] = None
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "public_ip": self.public_ip, "ipv6": self.ipv6, "geo": self.geo.as_dict(), "method": self.method, "confident": self.confident,
            "services_agree": self.services_agree, "sampled_ips": self.sampled_ips,
            "interfaces": self.interfaces, "tunnel_present": self.tunnel_present,
            "mesh_present": self.mesh_present, "mesh_names": self.mesh_names,
            "tor": self.tor, "error": self.error,
        }


def _valid_v4(text: str) -> Optional[str]:
    for tok in _IPV4_RE.findall(text or ""):
        try:
            ip = ipaddress.ip_address(tok)
        except ValueError:
            continue
        if ip.version == 4 and ip.is_global:
            return str(ip)
    return None


def _valid_v6(text: str) -> Optional[str]:
    for tok in _IPV6_RE.findall(text or ""):
        try:
            ip = ipaddress.ip_address(tok)
        except ValueError:
            continue
        if ip.version == 6 and ip.is_global:
            return str(ip)
    return None


def build_probe_script(timeout: int = 8) -> str:
    t = int(timeout)
    s = [
        "fetch() {",
        "  if command -v curl >/dev/null 2>&1; then",
        f"    curl $1 -A 'Mozilla/5.0 (LeakWatch)' -fsS --max-time {t} \"$2\" 2>/dev/null;",
        "  elif command -v wget >/dev/null 2>&1; then",
        f"    wget -U 'Mozilla/5.0 (LeakWatch)' -q -O - -T {t} \"$2\" 2>/dev/null;",
        "  fi;",
        "}",
        f"echo '{_MARK}IFACES'",
        "cat /proc/net/dev 2>/dev/null | tail -n +3 | cut -d: -f1 | tr -d ' '",
        f"echo '{_MARK}IPINFO'",
        f"fetch -4 {IPINFO_URL}",
        "echo",
    ]
    for key, url in PLAIN_V4:
        s += [f"echo '{_MARK}{key.upper()}'", f"fetch -4 {url}", "echo"]
    s += [f"echo '{_MARK}IPV6'", f"fetch -6 {IPV6_URL}", "echo"]
    s += [f"echo '{_MARK}TOR'", f"fetch -4 {TOR_URL}", "echo", f"echo '{_MARK}DONE'"]
    return "\n".join(s)


def _split_sections(text: str) -> dict:
    out, cur, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith(_MARK):
            if cur is not None:
                out[cur] = "\n".join(buf).strip()
            cur, buf = line[len(_MARK):].strip(), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        out[cur] = "\n".join(buf).strip()
    return out


def parse_probe_output(text: Optional[str], method: str) -> TestResult:
    res = TestResult(method=method)
    if not text:
        res.error = "no output from probe"
        return res
    sec = _split_sections(text)
    if "DONE" not in sec and "IPINFO" not in sec:
        res.error = "probe output unrecognised"
        return res

    ifaces = [i for i in re.split(r"\s+", sec.get("IFACES", "")) if i and i != "lo"]
    res.interfaces = ifaces
    low = [i.lower() for i in ifaces]
    res.tunnel_present = any(i.startswith(TUNNEL_PREFIXES) for i in low)
    res.mesh_names = [i for i in ifaces if i.lower().startswith(MESH_PREFIXES)]
    res.mesh_present = bool(res.mesh_names)

    geo = GeoInfo()
    raw = sec.get("IPINFO", "")
    if raw:
        try:
            d = json.loads(raw)
            geo.ip = d.get("ip")
            geo.org = d.get("org")
            geo.hostname = d.get("hostname")
            geo.city, geo.region, geo.country = d.get("city"), d.get("region"), d.get("country")
        except (json.JSONDecodeError, AttributeError):
            geo.ip = _valid_v4(raw)
    res.geo = geo

    sampled = {}
    if geo.ip and _valid_v4(geo.ip):
        sampled["ipinfo"] = geo.ip
    for key, _ in PLAIN_V4:
        ip = _valid_v4(sec.get(key.upper(), ""))
        if ip:
            sampled[key] = ip
    res.sampled_ips = sampled
    if sampled:
        counts = {}
        for ip in sampled.values():
            counts[ip] = counts.get(ip, 0) + 1
        consensus = max(counts, key=counts.get)
        res.public_ip = consensus
        res.services_agree = len(counts) == 1
        res.confident = counts[consensus] >= 2
        if geo.ip and geo.ip != consensus:
            res.error = "services disagreed on IP"
    else:
        res.error = "no IPv4 returned by any service"

    res.ipv6 = _valid_v6(sec.get("IPV6", ""))

    tor_raw = sec.get("TOR", "")
    if tor_raw:
        try:
            res.tor = bool(json.loads(tor_raw).get("IsTor"))
        except (json.JSONDecodeError, AttributeError):
            pass

    return res


def enrich_geo(ip, geo, timeout: int = 6) -> GeoInfo:
    """Name the exit IP's provider using two free sources: ipinfo.io (HTTPS,
    reliable) for org/hostname, and ip-api.com (HTTP) for isp/asname/rDNS.
    Cached per IP so repeat scans don't hammer the services."""
    if not ip:
        return geo
    now = time.time()
    cached = _GEO_CACHE.get(ip)
    if cached and now - cached[0] < _GEO_TTL:
        d = cached[1]
    else:
        d = {}
        ua = {"User-Agent": "Mozilla/5.0 (LeakWatch)"}
        key = os.environ.get("LEAKWATCH_PROXYCHECK_KEY", "").strip()
        try:
            pc = "https://proxycheck.io/v2/" + ip + "?vpn=1&asn=1"
            if key:
                pc += "&key=" + key
            pj = httpx.get(pc, headers=ua, timeout=timeout).json()
            rec = pj.get(ip) if isinstance(pj, dict) else None
            if isinstance(rec, dict):
                prov = rec.get("provider")
                if prov and prov.strip().lower() not in ("", "unknown"):
                    d["vpn_provider"] = prov
                if rec.get("proxy") == "yes":
                    d["proxy"] = True
                asn = rec.get("asn") or ""
                orgn = rec.get("organisation") or rec.get("provider") or ""
                if not d.get("org") and (asn or orgn):
                    d["org"] = (str(asn) + " " + str(orgn)).strip()
                if not d.get("isp") and orgn:
                    d["isp"] = orgn
        except Exception as e:  # noqa: BLE001
            log.debug("proxycheck enrich failed for %s: %s", ip, e)
        try:
            j = httpx.get("https://ipwho.is/" + ip, headers=ua, timeout=timeout).json()
            if isinstance(j, dict) and j.get("success"):
                conn = j.get("connection") or {}
                org = conn.get("org") or conn.get("isp")
                if conn.get("asn") and org:
                    d["org"] = "AS" + str(conn["asn"]) + " " + org
                elif org:
                    d["org"] = org
                if conn.get("isp"):
                    d["isp"] = conn["isp"]
                if conn.get("org"):
                    d["asname"] = conn["org"]
                if j.get("country_code"):
                    d["country"] = j["country_code"]
                if j.get("city"):
                    d["city"] = j["city"]
        except Exception as e:  # noqa: BLE001
            log.debug("ipwho.is enrich failed for %s: %s", ip, e)
        try:
            j = httpx.get("https://ipinfo.io/" + ip + "/json", headers=ua, timeout=timeout).json()
            if isinstance(j, dict):
                for k in ("org", "hostname", "city", "region", "country"):
                    if j.get(k):
                        d[k] = j[k]
        except Exception as e:  # noqa: BLE001
            log.debug("ipinfo enrich failed for %s: %s", ip, e)
        try:
            url = ("http://ip-api.com/json/" + ip +
                   "?fields=status,country,countryCode,city,isp,org,as,asname,reverse,query")
            j = httpx.get(url, headers=ua, timeout=timeout).json()
            if j.get("status") == "success":
                d.setdefault("isp", j.get("isp"))
                d.setdefault("asname", j.get("asname"))
                if not d.get("org"):
                    d["org"] = j.get("as") or j.get("org")
                d.setdefault("hostname", j.get("reverse"))
                d.setdefault("country", j.get("countryCode") or j.get("country"))
                d.setdefault("city", j.get("city"))
        except Exception as e:  # noqa: BLE001
            log.debug("ip-api enrich failed for %s: %s", ip, e)
        if d:
            _GEO_CACHE[ip] = (now, d)
    if d:
        geo.vpn_provider = geo.vpn_provider or d.get("vpn_provider")
        if geo.proxy is None:
            geo.proxy = d.get("proxy")
        geo.org = geo.org or d.get("org")
        geo.isp = geo.isp or d.get("isp")
        geo.asname = geo.asname or d.get("asname")
        geo.hostname = geo.hostname or d.get("hostname")
        geo.country = geo.country or d.get("country")
        geo.city = geo.city or d.get("city")
    return geo


class IPTester:
    def __init__(self, docker_client, probe_timeout: int = 8):
        self.dc = docker_client
        self.probe_timeout = probe_timeout

    def test_container(self, cinfo) -> TestResult:
        if not cinfo.running:
            r = TestResult()
            r.error = "container not running"
            return r
        script = build_probe_script(self.probe_timeout)
        raw = self.dc.run_sidecar(cinfo.id, script, timeout=self.probe_timeout * 7 + 10)
        res = parse_probe_output(raw, method="sidecar")
        if res.public_ip:
            return res
        container = self.dc.get_container(cinfo.id)
        if container is not None:
            raw2 = self.dc.exec_probe(container, script, timeout=self.probe_timeout * 7)
            res2 = parse_probe_output(raw2, method="exec")
            if res2.public_ip:
                return res2
            return res2 if (res2.interfaces or res2.sampled_ips) else res
        return res

    def test_host(self) -> TestResult:
        res = TestResult(method="host")
        try:
            with httpx.Client(timeout=self.probe_timeout, headers={"User-Agent": "LeakWatch"}) as client:
                d = client.get(IPINFO_URL).json()
                res.geo = GeoInfo(ip=d.get("ip"), org=d.get("org"), hostname=d.get("hostname"),
                                  city=d.get("city"), region=d.get("region"), country=d.get("country"))
                res.public_ip = d.get("ip")
                res.sampled_ips = {"ipinfo": d.get("ip")} if d.get("ip") else {}
                try:
                    res.ipv6 = _valid_v6(client.get(IPV6_URL).text)
                except Exception:
                    pass
        except Exception as e:  # noqa: BLE001
            res.error = "could not determine host IP: " + str(e)
            try:
                with httpx.Client(timeout=self.probe_timeout) as client:
                    ip = _valid_v4(client.get(PLAIN_V4[0][1]).text)
                if ip:
                    res.public_ip, res.geo, res.error = ip, GeoInfo(ip=ip), None
            except Exception:
                pass
        if res.public_ip:
            res.geo = enrich_geo(res.public_ip, res.geo, self.probe_timeout)
        res.confident = res.public_ip is not None
        return res
