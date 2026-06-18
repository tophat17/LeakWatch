"""Free, no-API-key VPN / provider identification (v2).

Matches against a combined haystack of every free signal we have for the exit
IP: ipinfo `org`, ip-api `isp` / `asname` / `org`, and reverse DNS. Order of
confidence:

  1. Mesh overlay (Tailscale, ZeroTier...) -> NOT a privacy VPN. confidence=mesh
  2. Known commercial VPN brand            -> confidence=confirmed
  3. Known VPN-hosting datacenter          -> confidence=likely
  4. Generic hosting / datacenter          -> confidence=hosting
  5. Nothing matched (residential ISP)     -> confidence=unknown
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ProviderResult:
    name: Optional[str] = None
    confidence: str = "unknown"   # mesh | confirmed | likely | hosting | unknown
    is_known_vpn: bool = False
    is_mesh: bool = False
    is_hosting: bool = False
    asn: Optional[str] = None
    detail: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "name": self.name, "confidence": self.confidence,
            "is_known_vpn": self.is_known_vpn, "is_mesh": self.is_mesh,
            "is_hosting": self.is_hosting, "asn": self.asn, "detail": self.detail,
        }


# Mesh / overlay networks they don't anonymise your internet exit.
MESH = {
    "Tailscale": ["tailscale", "ts.net"],
    "ZeroTier": ["zerotier"],
    "Headscale": ["headscale"],
    "Nebula": ["defined networking", "nebula mesh"],
}

# name -> (asn_numbers, keyword list matched against org/isp/asname/rDNS)
PROVIDERS: dict[str, dict] = {
    "Mullvad":           {"asn": {39351}, "kw": ["31173 services", "mullvad"]},
    "NordVPN":           {"asn": {136787, 200651}, "kw": ["tefincom", "nordvpn", "nordlynx", "nord security"]},
    "ProtonVPN":         {"asn": {62371, 209103}, "kw": ["proton ag", "protonvpn", "proton technologies", "proton"]},
    "Private Internet Access": {"asn": set(), "kw": ["private internet access", "london trust media", "privateinternetaccess"]},
    "Surfshark":         {"asn": {209854}, "kw": ["surfshark"]},
    "ExpressVPN":        {"asn": set(), "kw": ["express vpn", "expressvpn"]},
    "CyberGhost":        {"asn": set(), "kw": ["cyberghost"]},
    "AirVPN":            {"asn": set(), "kw": ["airvpn", "airdns"]},
    "IVPN":              {"asn": set(), "kw": ["ivpn"]},
    "TorGuard":          {"asn": set(), "kw": ["torguard", "vpnetworks"]},
    "Windscribe":        {"asn": set(), "kw": ["windscribe"]},
    "VyprVPN":           {"asn": set(), "kw": ["golden frog", "vyprvpn"]},
    "PureVPN":           {"asn": set(), "kw": ["purevpn", "gz systems"]},
    "hide.me":           {"asn": set(), "kw": ["hide.me", "hideservers", "eventure"]},
    "TunnelBear":        {"asn": set(), "kw": ["tunnelbear"]},
    "PrivadoVPN":        {"asn": set(), "kw": ["privado"]},
    "AzireVPN":          {"asn": set(), "kw": ["azirevpn", "netbouncer"]},
    "Perfect Privacy":   {"asn": set(), "kw": ["perfect privacy"]},
    "Hotspot Shield":    {"asn": set(), "kw": ["anchorfree", "pango", "hotspotshield"]},
    "OVPN":              {"asn": set(), "kw": ["ovpn integritet", "ovpn.com"]},
    "Hide My Ass":       {"asn": set(), "kw": ["hidemyass", "privax"]},
    "Mozilla VPN":       {"asn": {39351}, "kw": ["mozilla vpn"]},
}

# Datacenters that overwhelmingly host VPN/proxy exit nodes.
VPN_HOSTING_ASN = {9009: "M247", 60068: "Datacamp/CDN77", 212238: "Datacamp",
                   206092: "PacketHub", 213035: "Datacamp", 9304: "HGC"}
VPN_HOSTING_KW = ["m247", "datacamp", "packethub", "cdn77", "datapacket",
                  "clouvider", "zenlayer", "flokinet", "xtom", "31173",
                  "the constant company", "constant company", "global layer",
                  "gsl networks", "creanova", "tzulo", "hostroyale",
                  "cyberzone", "diamond ip brokers"]

HOSTING_KW = ["hosting", "datacenter", "data center", "colo", "vps", "dedicated",
              "server", "cloud", "ovh", "hetzner", "digitalocean", "linode",
              "vultr", "amazon", "aws", "google llc", "microsoft", "azure",
              "choopa", "quadranet", "psychz", "leaseweb", "i3d", "worldstream"]


def _asn(geo) -> tuple[Optional[int], Optional[str]]:
    for src in (getattr(geo, "org", None), getattr(geo, "asname", None)):
        if src:
            m = re.search(r"AS(\d+)", src, re.IGNORECASE)
            if m:
                return int(m.group(1)), f"AS{m.group(1)}"
    return None, None


def detect_provider(geo) -> ProviderResult:
    hay = geo.haystack() if hasattr(geo, "haystack") else (getattr(geo, "org", "") or "").lower()
    asn_num, asn_str = _asn(geo)
    res = ProviderResult(asn=asn_str)

    # 0) Authoritative proxy/VPN database (e.g. proxycheck.io) named the brand
    vp = getattr(geo, "vpn_provider", None)
    if vp and vp.strip().lower() not in ("", "unknown"):
        return ProviderResult(name=vp, confidence="confirmed", is_known_vpn=True,
                              is_hosting=True, asn=asn_str, detail="proxy database: " + vp)

    # 1) Mesh overlay
    for name, kws in MESH.items():
        if any(k in hay for k in kws):
            return ProviderResult(name=name, confidence="mesh", is_mesh=True,
                                  asn=asn_str, detail=f"mesh overlay ({name})")

    # 2) Known VPN brand
    for name, rules in PROVIDERS.items():
        if asn_num is not None and asn_num in rules["asn"]:
            return ProviderResult(name=name, confidence="confirmed", is_known_vpn=True,
                                  is_hosting=True, asn=asn_str, detail=f"ASN {asn_str} = {name}")
        for kw in rules["kw"]:
            if kw in hay:
                return ProviderResult(name=name, confidence="confirmed", is_known_vpn=True,
                                      is_hosting=True, asn=asn_str, detail=f"matched '{kw}'")

    # 3) Known VPN-hosting datacenter
    if asn_num is not None and asn_num in VPN_HOSTING_ASN:
        lab = VPN_HOSTING_ASN[asn_num]
        return ProviderResult(name=f"{lab} (VPN/proxy host)", confidence="likely",
                              is_known_vpn=True, is_hosting=True, asn=asn_str,
                              detail=f"{asn_str} is a known VPN-hosting network")
    for kw in VPN_HOSTING_KW:
        if kw in hay:
            return ProviderResult(name=f"{kw.title()} (VPN/proxy host)", confidence="likely",
                                  is_known_vpn=True, is_hosting=True, asn=asn_str,
                                  detail=f"matched VPN-hosting keyword '{kw}'")

    # 3b) Detection DB flagged it as a VPN/proxy but gave no brand name
    if getattr(geo, "proxy", None):
        return ProviderResult(name="VPN / proxy", confidence="likely", is_known_vpn=True,
                              is_hosting=True, asn=asn_str,
                              detail="flagged as a VPN/proxy by a detection database")

    # 4) Generic hosting / datacenter
    for kw in HOSTING_KW:
        if kw in hay:
            res.is_hosting = True
            res.confidence = "hosting"
            res.detail = f"datacenter/hosting ('{kw}')"
            return res

    # 5) Residential / unknown
    res.confidence = "unknown"
    res.detail = "no VPN/hosting signature (looks residential)"
    return res
