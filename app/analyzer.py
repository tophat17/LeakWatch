"""Verdict logic (v3.2): status / severity / message + per-container CHECK LIST,
driven by the app knowledge base. 'Protected' = an app that should use a VPN and
is confirmed to be doing so. (DNS-leak check removed.)

Statuses : OK | WARNING | CRITICAL | UNKNOWN | IGNORED
Behaviour: server_ip | different_ip | untestable
Rules    : auto | vpn | server | ignore
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app_catalog import (LEVEL_CRITICAL, LEVEL_GATEWAY, LEVEL_RECOMMENDED,
                         LEVEL_SERVER, lookup)
from vpn_detect import ProviderResult, detect_provider

RULE_AUTO, RULE_VPN, RULE_SERVER, RULE_IGNORE = "auto", "vpn", "server", "ignore"
VALID_RULES = {RULE_AUTO, RULE_VPN, RULE_SERVER, RULE_IGNORE}

STATUS_OK, STATUS_WARNING, STATUS_CRITICAL = "OK", "WARNING", "CRITICAL"
STATUS_UNKNOWN, STATUS_IGNORED = "UNKNOWN", "IGNORED"


@dataclass
class Verdict:
    status: str = STATUS_UNKNOWN
    behavior: str = "untestable"
    result_label: str = "Unable to Test"
    expected: str = "none"
    leaking: bool = False
    protected: bool = False
    ipv6_leak: bool = False
    on_critical_list: bool = False
    provider: ProviderResult = field(default_factory=ProviderResult)
    message: str = ""
    notes: list = field(default_factory=list)
    checks: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "status": self.status, "behavior": self.behavior,
            "result_label": self.result_label, "expected": self.expected,
            "leaking": self.leaking, "protected": self.protected,
            "ipv6_leak": self.ipv6_leak, "on_critical_list": self.on_critical_list,
            "provider": self.provider.as_dict(), "message": self.message,
            "notes": self.notes, "checks": self.checks,
        }


def is_on_critical_list(name: str, image: str) -> bool:
    return lookup(name, image).level == LEVEL_CRITICAL


def _provider_label(p: ProviderResult) -> str:
    if p.name:
        return p.name
    if p.confidence == "hosting":
        return "datacenter IP"
    return "unknown network"


def _check_ipv6_leak(test, host_ipv6):
    cv6 = getattr(test, "ipv6", None)
    if not cv6:
        return False, None
    if host_ipv6 and cv6 == host_ipv6:
        return True, "IPv6 egress " + str(cv6) + " matches the host - IPv6 is leaking outside the tunnel."
    return False, None


def _build_checks(expected, same, pub, test, provider, ipv6_leak):
    """List of {id,label,status,detail}. status: pass|fail|warn|info|skip.
    Pass/fail is judged relative to whether the app should be on a VPN."""
    out = []

    def add(cid, label, status, detail):
        out.append({"id": cid, "label": label, "status": status, "detail": detail})

    if not pub:
        add("reachable", "Internet reachable", "fail",
            "Could not determine a public IP for this container.")
        return out
    add("reachable", "Internet reachable", "pass",
        "Found a public IP for this container (" + pub + ").")

    if test.confident:
        add("crosscheck", "Multiple sources agree", "pass",
            "Two or more independent IP services returned the same address.")
    else:
        add("crosscheck", "Multiple sources agree", "warn",
            "Only one IP service responded; result is lower-confidence.")

    if expected == "vpn":
        if not same:
            add("ip_vs_server", "Exit IP differs from your server", "pass",
                "Good - traffic leaves on a different IP than your home/server.")
        else:
            add("ip_vs_server", "Exit IP differs from your server", "fail",
                "This app is using your server's real public IP - it is NOT on a VPN.")
    elif expected == "server":
        if same:
            add("ip_vs_server", "Using your server IP", "pass",
                "Correct - this app should use your normal connection.")
        else:
            add("ip_vs_server", "Using your server IP", "warn",
                "Using a different IP than your server; a VPN left on by mistake can break this app.")
    else:
        add("ip_vs_server", "Exit IP vs server", "info",
            "Same as your server IP." if same else "Different from your server IP.")

    if not same:
        if provider.is_known_vpn and provider.name:
            add("provider", "Recognised VPN provider", "pass",
                "Exit IP belongs to " + provider.name + ".")
        elif provider.is_hosting:
            add("provider", "Recognised VPN provider", "warn",
                "Exit is a datacenter IP (likely a VPN) but the brand could not be confirmed.")
        else:
            add("provider", "Recognised VPN provider",
                "warn" if expected == "vpn" else "info",
                "Exit looks residential; no VPN brand recognised.")

    if getattr(test, "tunnel_present", False):
        add("tunnel", "VPN tunnel interface present", "pass",
            "A tun/wg tunnel interface was detected in this container's network.")
    elif expected == "vpn":
        add("tunnel", "VPN tunnel interface present", "info",
            "No tun/wg interface seen (fine if it routes through another VPN container).")

    if getattr(test, "mesh_present", False):
        add("mesh", "Mesh overlay detected", "info",
            "Mesh network (" + ", ".join(test.mesh_names) + ") found - this does NOT change your internet exit IP.")

    v6 = getattr(test, "ipv6", None)
    if expected == "vpn":
        if v6:
            if ipv6_leak:
                add("ipv6", "IPv6 not leaking", "fail",
                    "IPv6 traffic (" + v6 + ") is bypassing the VPN.")
            else:
                add("ipv6", "IPv6 not leaking", "pass",
                    "IPv6 (" + v6 + ") is not your server's address.")
        else:
            add("ipv6", "IPv6 not leaking", "pass", "No IPv6 egress (nothing to leak).")
    elif v6:
        add("ipv6", "IPv6 in use", "info", "IPv6 egress: " + v6)

    tor = getattr(test, "tor", None)
    if tor is True:
        add("tor", "Tor exit node", "warn",
            "This exit is a Tor node - unusual for a container; verify it's intended.")
    elif tor is False:
        add("tor", "Not a Tor exit", "pass", "Exit is not a Tor node.")

    return out


def analyze(cinfo, host, test_result, rule: str = RULE_AUTO) -> Verdict:
    host = host or {}
    host_ip = host.get("public_ip")
    host_ipv6 = host.get("ipv6")

    name = cinfo.name
    app = lookup(name, cinfo.image)
    level = app.level
    crit = level in (LEVEL_CRITICAL, LEVEL_GATEWAY)
    v = Verdict(on_critical_list=(level == LEVEL_CRITICAL))
    rule = rule if rule in VALID_RULES else RULE_AUTO

    if rule == RULE_IGNORE:
        v.status, v.result_label = STATUS_IGNORED, "Ignored"
        v.message = name + " is ignored."
        return v

    if rule == RULE_VPN:
        expected = "vpn"
    elif rule == RULE_SERVER:
        expected = "server"
    elif level in (LEVEL_CRITICAL, LEVEL_RECOMMENDED, LEVEL_GATEWAY):
        expected = "vpn"
    elif level == LEVEL_SERVER:
        expected = "server"
    else:
        expected = "none"
    v.expected = expected

    pub = test_result.public_ip
    if not pub:
        v.status, v.behavior, v.result_label = STATUS_UNKNOWN, "untestable", "Unable to Test"
        reason = test_result.error or "no IP returned"
        v.message = "Could not determine public IP (" + str(reason) + ")."
        if expected == "vpn":
            v.notes.append("Expected to use a VPN but could not be verified.")
        v.checks = _build_checks(expected, False, None, test_result, ProviderResult(), False)
        return v

    same = host_ip is not None and pub == host_ip
    v.provider = detect_provider(test_result.geo)
    if test_result.mesh_present:
        v.notes.append("Mesh overlay present (" + ", ".join(test_result.mesh_names) + ") - does not change the internet exit IP.")
    if test_result.error:
        v.notes.append(test_result.error)
    if not test_result.confident:
        v.notes.append("Only one IP source responded; lower confidence.")

    ipv6_leak = False

    if same:
        v.behavior, v.result_label = "server_ip", "Using Server IP"
        if expected == "vpn":
            if crit:
                v.status, v.leaking = STATUS_CRITICAL, True
                v.message = "LEAKING! " + name + " should be behind a VPN but is using your server IP (" + pub + ")."
            else:
                v.status = STATUS_WARNING
                v.message = "Expected a VPN but using the server IP (" + pub + ")."
        else:
            v.status = STATUS_OK
            v.message = "Using the server's public IP (" + pub + ") - no VPN needed for this app."
    else:
        v.behavior, v.result_label = "different_ip", "Using Different IP"
        label = _provider_label(v.provider)
        tunnelled = test_result.tunnel_present or v.provider.is_known_vpn
        if expected == "vpn":
            v.status = STATUS_OK
            if v.provider.is_known_vpn and v.provider.name:
                v.protected = True
                v.message = "Protected - " + name + " is using a VPN (" + v.provider.name + "), exit IP " + pub + "."
            elif tunnelled:
                v.protected = True
                v.message = "Protected - " + name + " is going through a VPN tunnel (" + label + "), exit IP " + pub + "."
            else:
                v.message = "Using a non-server IP (" + label + ", " + pub + "); VPN not positively confirmed."
                v.notes.append("Different from server IP, but VPN could not be confirmed.")

            il, imsg = _check_ipv6_leak(test_result, host_ipv6)
            if il:
                ipv6_leak = v.ipv6_leak = True
                v.protected = False
                v.status = STATUS_WARNING
                v.message = "VPN active for IPv4, but IPv6 leak detected."
                v.notes.append(imsg)
            elif test_result.ipv6 and not host_ipv6:
                v.notes.append("Has IPv6 egress (" + test_result.ipv6 + "); confirm it's inside the tunnel.")
        elif expected == "server":
            v.status = STATUS_WARNING
            v.message = "Expected the server IP but using a different IP (" + label + ", " + pub + ")."
        else:
            v.status = STATUS_OK
            v.message = "Using a different IP (" + label + ", " + pub + ")."

    v.checks = _build_checks(expected, same, pub, test_result, v.provider, ipv6_leak)
    return v
