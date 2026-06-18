"""Logic tests (v3). Run: PYTHONPATH=app python tests/test_logic.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from analyzer import (  # noqa: E402
    STATUS_CRITICAL, STATUS_IGNORED, STATUS_OK, STATUS_UNKNOWN, STATUS_WARNING, analyze,
)
from app_catalog import lookup  # noqa: E402
from docker_client import ContainerInfo  # noqa: E402
from ip_tester import GeoInfo, TestResult, parse_probe_output, build_probe_script, _MARK  # noqa: E402
from vpn_detect import detect_provider  # noqa: E402

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print("  ok  - " + label)
    else:
        FAIL += 1; print("  FAIL- " + label)


def c(name, image="img:latest", running=True):
    return ContainerInfo(id="x" * 64, name=name, image=image,
                         state="running" if running else "exited",
                         status="Up", network_mode="bridge")


def tr(ip, org=None, isp=None, asname=None, host=None, ipv6=None,
       tunnel=False, mesh=None, tor=None, confident=True, error=None):
    r = TestResult(public_ip=ip, method="sidecar", confident=confident,
                   services_agree=confident, tunnel_present=tunnel, error=error,
                   ipv6=ipv6, tor=tor)
    r.geo = GeoInfo(ip=ip, org=org, isp=isp, asname=asname, hostname=host)
    r.mesh_names = mesh or []
    r.mesh_present = bool(mesh)
    if ip:
        r.sampled_ips = {"ipinfo": ip, "ipify": ip} if confident else {"ipinfo": ip}
    return r


def by_id(verdict):
    return {x["id"]: x for x in verdict.checks}


HOST_IP = "97.107.188.175"
HOST = {
    "public_ip": HOST_IP, "ipv6": "2001:db8::1",
    "geo": {"isp": "Beanfield Technologies Inc.", "org": "AS6391 Beanfield Technologies Inc."},
}


def test_critical_leak():
    print("test_critical_leak")
    v = analyze(c("qbittorrent"), HOST, tr(HOST_IP), rule="auto")
    check("CRITICAL", v.status == STATUS_CRITICAL)
    check("leaking", v.leaking)
    check("label Using Server IP", v.result_label == "Using Server IP")


def test_recommended_app_warns():
    print("test_recommended_app_warns")
    v = analyze(c("sonarr"), HOST, tr(HOST_IP), rule="auto")
    check("recommended exposed -> WARNING", v.status == STATUS_WARNING)
    check("not CRITICAL", v.status != STATUS_CRITICAL)
    check("expected vpn", v.expected == "vpn")


def test_vpn_ok_mullvad():
    print("test_vpn_ok_mullvad")
    v = analyze(c("binhex-delugevpn"), HOST, tr("151.240.254.11", org="AS39351 31173 Services AB"), rule="auto")
    check("OK", v.status == STATUS_OK)
    check("Mullvad", v.provider.name == "Mullvad")


def test_plex_server_ok():
    print("test_plex_server_ok")
    v = analyze(c("plex"), HOST, tr(HOST_IP), rule="auto")
    check("OK", v.status == STATUS_OK)
    check("expected server", v.expected == "server")


def test_server_app_on_vpn_warns():
    print("test_server_app_on_vpn_warns")
    v = analyze(c("plex"), HOST, tr("8.8.8.8", org="AS15169 Google LLC"), rule="auto")
    check("media server on different IP -> WARNING", v.status == STATUS_WARNING)


def test_force_vpn_warns():
    print("test_force_vpn_warns")
    v = analyze(c("some-random-app"), HOST, tr(HOST_IP), rule="vpn")
    check("forced vpn but on host IP -> WARNING", v.status == STATUS_WARNING)
    check("not critical", v.status != STATUS_CRITICAL)


def test_untestable():
    print("test_untestable")
    v = analyze(c("alpine"), HOST, tr(None, error="no output"), rule="auto")
    check("UNKNOWN", v.status == STATUS_UNKNOWN)
    check("has reachable=fail check", by_id(v)["reachable"]["status"] == "fail")


def test_ignore():
    print("test_ignore")
    v = analyze(c("qbittorrent"), HOST, tr(HOST_IP), rule="ignore")
    check("IGNORED", v.status == STATUS_IGNORED)



def test_ipv6_leak():
    print("test_ipv6_leak")
    v = analyze(c("binhex-delugevpn"), HOST,
                tr("151.240.254.11", org="AS39351 31173 Services AB", ipv6="2001:db8::1"), rule="auto")
    check("ipv6_leak flagged", v.ipv6_leak is True)
    check("WARNING", v.status == STATUS_WARNING)


def test_checks_list():
    print("test_checks_list")
    v = analyze(c("qbittorrent"), HOST, tr(HOST_IP), rule="auto")
    ch = by_id(v)
    check("has ip_vs_server", "ip_vs_server" in ch)
    check("ip_vs_server FAIL when leaking", ch["ip_vs_server"]["status"] == "fail")
    check("reachable pass", ch["reachable"]["status"] == "pass")
    v2 = analyze(c("binhex-delugevpn"), HOST, tr("151.240.254.11", org="AS39351 31173 Services AB"), rule="auto")
    ch2 = by_id(v2)
    check("ip_vs_server PASS on vpn", ch2["ip_vs_server"]["status"] == "pass")
    check("provider PASS for Mullvad", ch2["provider"]["status"] == "pass")


def test_tor_check():
    print("test_tor_check")
    v = analyze(c("binhex-delugevpn"), HOST,
                tr("151.240.254.11", org="AS39351 31173 Services AB", tor=True), rule="auto")
    check("tor check present + warn", by_id(v)["tor"]["status"] == "warn")


def test_catalog_levels():
    print("test_catalog_levels")
    check("qbit critical", lookup("qbittorrent", "i").level == "critical")
    check("sonarr recommended", lookup("sonarr", "i").level == "recommended")
    check("prowlarr recommended", lookup("binhex-prowlarr", "i").level == "recommended")
    check("plex server", lookup("plex", "i").level == "server")
    check("ddns server", lookup("cloudflare-ddns", "i").level == "server")
    check("gluetun gateway", lookup("gluetun", "i").level == "gateway")
    check("delugevpn critical (client not gateway)", lookup("binhex-delugevpn", "i").level == "critical")
    check("unknown app", lookup("Rickroll", "i").level == "unknown")
    check("has why text", len(lookup("qbittorrent", "i").why) > 10)


def test_provider_detection():
    print("test_provider_detection")
    check("Mullvad ASN", detect_provider(GeoInfo(org="AS39351 31173 Services AB")).name == "Mullvad")
    check("Surfshark isp", detect_provider(GeoInfo(isp="Surfshark Ltd")).name == "Surfshark")
    check("residential unknown", detect_provider(GeoInfo(org="AS7922 Comcast", isp="Comcast Cable")).confidence == "unknown")
    check("Tailscale mesh", detect_provider(GeoInfo(isp="Tailscale Inc.")).is_mesh)
    check("proxycheck names brand", detect_provider(GeoInfo(vpn_provider="Surfshark VPN")).name == "Surfshark VPN")
    check("AS209854 -> Surfshark", detect_provider(GeoInfo(org="AS209854 Cyberzone S.A.")).name == "Surfshark")
    check("proxy flag -> likely VPN", detect_provider(GeoInfo(org="AS1 X Host", proxy=True)).confidence == "likely")


def test_probe_parsing():
    print("test_probe_parsing")
    m = _MARK
    sample = (
        m + "IFACES\nlo eth0 tun0 tailscale0 \n"
        + m + 'IPINFO\n{"ip": "151.240.254.11", "org": "AS39351 31173 Services AB"}\n'
        + m + "IPIFY\n151.240.254.11\n" + m + "ICANHAZ\n151.240.254.11\n"
        + m + "IPV6\n2606:4700:4700::1111\n"
        + m + 'TOR\n{"IsTor": false}\n'
        + m + "DONE\n"
    )
    r = parse_probe_output(sample, "sidecar")
    check("public_ip", r.public_ip == "151.240.254.11")
    check("ipv6 parsed", r.ipv6 == "2606:4700:4700::1111")
    check("tor parsed false", r.tor is False)
    check("tunnel detected", r.tunnel_present is True)
    check("mesh detected", r.mesh_present and "tailscale0" in r.mesh_names)
    check("script has TOR + markers", "TOR" in build_probe_script(5) and _MARK in build_probe_script(5))


def test_protected():
    print("test_protected")
    v = analyze(c("binhex-delugevpn"), HOST, tr("151.240.254.11", org="AS39351 31173 Services AB"), rule="auto")
    check("protected flag set", v.protected is True)
    check("message says protected", "protected" in v.message.lower())
    v2 = analyze(c("plex"), HOST, tr(HOST_IP), rule="auto")
    check("server app not 'protected'", v2.protected is False)



def test_unrecognised_has_level():
    print("test_unrecognised_has_level")
    from app_catalog import lookup as _lk
    check("rickroll level is unknown (UI shows a badge)", _lk("Rickroll", "modem7/docker-rickroll").level == "unknown")


def main():
    for fn in [
        test_critical_leak, test_recommended_app_warns, test_vpn_ok_mullvad,
        test_plex_server_ok, test_server_app_on_vpn_warns, test_force_vpn_warns,
        test_untestable, test_ignore, test_ipv6_leak,
        test_checks_list, test_tor_check, test_catalog_levels,
        test_provider_detection, test_probe_parsing,
        test_protected, test_unrecognised_has_level,
    ]:
        fn()
    print("\n%d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
