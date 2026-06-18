"""Scan orchestration (v2) - Docker + IP testing + enrichment + analyzer + store."""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from analyzer import analyze, is_on_critical_list
from app_catalog import lookup
from docker_client import ContainerInfo, DockerClient
from ip_tester import IPTester, TestResult, enrich_geo
from settings_store import SettingsStore
from vpn_detect import detect_provider

log = logging.getLogger("leakwatch.service")


class LeakWatch:
    def __init__(self, config, store: SettingsStore):
        self.config = config
        self.store = store
        self.dc = DockerClient(helper_image=config.helper_image)
        self.tester = IPTester(self.dc, probe_timeout=config.probe_timeout)

    def health(self) -> dict:
        docker_ok, err = True, None
        try:
            self.dc.client.ping()
        except Exception as e:  # noqa: BLE001
            docker_ok, err = False, str(e)
        return {"status": "ok" if docker_ok else "degraded", "docker_ok": docker_ok, "error": err}

    def host_info(self, refresh: bool = False) -> dict:
        if not refresh:
            cached = self.store.meta_get("host")
            if cached:
                return cached
        res = self.tester.test_host()
        info = {
            "public_ip": res.public_ip,
            "ipv6": res.ipv6,
            "geo": res.geo.as_dict(),
            "provider": detect_provider(res.geo).as_dict(),
            "error": res.error,
            "scanned_at": time.time(),
        }
        self.store.meta_set("host", info)
        return info

    def _container_payload(self, c: ContainerInfo) -> dict:
        return {
            "name": c.name, "image": c.image, "state": c.state, "status": c.status,
            "network_mode": c.network_mode, "routed_through": c.routed_through,
            "is_self": c.is_self,
            "on_critical_list": is_on_critical_list(c.name, c.image),
            "rule": self.store.get_rule(c.name),
            "app": lookup(c.name, c.image).as_dict(),
        }

    def list_state(self) -> dict:
        containers = self.dc.list_containers(include_stopped=self.config.include_stopped)
        cache = self.store.cache_all()
        items = []
        for c in containers:
            p = self._container_payload(c)
            cached = cache.get(c.name)
            p["test"] = cached.get("test") if cached else None
            p["verdict"] = cached.get("verdict") if cached else None
            p["scanned_at"] = cached.get("scanned_at") if cached else None
            items.append(p)
        return {"host": self.store.meta_get("host"), "containers": items,
                "last_scan": self.store.meta_get("last_scan")}

    def _scan_one(self, c: ContainerInfo, host: dict) -> dict:
        p = self._container_payload(c)
        if c.is_self:
            p["test"] = TestResult(method="skipped").as_dict()
            p["verdict"] = {
                "status": "IGNORED", "behavior": "untestable",
                "result_label": "LeakWatch itself", "expected": "none",
                "leaking": False, "ipv6_leak": False,
                "on_critical_list": False, "provider": {},
                "message": "This is the LeakWatch container.", "notes": [],
            }
            p["scanned_at"] = time.time()
            self.store.cache_set(c.name, {"test": p["test"], "verdict": p["verdict"]})
            return p

        test = self.tester.test_container(c)
        if test.public_ip:
            test.geo = enrich_geo(test.public_ip, test.geo, self.config.probe_timeout)
        rule = self.store.get_rule(c.name)
        verdict = analyze(c, host, test, rule)
        p["test"] = test.as_dict()
        p["verdict"] = verdict.as_dict()
        p["scanned_at"] = time.time()
        self.store.cache_set(c.name, {"test": p["test"], "verdict": p["verdict"]})
        return p

    def scan_all(self) -> dict:
        host = self.host_info(refresh=True)
        containers = self.dc.list_containers(include_stopped=self.config.include_stopped)
        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=max(1, self.config.scan_concurrency)) as pool:
            futures = {pool.submit(self._scan_one, c, host): c for c in containers}
            for fut in as_completed(futures):
                c = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    log.exception("scan failed for %s", c.name)
                    p = self._container_payload(c)
                    p["test"] = {"error": str(e)}
                    p["verdict"] = {
                        "status": "UNKNOWN", "behavior": "untestable",
                        "result_label": "Unable to Test", "expected": "none",
                        "leaking": False, "ipv6_leak": False,
                        "on_critical_list": p["on_critical_list"], "provider": {},
                        "message": f"Scan error: {e}", "notes": [],
                    }
                    results.append(p)
        results.sort(key=lambda x: x["name"].lower())
        stamp = time.time()
        self.store.meta_set("last_scan", stamp)
        return {"host": host, "containers": results, "last_scan": stamp}

    def scan_container(self, name: str) -> Optional[dict]:
        containers = self.dc.list_containers(include_stopped=self.config.include_stopped)
        match = next((c for c in containers if c.name == name), None)
        if match is None:
            return None
        host = self.host_info(refresh=False) or self.host_info(refresh=True)
        return self._scan_one(match, host)

    def set_rule(self, name: str, rule: str) -> None:
        self.store.set_rule(name, rule)

    def close(self) -> None:
        self.dc.close()
