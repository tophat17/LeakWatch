"""Config + request/response models."""
from __future__ import annotations

import os

from pydantic import BaseModel

from analyzer import VALID_RULES


class Config:
    """Runtime configuration, all overridable via environment variables."""

    def __init__(self) -> None:
        self.helper_image = os.environ.get("LEAKWATCH_HELPER_IMAGE", "curlimages/curl:latest")
        self.probe_timeout = int(os.environ.get("LEAKWATCH_PROBE_TIMEOUT", "8"))
        self.scan_concurrency = int(os.environ.get("LEAKWATCH_CONCURRENCY", "4"))
        self.include_stopped = os.environ.get("LEAKWATCH_INCLUDE_STOPPED", "true").lower() == "true"
        self.port = int(os.environ.get("LEAKWATCH_PORT", "8080"))
        self.proxycheck_key = os.environ.get("LEAKWATCH_PROXYCHECK_KEY", "")

    def as_dict(self) -> dict:
        return {
            "helper_image": self.helper_image,
            "probe_timeout": self.probe_timeout,
            "scan_concurrency": self.scan_concurrency,
            "include_stopped": self.include_stopped,
            "port": self.port,
            "proxycheck_key_set": bool(self.proxycheck_key),
        }


class SetRuleRequest(BaseModel):
    rule: str

    def valid(self) -> bool:
        return self.rule in VALID_RULES
