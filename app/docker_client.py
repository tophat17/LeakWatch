"""Thin wrapper around the Docker Engine API (via the mounted socket).

Responsibilities:
  * list running/all containers with their resolved network mode
  * identify the LeakWatch container itself (so we never scan ourselves)
  * run a short-lived "sidecar" container inside a target's network namespace
  * exec a command inside a target container (fallback path)

Nothing here decides what an IP *means* — that lives in analyzer.py.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import docker
from docker.errors import APIError, ImageNotFound, NotFound
from docker.models.containers import Container

log = logging.getLogger("leakwatch.docker")


@dataclass
class ContainerInfo:
    id: str
    name: str
    image: str
    state: str  # running, exited, ...
    status: str  # human string e.g. "Up 3 hours"
    network_mode: str  # raw HostConfig.NetworkMode, e.g. "bridge" or "container:abc"
    routed_through: Optional[str] = None  # name of container we share a netns with
    is_self: bool = False
    labels: dict = field(default_factory=dict)

    @property
    def running(self) -> bool:
        return self.state == "running"


class DockerClient:
    def __init__(self, helper_image: str = "curlimages/curl:latest"):
        # from_env honours DOCKER_HOST; defaults to the unix socket otherwise.
        self.client = docker.from_env()
        self.helper_image = helper_image
        self._self_id = self._detect_self_id()

    # ------------------------------------------------------------------ #
    # Identity                                                            #
    # ------------------------------------------------------------------ #
    def _detect_self_id(self) -> Optional[str]:
        """Best-effort detection of our own container id.

        The container id is the hostname inside a container by default, and is
        also discoverable from the cgroup file. Either is good enough to avoid
        scanning ourselves.
        """
        # 1) HOSTNAME is the short container id unless overridden.
        candidate = os.environ.get("HOSTNAME", "").strip()
        # 2) cgroup path contains the full id on cgroup v1; mountinfo on v2.
        for path in ("/proc/self/cgroup", "/proc/self/mountinfo"):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            for token in text.replace("/", " ").replace("-", " ").split():
                if len(token) == 64 and all(c in "0123456789abcdef" for c in token):
                    return token
        return candidate or None

    def is_self(self, container: Container) -> bool:
        if not self._self_id:
            return False
        cid = container.id or ""
        return cid.startswith(self._self_id) or self._self_id.startswith(cid[:12])

    # ------------------------------------------------------------------ #
    # Listing                                                             #
    # ------------------------------------------------------------------ #
    def list_containers(self, include_stopped: bool = True) -> list[ContainerInfo]:
        out: list[ContainerInfo] = []
        id_to_name = {}
        raw = self.client.containers.list(all=include_stopped)
        for c in raw:
            id_to_name[c.id] = c.name
        for c in raw:
            attrs = c.attrs or {}
            host_cfg = attrs.get("HostConfig", {}) or {}
            net_mode = host_cfg.get("NetworkMode", "") or ""
            routed = None
            if net_mode.startswith("container:"):
                target_id = net_mode.split(":", 1)[1]
                routed = id_to_name.get(target_id, target_id[:12])
            image = ""
            try:
                tags = c.image.tags
                image = tags[0] if tags else (c.image.id or "")[:19]
            except Exception:
                image = "<unknown>"
            out.append(
                ContainerInfo(
                    id=c.id,
                    name=c.name,
                    image=image,
                    state=c.status,
                    status=attrs.get("State", {}).get("Status", c.status),
                    network_mode=net_mode,
                    routed_through=routed,
                    is_self=self.is_self(c),
                    labels=(attrs.get("Config", {}) or {}).get("Labels", {}) or {},
                )
            )
        out.sort(key=lambda x: x.name.lower())
        return out

    def get_container(self, name_or_id: str) -> Optional[Container]:
        try:
            return self.client.containers.get(name_or_id)
        except NotFound:
            return None

    # ------------------------------------------------------------------ #
    # Helper image                                                        #
    # ------------------------------------------------------------------ #
    def ensure_helper_image(self) -> bool:
        try:
            self.client.images.get(self.helper_image)
            return True
        except ImageNotFound:
            pass
        except APIError as e:
            log.warning("could not check helper image: %s", e)
        try:
            log.info("pulling helper image %s", self.helper_image)
            self.client.images.pull(self.helper_image)
            return True
        except APIError as e:
            log.error("failed to pull helper image %s: %s", self.helper_image, e)
            return False

    # ------------------------------------------------------------------ #
    # Probes                                                              #
    # ------------------------------------------------------------------ #
    def run_sidecar(self, target_id: str, script: str, timeout: int = 30) -> Optional[str]:
        """Run `sh -c <script>` in a throwaway container that shares the
        target's network namespace. Returns combined stdout/stderr, or None.

        This is tool-independent: it works even if the target container has no
        curl/wget/python of its own, because the *helper* image provides them
        while seeing the exact same network stack (including any VPN tunnel).
        """
        if not self.ensure_helper_image():
            return None
        container = None
        try:
            container = self.client.containers.run(
                self.helper_image,
                command=["sh", "-c", script],
                entrypoint="",  # override curl image's default entrypoint
                network_mode=f"container:{target_id}",
                remove=False,
                detach=True,
                stderr=True,
                stdout=True,
                # No new privileges; we only need outbound network.
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
            )
            result = container.wait(timeout=timeout)
            logs = container.logs(stdout=True, stderr=True)
            if isinstance(logs, bytes):
                logs = logs.decode("utf-8", errors="replace")
            return logs
        except Exception as e:  # noqa: BLE001 - report, never crash a scan
            log.warning("sidecar failed for %s: %s", target_id[:12], e)
            return None
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def exec_probe(self, container: Container, script: str, timeout: int = 20) -> Optional[str]:
        """Fallback: run a shell snippet *inside* the target container itself.

        Only works if the container ships a shell + an HTTP client. Used when
        the sidecar route is unavailable.
        """
        try:
            exit_code, output = container.exec_run(
                ["sh", "-c", script],
                stdout=True,
                stderr=True,
                demux=False,
            )
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            return output
        except Exception as e:  # noqa: BLE001
            log.debug("exec probe failed for %s: %s", container.name, e)
            return None

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass
