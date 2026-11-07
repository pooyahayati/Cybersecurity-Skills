"""Local Linux Docker isolation. No native or network-enabled execution fallback."""

from __future__ import annotations

import os
from pathlib import Path
import re

from .common import Blocked, parse, read_file, regular, require, sha256
from .process import bounded_process


IMAGE = "docker.io/library/python:3-slim"
LABEL = "org.pooyahayati.cybersecurity"


class Docker:
    def __init__(self, executable, state, endpoint=None):
        self.executable = Path(executable).resolve(strict=True)
        regular(self.executable)
        self.identity = sha256(read_file(self.executable.parent, self.executable.name, 256 * 1024 * 1024))
        self.state = state
        self.instance = sha256(state.key)[:24]
        self.endpoint = endpoint or ("npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt"
                                     else "unix:///var/run/docker.sock")
        require(self.endpoint == "npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt"
                else bool(re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", self.endpoint))
                and ".." not in self.endpoint.split("/"), "only a local Docker endpoint is supported")
        self.env = {"PATH": str(self.executable.parent) + os.pathsep + os.defpath}
        if os.name == "nt":
            for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
                if key in os.environ:
                    self.env[key] = os.environ[key]

    def command(self, args, timeout=30, limit=4 * 1024 * 1024, **kwargs):
        require(sha256(read_file(self.executable.parent, self.executable.name, 256 * 1024 * 1024))
                == self.identity, "Docker executable changed; reload the controller")
        # A fixed empty config avoids credential helpers and ambient Docker settings.
        require(read_file(self.state.root, "docker-config/config.json") == b"{}\n",
                "private Docker configuration changed")
        argv = [str(self.executable), "--config", str(self.state.root / "docker-config"),
                "--host", self.endpoint, *args]
        return bounded_process(argv, self.env, timeout, limit, **kwargs)

    def checked(self, args, **kwargs):
        result = self.command(args, **kwargs)
        require(result["exit_code"] == 0, "Docker operation failed; isolation is unavailable")
        return result["content"]

    def observe(self):
        version = parse(self.checked(["version", "--format", "{{json .}}"], limit=1024 * 1024))
        require(isinstance(version, dict) and isinstance(version.get("Server"), dict)
                and version["Server"].get("Os") == "linux", "a local Linux Docker engine is required")
        info = parse(self.checked(["info", "--format", "{{json .}}"], limit=2 * 1024 * 1024))
        require(isinstance(info, dict) and all(info.get(key) is True for key in
                ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit"))
                and info.get("CgroupVersion") == "2"
                and "name=seccomp,profile=builtin" in info.get("SecurityOptions", [])
                and "runc" in info.get("Runtimes", {}), "required kernel isolation controls are unavailable")
        return {"client_version": version.get("Client", {}).get("Version"),
                "server_version": version["Server"].get("Version"),
                "executable_sha256": self.identity, "endpoint": self.endpoint}

    def latest(self):
        prerequisite = self.observe()
        self.checked(["pull", IMAGE], timeout=300)
        rows = parse(self.checked(["image", "inspect", IMAGE]))
        require(isinstance(rows, list) and len(rows) == 1, "runtime image is unavailable")
        image = rows[0]
        require(image.get("Os") == "linux" and not image.get("Config", {}).get("Volumes"),
                "runtime image declares unsupported OS or anonymous volumes")
        digests = image.get("RepoDigests", [])
        refs = [d for d in digests if isinstance(d, str) and re.fullmatch(
            r"(?:docker.io/library/)?python@sha256:[0-9a-f]{64}", d)]
        require(len(refs) == 1 and re.fullmatch(r"sha256:[0-9a-f]{64}", str(image.get("Id"))),
                "runtime image lacks an unambiguous immutable identity")
        return {"identity": {"channel": IMAGE, "reference": refs[0], "image_id": image["Id"],
                             "architecture": image.get("Architecture")},
                "prerequisite": prerequisite}

    def name(self, operation):
        require(re.fullmatch(r"op-[0-9a-f]{32}", operation), "invalid operation ID")
        return "cybersecurity-" + self.instance + "-" + operation

    def inspect(self, name):
        result = self.command(["container", "inspect", name])
        if result["exit_code"] != 0:
            # A failed inspect is not evidence of absence. Query the daemon inventory.
            rows = self.checked(["container", "ls", "--all", "--no-trunc", "--format", "{{.Names}}"])
            if name not in rows.decode("utf-8").splitlines():
                return None
            # Creation may finish between inspect and inventory. Retry that exact
            # identity once; an unavailable second observation still blocks.
            result = self.command(["container", "inspect", name])
            require(result["exit_code"] == 0, "container state cannot be verified")
        rows = parse(result["content"])
        require(isinstance(rows, list) and len(rows) == 1, "ambiguous container identity")
        return rows[0]

    def owned(self, info, operation):
        labels = info.get("Config", {}).get("Labels", {})
        require(labels.get(LABEL + ".instance") == self.instance
                and labels.get(LABEL + ".operation") == operation, "container is not owned by this operation")

    def cleanup(self, operation):
        name = self.name(operation)
        info = self.inspect(name)
        if info is not None:
            self.owned(info, operation)
            self.checked(["container", "rm", "--force", name])
        require(self.inspect(name) is None, "container cleanup could not be verified")

    def execute(self, operation, image, component, inputs, specification, limits, guard, output, resources=None):
        name = self.name(operation)
        require(self.inspect(name) is None, "operation container already exists; recover it first")
        mounts = {"/component": component, "/inputs": inputs}
        mounts.update({"/resources/" + key: value for key, value in (resources or {}).items()})
        for path in mounts.values():
            require("," not in str(path) and "\n" not in str(path) and "\r" not in str(path),
                    "mount path contains unsupported delimiters")
        entrypoint = "/component/" + specification["entrypoint"]
        argv = (["/usr/local/bin/python", "-I", "-B", entrypoint]
                if specification["interpreter"] == "python" else [entrypoint])
        argv += specification["arguments"]
        duration = specification["timeout_seconds"]
        # PID 1 is a deadline supervisor. Killing it terminates the container namespace.
        command = ["-i", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "LANG=C.UTF-8",
                   "/usr/bin/timeout", "--signal=KILL", str(duration), *argv]
        args = ["container", "create", "--name", name,
            "--label", LABEL + ".instance=" + self.instance,
            "--label", LABEL + ".operation=" + operation,
            "--network", "none", "--read-only", "--user", "65532:65532", "--runtime", "runc",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
            "--security-opt", "seccomp=builtin",
            "--memory", str(limits["memory_mb"]) + "m",
            "--memory-swap", str(limits["memory_mb"]) + "m",
            "--cpus", str(limits["cpus"]), "--pids-limit", str(limits["pids"]),
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={limits['tmpfs_mb']}m,mode=1777",
            "--shm-size", "1m", "--log-driver", "none", "--no-healthcheck",
            "--restart", "no", "--stop-timeout", "1", "--workdir", "/inputs",
            "--entrypoint", "/usr/bin/env"]
        for target, source in mounts.items():
            args += ["--mount", f"type=bind,source={source},target={target},readonly"]
        args += [image["reference"], *command]
        guard()
        try:
            self.checked(args)
            info = self.inspect(name)
            require(info is not None, "created container is unavailable")
            self.owned(info, operation)
            self.verify(info, image, mounts, limits, command)
            guard()
            result = self.command(["container", "start", "--attach", name],
                timeout=duration + 5, limit=specification["max_output_bytes"],
                guard=guard, sink=output, capture=False)
            info = self.inspect(name)
            require(info is not None and info.get("State", {}).get("Running") is False,
                    "container exit was not observed")
            require(result["exit_code"] == info["State"].get("ExitCode"),
                    "container and attach exit status disagree")
            require(not info["State"].get("OOMKilled"), "container exceeded its memory limit")
            require(result["exit_code"] not in (124, 137), "container reached its hard deadline or was killed")
            result.pop("content", None)
            return result
        finally:
            self.cleanup(operation)

    def verify(self, info, image, expected_mounts, limits, command):
        config, host = info.get("Config", {}), info.get("HostConfig", {})
        require(info.get("Image") == image["image_id"] and config.get("User") == "65532:65532"
                and config.get("Entrypoint") == ["/usr/bin/env"] and config.get("Cmd") == command
                and config.get("Healthcheck", {}).get("Test") == ["NONE"]
                and not config.get("Volumes"), "runtime identity or entrypoint changed")
        require(host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True
                and host.get("Privileged") is False and host.get("CapDrop") == ["ALL"]
                and not host.get("CapAdd") and set(host.get("SecurityOpt", []))
                    == {"no-new-privileges=true", "seccomp=builtin"}
                and host.get("Memory") == limits["memory_mb"] * 1024**2
                and host.get("MemorySwap") == host.get("Memory")
                and host.get("NanoCpus") == int(limits["cpus"] * 10**9)
                and host.get("PidsLimit") == limits["pids"]
                and host.get("LogConfig", {}).get("Type") == "none"
                and host.get("RestartPolicy", {}).get("Name") == "no"
                and host.get("Runtime") == "runc"
                and host.get("PidMode", "") == "" and host.get("IpcMode") == "private"
                and not host.get("Devices") and not host.get("DeviceRequests")
                and not host.get("PortBindings") and not host.get("Binds"),
                "Docker did not enforce the requested isolation")
        require(host.get("Tmpfs") == {"/tmp":
            f"rw,noexec,nosuid,nodev,size={limits['tmpfs_mb']}m,mode=1777"}
            and host.get("ShmSize") == 1024**2, "scratch-space limits were not enforced")
        mounts = info.get("Mounts", [])
        require(len(mounts) == len(expected_mounts)
                and {m.get("Destination") for m in mounts} == set(expected_mounts)
                and all(m.get("RW") is False and m.get("Type") == "bind"
                        and m.get("Propagation") == "rprivate" for m in mounts),
                "unexpected container mounts")
        # Desktop rewrites Windows source paths. HostConfig retains the request.
        requested = host.get("Mounts", [])
        expected = {key: str(value) for key, value in expected_mounts.items()}
        require(len(requested) == len(expected) and all(m.get("Type") == "bind" and m.get("ReadOnly") is True
                and expected.get(m.get("Target")) == m.get("Source") for m in requested),
                "container mount sources differ from the verified snapshots")
