"""Offline managed-install inspection; never imports installed candidate code."""

import platform
import sys

from .common import require
from .package_version import channel


def diagnose(manager):
    with manager.locked():
        require(not (manager.state / "transaction.json").exists(),
                "pending operation requires explicit recovery")
        identity = manager.current()
        require(identity is not None, "managed installation is missing")
        manifest, _ = manager.archive(identity)
    return {"installed_archive_sha256": identity, "source_revision": manifest["source_revision"],
            "version": manifest["version"], "release_channel": channel(manifest["version"]),
            "integrity_verified": True,
            "python_version": platform.python_version(), "platform": sys.platform,
            "python_meets_minimum": sys.version_info >= (3, 11),
            "platform_in_test_matrix": sys.platform in ("win32", "linux"),
            "runtime_readiness": "not_established", "host_discovery": "not_checked",
            "operation_prerequisites": {
                "M2": "Explicit private state and scoped context; see docs/M2-OPERATIONS.md",
                "M3": "Current accepted components and real Docker isolation; see docs/M3-OPERATIONS.md",
                "M4": "Current accepted components, Docker and scoped destination authority; see docs/M4-OPERATIONS.md",
                "M5": "Current accepted components, Docker and operation-specific budgets; see docs/M5-OPERATIONS.md"},
            "freshness_verified": False, "publisher_authenticated": False,
            "security_verdict": "not_established", "stable_release": False}
