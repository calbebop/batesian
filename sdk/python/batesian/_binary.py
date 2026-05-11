"""Locates the Batesian CLI binary on the current system."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


class BinaryNotFoundError(Exception):
    """Raised when the batesian binary cannot be found."""


def find_binary(binary_path: Optional[str] = None) -> str:
    """Return the absolute path to the batesian binary.

    Search order:
    1. ``binary_path`` argument (explicit override).
    2. ``BATESIAN_BIN`` environment variable.
    3. ``batesian`` / ``batesian.exe`` on ``PATH``.
    4. Common installation locations (``~/go/bin``, ``/usr/local/bin``).

    Raises :class:`BinaryNotFoundError` if none of the above succeed.
    """
    if binary_path:
        if _is_executable(binary_path):
            return binary_path
        raise BinaryNotFoundError(f"Specified binary path is not executable: {binary_path}")

    env_path = os.environ.get("BATESIAN_BIN")
    if env_path and _is_executable(env_path):
        return env_path

    name = "batesian.exe" if sys.platform == "win32" else "batesian"
    which = shutil.which(name)
    if which:
        return which

    candidates = [
        Path.home() / "go" / "bin" / name,
        Path("/usr/local/bin") / name,
        Path("/usr/bin") / name,
    ]
    for candidate in candidates:
        if _is_executable(str(candidate)):
            return str(candidate)

    raise BinaryNotFoundError(
        "batesian binary not found. Install with:\n"
        "  go install github.com/calbebop/batesian/cmd/batesian@latest\n"
        "or set the BATESIAN_BIN environment variable to its path."
    )


def binary_version(binary_path: str) -> str:
    """Return the version string reported by the binary, or 'unknown' on failure."""
    try:
        result = subprocess.run(
            [binary_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or result.stderr.strip() or "unknown"
    except Exception:
        return "unknown"


def _is_executable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)
