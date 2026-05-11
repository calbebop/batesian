"""Tests for batesian._binary."""

import os
import stat
import sys
import pytest
from batesian._binary import find_binary, binary_version, BinaryNotFoundError

# Windows does not honour Unix execute bits; os.access(X_OK) always returns
# True for existing files. Tests that rely on non-executable files are skipped.
_UNIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="Unix execute bits not applicable on Windows")


class TestFindBinary:
    def test_explicit_path_valid(self, tmp_path):
        name = "batesian.exe" if sys.platform == "win32" else "batesian"
        binary = tmp_path / name
        binary.write_text("#!/bin/sh\necho ok\n")
        if sys.platform != "win32":
            binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
        assert find_binary(str(binary)) == str(binary)

    @_UNIX_ONLY
    def test_explicit_path_not_executable(self, tmp_path):
        binary = tmp_path / "batesian"
        binary.write_text("#!/bin/sh\necho ok\n")
        binary.chmod(0o644)  # not executable
        with pytest.raises(BinaryNotFoundError, match="not executable"):
            find_binary(str(binary))

    def test_explicit_path_not_found(self):
        with pytest.raises(BinaryNotFoundError):
            find_binary("/nonexistent/path/batesian")

    def test_env_var_valid(self, tmp_path, monkeypatch):
        name = "batesian.exe" if sys.platform == "win32" else "batesian"
        binary = tmp_path / name
        binary.write_text("#!/bin/sh\necho ok\n")
        if sys.platform != "win32":
            binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
        monkeypatch.setenv("BATESIAN_BIN", str(binary))
        assert find_binary() == str(binary)

    @_UNIX_ONLY
    def test_env_var_not_executable(self, tmp_path, monkeypatch):
        binary = tmp_path / "batesian"
        binary.write_text("not executable")
        binary.chmod(0o644)
        monkeypatch.setenv("BATESIAN_BIN", str(binary))
        monkeypatch.delenv("PATH", raising=False)
        with pytest.raises(BinaryNotFoundError):
            find_binary()

    def test_no_binary_raises(self, monkeypatch):
        monkeypatch.delenv("BATESIAN_BIN", raising=False)
        monkeypatch.setenv("PATH", "")  # Clear PATH so shutil.which returns None.
        with pytest.raises(BinaryNotFoundError, match="batesian binary not found"):
            find_binary()


class TestBinaryVersion:
    def test_returns_string_on_failure(self):
        result = binary_version("/nonexistent/binary")
        assert result == "unknown"
