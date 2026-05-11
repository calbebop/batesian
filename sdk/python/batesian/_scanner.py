"""Core Scanner class that drives the Batesian CLI."""

from __future__ import annotations

import json
import subprocess
from typing import List, Optional

from batesian._binary import find_binary, BinaryNotFoundError
from batesian._models import Results, ScanError


class Scanner:
    """Run Batesian attack rules against a target agent or MCP endpoint.

    Parameters
    ----------
    target:
        Base URL of the agent or MCP server to scan
        (e.g. ``"https://agent.example.com"``).
    binary_path:
        Explicit path to the batesian binary. If omitted, the binary is
        located automatically via :func:`~batesian._binary.find_binary`.
    token:
        Bearer token for authenticated targets. If omitted, the
        ``BATESIAN_TOKEN`` environment variable is read automatically by
        the CLI. Pass ``token`` here to set it explicitly in Python.
    token_url:
        OAuth 2.0 token endpoint for automatic client-credentials token
        acquisition. Requires ``client_id``.
    client_id:
        OAuth 2.0 client ID (used with ``token_url``).
    client_secret:
        OAuth 2.0 client secret (used with ``token_url``).
    oauth_scopes:
        OAuth 2.0 scopes to request (used with ``token_url``).
    oauth_audience:
        OAuth 2.0 audience identifier (Auth0/Okta-style; used with ``token_url``).
    auth_url:
        OAuth 2.0 authorization endpoint URL. Setting this enables the
        interactive PKCE authorization-code flow in the underlying CLI.
        The CLI still drives the browser callback; the SDK only forwards
        the flag.
    redirect_port:
        Local TCP port for the OAuth callback listener used by PKCE
        (default: ``9876`` in the CLI). Pass an explicit port if the
        default is taken or if you have a fixed redirect URI registered
        with the IdP.
    no_browser:
        When True, the CLI prints the authorization URL instead of
        attempting to auto-open a browser. Useful for headless or CI
        environments where the browser cannot be launched.
    timeout:
        Per-request HTTP timeout in seconds (default: 10).
    skip_tls:
        Skip TLS certificate verification. Not recommended for production.
    config:
        Path to a ``batesian.yaml`` config file.
    verbose:
        Enable verbose CLI output (forwarded as ``-v`` to the binary).
        Verbose output is written to stderr and does not affect the JSON
        results returned by ``run()`` / ``probe()``.
    """

    def __init__(
        self,
        target: str,
        *,
        binary_path: Optional[str] = None,
        token: Optional[str] = None,
        token_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        oauth_scopes: Optional[List[str]] = None,
        oauth_audience: Optional[str] = None,
        auth_url: Optional[str] = None,
        redirect_port: Optional[int] = None,
        no_browser: bool = False,
        timeout: int = 10,
        skip_tls: bool = False,
        config: Optional[str] = None,
        verbose: bool = False,
    ) -> None:
        self.target = target
        self.binary = find_binary(binary_path)
        self.token = token
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.oauth_scopes = oauth_scopes or []
        self.oauth_audience = oauth_audience
        self.auth_url = auth_url
        self.redirect_port = redirect_port
        self.no_browser = no_browser
        self.timeout = timeout
        self.skip_tls = skip_tls
        self.config = config
        self.verbose = verbose

    def run(
        self,
        *,
        rules: Optional[List[str]] = None,
        protocol: Optional[str] = None,
        tags: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        rules_dir: Optional[str] = None,
        oob: bool = False,
        oob_url: Optional[str] = None,
    ) -> Results:
        """Execute a scan and return the findings.

        Parameters
        ----------
        rules:
            Explicit list of rule IDs to run. If omitted, all applicable rules
            for the detected protocol(s) are run.
        protocol:
            Filter rules by protocol: ``"a2a"``, ``"mcp"``, or ``None`` for all.
        tags:
            Filter rules by tag (e.g. ``["injection", "auth"]``).
        severities:
            Filter rules by severity (e.g. ``["critical", "high"]``).
        rules_dir:
            Additional directory containing custom YAML rule files.
        oob:
            Enable local OOB listener for SSRF callback detection.
        oob_url:
            External OOB listener URL (overrides ``oob=True``).

        Returns
        -------
        Results
            Parsed scan output with all findings.

        Raises
        ------
        ScanError
            If the CLI exits with a non-zero code or produces no parseable output.
        BinaryNotFoundError
            If the batesian binary cannot be located.
        """
        cmd = self._build_command(
            rules=rules,
            protocol=protocol,
            tags=tags,
            severities=severities,
            rules_dir=rules_dir,
            oob=oob,
            oob_url=oob_url,
        )

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(self.timeout * 60, 120),  # CLI timeout is per-request; give generous wall time
            )
        except subprocess.TimeoutExpired as e:
            raise ScanError(f"Scan timed out after {e.timeout}s") from e
        except FileNotFoundError:
            raise BinaryNotFoundError(f"batesian binary not found at: {self.binary}")

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        if not stdout:
            raise ScanError(
                "batesian produced no output",
                returncode=proc.returncode,
                stderr=stderr,
            )

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ScanError(
                f"Failed to parse batesian JSON output: {e}",
                returncode=proc.returncode,
                stderr=stderr,
            ) from e

        if proc.returncode != 0:
            raise ScanError(
                f"batesian exited with code {proc.returncode}",
                returncode=proc.returncode,
                stderr=stderr,
            )

        return Results.from_dict(data)

    def probe(self, *, protocol: Optional[str] = None) -> dict:
        """Run the batesian probe command and return the raw discovery data.

        Parameters
        ----------
        protocol:
            Protocol to probe: ``"a2a"`` or ``"mcp"``. Defaults to
            ``"a2a"`` when omitted (matches the CLI default).

        Returns
        -------
        dict
            Raw JSON probe output from the CLI.
        """
        cmd = [self.binary, "probe", "--target", self.target, "--output", "json"]
        if protocol:
            cmd += ["--protocol", protocol]
        if self.token:
            cmd += ["--token", self.token]
        if self.skip_tls:
            cmd.append("--skip-tls")
        if self.config:
            cmd += ["--config", self.config]
        if self.verbose:
            cmd.append("-v")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(self.timeout * 6, 60),
            )
        except subprocess.TimeoutExpired as e:
            raise ScanError(f"Probe timed out after {e.timeout}s") from e

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        if not stdout:
            raise ScanError("batesian probe produced no output", returncode=proc.returncode, stderr=stderr)

        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ScanError(f"Failed to parse probe output: {e}", returncode=proc.returncode, stderr=stderr) from e

        if proc.returncode != 0:
            raise ScanError(
                f"batesian probe exited with code {proc.returncode}",
                returncode=proc.returncode,
                stderr=stderr,
            )

        return result

    def _build_command(
        self,
        *,
        rules: Optional[List[str]],
        protocol: Optional[str],
        tags: Optional[List[str]],
        severities: Optional[List[str]],
        rules_dir: Optional[str],
        oob: bool,
        oob_url: Optional[str],
    ) -> List[str]:
        cmd = [
            self.binary,
            "scan",
            "--target", self.target,
            "--output", "json",
            "--timeout", str(self.timeout),
        ]

        if rules:
            cmd += ["--rule-ids", ",".join(rules)]
        if protocol:
            cmd += ["--protocol", protocol]
        if tags:
            cmd += ["--tags", ",".join(tags)]
        if severities:
            cmd += ["--severity", ",".join(severities)]
        if rules_dir:
            cmd += ["--rules-dir", rules_dir]
        if self.token:
            cmd += ["--token", self.token]
        if self.token_url:
            cmd += ["--token-url", self.token_url]
        if self.client_id:
            cmd += ["--client-id", self.client_id]
        if self.client_secret:
            cmd += ["--client-secret", self.client_secret]
        if self.oauth_scopes:
            cmd += ["--oauth-scopes", ",".join(self.oauth_scopes)]
        if self.oauth_audience:
            cmd += ["--oauth-audience", self.oauth_audience]
        if self.auth_url:
            cmd += ["--auth-url", self.auth_url]
        if self.redirect_port is not None:
            cmd += ["--redirect-port", str(self.redirect_port)]
        if self.no_browser:
            cmd.append("--no-browser")
        if self.skip_tls:
            cmd.append("--skip-tls")
        if self.config:
            cmd += ["--config", self.config]
        if self.verbose:
            cmd.append("-v")
        if oob_url:
            cmd += ["--oob-url", oob_url]
        elif oob:
            cmd.append("--oob")

        return cmd
