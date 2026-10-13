import ast
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient

from testdata.mcp_oauth_metadata_ssrf_server import app


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "testdata"
POSTURE_FIXTURES = (
    "a2a_push_callback_auth_server.py",
    "mcp_origin_prefix_bypass_server.py",
    "mcp_scope_confusion_server.py",
    "mcp_shadow_surface_server.py",
    "mcp_task_entropy_server.py",
    "mcp_token_replay_server.py",
    "mcp_tool_param_traversal_server.py",
    "mcp_tool_poisoning_server.py",
    "mcp_vulnerable_version_server.py",
)


class FixtureSafetyTests(unittest.TestCase):
    def test_unknown_postures_exit_before_serving(self):
        for name in POSTURE_FIXTURES:
            with self.subTest(name=name):
                result = subprocess.run(
                    [sys.executable, str(FIXTURES / name), "invalid-posture"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unknown posture", result.stderr)

    def test_uvicorn_fixtures_bind_to_loopback(self):
        checked = 0
        for path in FIXTURES.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if not isinstance(node.func.value, ast.Name) or node.func.value.id != "uvicorn":
                    continue
                if node.func.attr != "run":
                    continue
                checked += 1
                with self.subTest(name=path.name, line=node.lineno):
                    hosts = [keyword.value for keyword in node.keywords if keyword.arg == "host"]
                    self.assertEqual(len(hosts), 1)
                    self.assertIsInstance(hosts[0], ast.Constant)
                    self.assertEqual(hosts[0].value, "127.0.0.1")
        self.assertGreater(checked, 0)

        path = FIXTURES / "mcp_param_header_server.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        servers = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == "HTTPServer"]
        self.assertEqual(len(servers), 1)
        self.assertIsInstance(servers[0].args[0], ast.Tuple)
        self.assertEqual(servers[0].args[0].elts[0].value, "127.0.0.1")

    def test_metadata_fetch_requires_opt_in(self):
        app.state.allow_metadata_fetch = False
        try:
            with TestClient(app) as client, patch("urllib.request.urlopen") as urlopen:
                response = client.post("/register", json={"jwks_uri": "http://127.0.0.1:9/jwks"})
                self.assertEqual(response.status_code, 403)
                urlopen.assert_not_called()

                app.state.allow_metadata_fetch = True
                response = client.post("/register", json={"jwks_uri": "http://127.0.0.1:9/jwks"})
                self.assertEqual(response.status_code, 201)
                urlopen.assert_called_once()
        finally:
            app.state.allow_metadata_fetch = False


if __name__ == "__main__":
    unittest.main()
