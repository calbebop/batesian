"""Modern MCP parameter-header fixture: vulnerable and patched postures."""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


PORT = 7814
VERSION = "2026-07-28"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
        except (ValueError, TypeError):
            self.send_error(400)
            return

        method = request.get("method")
        request_id = request.get("id")
        if method == "initialize":
            self.reply(request_id, error=(-32601, "Method not found"))
            return
        if (self.headers.get("Mcp-Protocol-Version") != VERSION
                or self.headers.get("Mcp-Method") != method):
            self.reply(request_id, status=400, error=(-32020, "HeaderMismatch"))
            return

        if method == "server/discover":
            self.reply(request_id, result={
                "resultType": "complete",
                "supportedVersions": [VERSION],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "param-header-fixture", "version": "1"},
            })
        elif method == "tools/list":
            self.reply(request_id, result={
                "resultType": "complete",
                "tools": [{
                    "name": "lookup",
                    "annotations": {"readOnlyHint": True},
                    "inputSchema": {
                        "type": "object",
                        "properties": {"region": {
                            "type": "string", "x-mcp-header": "Region",
                        }},
                    },
                }],
            })
        elif method == "tools/call":
            params = request.get("params") or {}
            args = params.get("arguments") or {}
            meta = params.get("_meta") or {}
            region = args.get("region")
            if (params.get("name") != "lookup"
                    or self.headers.get("Mcp-Name") != "lookup"
                    or meta.get("io.modelcontextprotocol/protocolVersion") != VERSION
                    or not isinstance(region, str) or not region):
                self.reply(request_id, error=(-32602, "Invalid params"))
            elif (self.headers.get("Mcp-Param-Region") != region
                    and self.server.posture == "patched"):
                self.reply(request_id, status=400, error=(-32020, "HeaderMismatch"))
            else:
                self.reply(request_id, result={
                    "resultType": "complete", "content": [], "isError": False,
                })
        else:
            self.reply(request_id, error=(-32601, "Method not found"))

    def reply(self, request_id, status=200, result=None, error=None):
        body = {"jsonrpc": "2.0", "id": request_id}
        if error is None:
            body["result"] = result
        else:
            body["error"] = {"code": error[0], "message": error[1]}
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    posture = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"
    if posture not in {"vulnerable", "patched"}:
        raise SystemExit("posture must be vulnerable or patched")
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    server.posture = posture
    print(f"MCP parameter-header fixture ({posture}) on port {PORT}", flush=True)
    server.serve_forever()
