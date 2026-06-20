"""
Deliberately vulnerable A2A test server for validating:
  - a2a-context-fixation-001: the server ADOPTS a client-supplied contextId and
    merges different principals' messages under it, so an attacker who fixes a
    contextId can read a victim's messages (session/context fixation, CWE-384).

Two principals are distinguished by bearer token:
  Authorization: Bearer tok-a  -> tenant A
  Authorization: Bearer tok-b  -> tenant B

Messaging is authenticated (unauthenticated requests are rejected) - which is
what separates this from a no-auth server. The bugs are: (1) the client-supplied
contextId is honored verbatim, and (2) GetTask returns the WHOLE context's
history regardless of which principal authored each message.

Validate against it (two principals required):
  python testdata/a2a_context_fixation_server.py
  batesian scan --target http://127.0.0.1:3104 \\
      --rule-ids a2a-context-fixation-001 \\
      --principal name=tenant-a,token=tok-a,tenant=A \\
      --principal name=tenant-b,token=tok-b,tenant=B -v

Run: python testdata/a2a_context_fixation_server.py
"""
import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

PORT = 3104

# contextId -> list of {"tenant", "text", "taskId"}
CTX_MSGS: dict = {}
# taskId -> contextId
TASK_CTX: dict = {}
TOKEN_TENANT = {"tok-a": "A", "tok-b": "B"}
_counter = 0


def tenant_of(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
    return TOKEN_TENANT.get(token, "")


def rpc_result(req_id, result):
    return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}),
                    media_type="application/json")


def rpc_error(req_id, code, message):
    return Response(json.dumps({"jsonrpc": "2.0", "id": req_id,
                                "error": {"code": code, "message": message}}),
                    media_type="application/json")


async def rpc(request: Request) -> Response:
    global _counter
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})
    message = params.get("message", {})
    tenant = tenant_of(request)

    if method in ("SendMessage", "message/send"):
        if not tenant:
            return rpc_error(req_id, -32600, "authentication required")
        # VULNERABLE: honor the client-supplied contextId verbatim.
        ctx_id = message.get("contextId") or "srv-ctx"
        parts = message.get("parts", [])
        text = parts[0].get("text", "") if parts else ""
        _counter += 1
        task_id = f"task-{tenant}-{_counter}"
        CTX_MSGS.setdefault(ctx_id, []).append({"tenant": tenant, "text": text, "taskId": task_id})
        TASK_CTX[task_id] = ctx_id
        return rpc_result(req_id, {"id": task_id, "contextId": ctx_id, "status": "working"})

    if method in ("GetTask", "tasks/get"):
        if not tenant:
            return rpc_error(req_id, -32600, "authentication required")
        task_id = params.get("id", "")
        ctx_id = TASK_CTX.get(task_id, "")
        # VULNERABLE: return the WHOLE context conversation, not just this task's.
        history = [
            {"role": "user", "parts": [{"text": m["text"]}]}
            for m in CTX_MSGS.get(ctx_id, [])
        ]
        return rpc_result(req_id, {"id": task_id, "contextId": ctx_id, "history": history})

    return rpc_error(req_id, -32601, "Method not found")


app = Starlette(routes=[Route("/", rpc, methods=["POST"])])

if __name__ == "__main__":
    print(f"[*] A2A context-fixation vulnerable server on port {PORT}", flush=True)
    print("[*] Tokens: tok-a (tenant A), tok-b (tenant B)", flush=True)
    print("[*] Vulnerability: honors client contextId + merges principals' messages", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
