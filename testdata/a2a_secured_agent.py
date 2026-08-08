"""
A2A agent that ENFORCES AUTHORIZATION. Two postures, one codebase.

Every other A2A fixture here enforces nothing, so for the cross-principal rules
only the positive direction was ever exercised: they fire when a surface is wide
open. This is the negative control, and the gap it closes is not hypothetical.
Three false negatives in the A2A rules were found only by pointing the scanner at
an agent that enforces authorization and has one specific bug:

  - eight rules reported a secured agent CLEAN when the credential they were given
    could not create a task, so there was never a task to test with (PR #175)
  - a2a-delegation-integrity-001 reported that a delegated task's chain of custody
    held while the wrong principal was demonstrably continuing it, because the
    v1.0 send envelope nests the task and its oracle read only the flat shape
    (PR #176)
  - a2a-session-smuggle-001 reported a high-severity indicator against servers
    that store no history at all (PR #177)

Postures, selected by the first argument:

  secured   a bearer token is required AND task ownership is enforced on reads,
            continuations, cancels and push-config writes. Any finding here is a
            FALSE POSITIVE.
  idor      a bearer token is required but ownership is NOT enforced: any valid
            token may act on any task. a2a-multitenant-isolation-001,
            a2a-delegation-integrity-001, a2a-task-cancel-idor-001 and
            a2a-push-binding-001 MUST fire. Silence here is a false negative.

Ownership is the only difference between the two, which is what makes a diff
between them mean something.

WIRE SHAPES ARE REPRODUCED FROM CAPTURED a2a-sdk RESPONSES, not written from the
specification and not from what the rules happen to send. A fixture built from the
scanner's own assumptions vouches for the scanner instead of testing it, which is
how several of these defects survived. The shape that matters most: v1.0
SendMessage answers with the Task NESTED under result.task, because
SendMessageResponse is a protobuf oneof, while v1.0 GetTask answers with a bare
Task, flat. The v0.3 slash methods answer flat with lowercase state strings.

Run:
    python testdata/a2a_secured_agent.py secured
    python testdata/a2a_secured_agent.py idor

Scan (two principals are required by the cross-principal rules; --token drives the
rules that read a single credential):
    batesian scan --target http://127.0.0.1:3111 --token tok-a \\
        --principal name=a,token=tok-a,tenant=A \\
        --principal name=b,token=tok-b,tenant=B -v

Endpoint: http://127.0.0.1:3111/
"""
import sys
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 3111

POSTURES = ("secured", "idor")
POSTURE = sys.argv[1] if len(sys.argv) > 1 else "secured"

# The multi-principal fixtures in this directory all expect these two tokens
# specifically, so a single --principal pair works across the whole set.
TOKENS = {"tok-a": "tenant-a", "tok-b": "tenant-b"}

# task id -> {"ctx", "owner", "state", "history"}
TASKS: dict = {}


def _principal(request: Request) -> str:
    """The principal a bearer token identifies, or "" for none."""
    authz = request.headers.get("authorization", "")
    if not authz.startswith("Bearer "):
        return ""
    return TOKENS.get(authz[len("Bearer "):], "")


def _unauthenticated() -> Response:
    # As the SDK agent answered it: HTTP 401 with a JSON body that is not a
    # JSON-RPC envelope. Rules must treat this as an auth refusal on the status.
    return JSONResponse(
        {"error": "unauthenticated", "message": "a valid bearer token is required"},
        status_code=401,
    )


def _error(req_id, code, message):
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": code, "message": message}})


def _normalized(message: dict) -> dict:
    """A stored copy of message with the role forced to the client role.

    The specification defines ROLE_AGENT as server-to-client. Storing a
    client-authored turn under it is what a2a-session-smuggle-001 reports, so a
    fixture whose findings are meant to be false positives must not do it. Both
    official SDKs DO store it verbatim, which is why that rule fires against them;
    normalizing here is the secure behaviour, and it exercises the rule's
    neutralized branch rather than its confirmed one.
    """
    stored = dict(message)
    role = stored.get("role")
    stored["role"] = 1 if isinstance(role, int) else "user"
    return stored


def _may_touch(task: dict, caller: str) -> bool:
    """Whether caller may act on task. The only place the postures differ."""
    if POSTURE == "idor":
        return True  # any authenticated caller: the bug under test
    return task["owner"] == caller


def _task_body(task_id: str, v1: bool, nest: bool):
    """A Task in the envelope the method actually uses."""
    task = TASKS[task_id]
    state = task["state"]
    body = {
        "id": task_id,
        "contextId": task["ctx"],
        "status": {"state": f"TASK_STATE_{state.upper()}" if v1 else state},
        "history": task["history"],
    }
    if not v1:
        body["kind"] = "task"
    return {"task": body} if (v1 and nest) else body


def _send(req_id, params, caller, v1):
    message = (params or {}).get("message") or {}
    task_id = message.get("taskId") or ""

    if task_id:
        # A continuation. The SDK returns the referenced task rather than appending,
        # logging "Task already exists. Ignoring task replacement." Reproduced as
        # observed: what the rules judge is whether the reply references that task.
        if task_id not in TASKS:
            return _error(req_id, -32001, "Task not found")
        if not _may_touch(TASKS[task_id], caller):
            return _error(req_id, -32600, "not authorized for this task")
        return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                             "result": _task_body(task_id, v1, nest=True)})

    task_id = uuid.uuid4().hex
    TASKS[task_id] = {
        "ctx": uuid.uuid4().hex,
        "owner": caller,
        "state": "submitted",
        "history": [_normalized(message)] if message else [],
    }
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "result": _task_body(task_id, v1, nest=True)})


def _get(req_id, params, caller, v1):
    task_id = (params or {}).get("id") or ""
    if task_id not in TASKS:
        return _error(req_id, -32001, "Task not found")
    if not _may_touch(TASKS[task_id], caller):
        return _error(req_id, -32600, "not authorized for this task")
    # GetTask answers with a bare Task even on v1.0, so never nested.
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "result": _task_body(task_id, v1, nest=False)})


def _cancel(req_id, params, caller, v1):
    task_id = (params or {}).get("id") or ""
    if task_id not in TASKS:
        return _error(req_id, -32001, "Task not found")
    if not _may_touch(TASKS[task_id], caller):
        return _error(req_id, -32600, "not authorized for this task")
    TASKS[task_id]["state"] = "canceled"
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "result": _task_body(task_id, v1, nest=False)})


def _set_push(req_id, params, caller):
    task_id = (params or {}).get("taskId") or ""
    if task_id not in TASKS:
        return _error(req_id, -32001, "Task not found")
    if not _may_touch(TASKS[task_id], caller):
        return _error(req_id, -32600, "not authorized for this task")
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "result": {"taskId": task_id, "url": "set", "token": "set"}})


async def agent_card(request: Request) -> JSONResponse:
    # The URL is pinned rather than built from request.base_url. Echoing the Host
    # header into the card is a real weakness (a2a-wellknown-hostinject-001 fires on
    # it, correctly), and this fixture exists so that a finding against the secured
    # posture means the scanner is wrong, not the fixture.
    return JSONResponse(
        {
            "name": f"Secured Echo Agent ({POSTURE})",
            "description": "Authorization-enforcing A2A fixture",
            "version": "1.0.0",
            "protocolVersion": "1.0",
            "capabilities": {"pushNotifications": True},
            "skills": [],
            "supportedInterfaces": [
                {"url": f"http://127.0.0.1:{PORT}/", "protocolBinding": "JSONRPC",
                 "protocolVersion": "1.0"},
            ],
        },
        # The card is a trust anchor, so it must not be cached without revalidation.
        headers={"Cache-Control": "no-store"},
    )


async def jsonrpc(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        return _error(None, -32700, "Parse error")
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params") or {}

    # Authorization first, in both postures.
    caller = _principal(request)
    if not caller:
        return _unauthenticated()

    if method in ("SendMessage", "message/send"):
        return _send(req_id, params, caller, v1=method == "SendMessage")
    if method in ("GetTask", "tasks/get"):
        return _get(req_id, params, caller, v1=method == "GetTask")
    if method in ("CancelTask", "tasks/cancel"):
        return _cancel(req_id, params, caller, v1=method == "CancelTask")
    if method in ("CreateTaskPushNotificationConfig", "tasks/pushNotificationConfig/set"):
        return _set_push(req_id, params, caller)
    return _error(req_id, -32601, "Method not found")


app = Starlette(routes=[
    Route("/.well-known/agent-card.json", agent_card, methods=["GET"]),
    Route("/.well-known/agent.json", agent_card, methods=["GET"]),
    Route("/", jsonrpc, methods=["POST"]),
])

if __name__ == "__main__":
    if POSTURE not in POSTURES:
        sys.exit(f"unknown posture {POSTURE!r}; expected one of {', '.join(POSTURES)}")
    print(f"[*] A2A authorization-enforcing agent ({POSTURE}) on http://127.0.0.1:{PORT}/", flush=True)
    if POSTURE == "secured":
        print("[*] Expected: no findings. Any finding is a false positive.", flush=True)
    else:
        print("[*] Expected: multitenant-isolation, delegation-integrity, "
              "task-cancel-idor and push-binding all fire.", flush=True)
    print("[*] Credentials: --token tok-a plus two principals (tok-a, tok-b)", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
