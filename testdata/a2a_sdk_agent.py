"""Small A2A v1 agent backed by the current official Python SDK."""

import sys

import uvicorn
from starlette.applications import Starlette

from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    create_agent_card_routes,
    create_jsonrpc_routes,
    create_rest_routes,
)
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Part,
    Task,
    TaskState,
    TaskStatus,
)


class EchoExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, queue: EventQueue) -> None:
        if not context.message or not context.task_id or not context.context_id:
            raise ValueError("missing task context")

        await queue.enqueue_event(
            Task(
                id=context.task_id,
                context_id=context.context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
                history=[context.message],
            )
        )
        updater = TaskUpdater(
            event_queue=queue,
            task_id=context.task_id,
            context_id=context.context_id,
        )
        await updater.add_artifact(
            parts=[Part(text="sdk echo")], name="reply", last_chunk=True
        )
        await updater.complete()

    async def cancel(self, context: RequestContext, queue: EventQueue) -> None:
        updater = TaskUpdater(
            event_queue=queue,
            task_id=context.task_id or "",
            context_id=context.context_id or "",
        )
        await updater.cancel()


def build_app(port: int) -> Starlette:
    base = f"http://127.0.0.1:{port}"
    card = AgentCard(
        name="SDK Compatibility Agent",
        description="A2A SDK compatibility target",
        version="1.0.0",
        capabilities=AgentCapabilities(streaming=False, push_notifications=False),
        default_input_modes=["text"],
        default_output_modes=["text"],
        skills=[
            AgentSkill(
                id="echo", name="Echo", description="Returns a short reply.", tags=["test"]
            )
        ],
        supported_interfaces=[
            AgentInterface(
                protocol_binding="HTTP+JSON",
                protocol_version="1.0",
                url=f"{base}/a2a/rest",
            ),
            AgentInterface(
                protocol_binding="JSONRPC",
                protocol_version="1.0",
                url=f"{base}/a2a/jsonrpc",
            ),
        ],
    )
    handler = DefaultRequestHandler(
        agent_executor=EchoExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    return Starlette(
        routes=[
            *create_agent_card_routes(card),
            *create_jsonrpc_routes(handler, rpc_url="/a2a/jsonrpc"),
            *create_rest_routes(handler, path_prefix="/a2a/rest"),
        ]
    )


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3120
    uvicorn.run(build_app(port), host="127.0.0.1", port=port, log_level="warning")
