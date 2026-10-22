import json
import unittest

from starlette.testclient import TestClient

from testdata import a2a_push_binding_server as fixture


class SubscriptionFixtureTests(unittest.TestCase):
    def test_read_denial_and_subscription_postures(self):
        original = fixture.BOUND
        try:
            for method in ("SubscribeToTask", "tasks/resubscribe"):
                for bound in (False, True):
                    with self.subTest(method=method, bound=bound):
                        fixture.BOUND = bound
                        fixture.TASK_OWNER.clear()
                        fixture.PUSH_CFG.clear()
                        with TestClient(fixture.app) as client:
                            owner = {"Authorization": "Bearer tok-a"}
                            other = {"Authorization": "Bearer tok-b"}
                            created = client.post("/", headers=owner, json={
                                "jsonrpc": "2.0", "id": "create", "method": "SendMessage", "params": {},
                            }).json()
                            task_id = created["result"]["id"]
                            denied = client.post("/", headers=other, json={
                                "jsonrpc": "2.0", "id": "read", "method": "GetTask",
                                "params": {"id": task_id},
                            }).json()
                            self.assertIn("error", denied)
                            response = client.post("/", headers=other, json={
                                "jsonrpc": "2.0", "id": "subscribe", "method": method,
                                "params": {"id": task_id},
                            })
                            if bound:
                                self.assertIn("error", response.json())
                            else:
                                self.assertIn("text/event-stream", response.headers["content-type"])
                                event = json.loads(response.text.removeprefix("data: ").strip())
                                self.assertEqual(event["id"], "subscribe")
                                self.assertEqual(event["result"]["id"], task_id)
                                self.assertEqual(event["result"]["contextId"], "ctx-tenant-a")
        finally:
            fixture.BOUND = original
            fixture.TASK_OWNER.clear()
            fixture.PUSH_CFG.clear()

    def test_rest_read_denial_and_subscription_postures(self):
        original_binding, original_bound = fixture.BINDING, fixture.BOUND
        try:
            fixture.BINDING = "rest"
            for bound in (False, True):
                with self.subTest(bound=bound):
                    fixture.BOUND = bound
                    fixture.TASK_OWNER.clear()
                    with TestClient(fixture.app) as client:
                        owner = {"Authorization": "Bearer tok-a"}
                        other = {"Authorization": "Bearer tok-b"}
                        card = client.get("/.well-known/agent-card.json").json()
                        self.assertEqual(card["supportedInterfaces"][0]["protocolBinding"], "HTTP+JSON")
                        task_id = client.post("/agent/message:send", headers=owner, json={
                            "message": {"role": "ROLE_USER", "parts": [{"text": "probe"}]},
                        }).json()["task"]["id"]
                        self.assertEqual(client.get(f"/agent/tasks/{task_id}", headers=other).status_code, 404)
                        response = client.post(f"/agent/tasks/{task_id}:subscribe", headers=other,
                                               json={"id": task_id})
                        if bound:
                            self.assertEqual(response.status_code, 404)
                        else:
                            self.assertIn("text/event-stream", response.headers["content-type"])
                            event = json.loads(response.text.removeprefix("data: ").strip())
                            self.assertEqual(event["task"]["id"], task_id)
                            self.assertEqual(event["task"]["contextId"], "ctx-tenant-a")
        finally:
            fixture.BINDING, fixture.BOUND = original_binding, original_bound
            fixture.TASK_OWNER.clear()


if __name__ == "__main__":
    unittest.main()
