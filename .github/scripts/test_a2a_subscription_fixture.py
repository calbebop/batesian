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


if __name__ == "__main__":
    unittest.main()
