import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { loadSkills } from '@modelcontextprotocol/server/ext/skills/node';
import {
  localhostHostValidation,
  localhostOriginValidation,
  toNodeHandler,
} from '@modelcontextprotocol/node';

const skills = await loadSkills(fileURLToPath(new URL('./skills', import.meta.url)), { strict: true });

const handler = createMcpHandler(() => {
  const server = new McpServer({ name: 'batesian-ts-fixture', version: '1.0.0' });
  skills.attach(server);
  server.registerTool('fixture_ping', { description: 'Return a fixed test value' }, async () => ({
    content: [{ type: 'text', text: 'fixture-pong' }],
  }));
  return server;
});

const nodeHandler = toNodeHandler(handler);
const validateHost = localhostHostValidation();
const validateOrigin = localhostOriginValidation();
const httpServer = createServer((req, res) => {
  if (!validateHost(req, res) || !validateOrigin(req, res)) return;
  void nodeHandler(req, res);
});

httpServer.listen(7798, '127.0.0.1');

async function shutdown() {
  httpServer.close();
  await handler.close();
}

process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);
