// Verify the installed MCP server and exercise a read-only project operation.
import { Client } from '../.tools/ctf/token-optimizer-mcp/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js';
import { StdioClientTransport } from '../.tools/ctf/token-optimizer-mcp/node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';

const root = fileURLToPath(new URL('../', import.meta.url));
const config = JSON.parse(readFileSync(resolve(root, '.mcp.json'), 'utf8'));
const entry = config.mcpServers['token-optimizer'];
const client = new Client({ name: 'ctf-project-check', version: '1.0.0' });
const transport = new StdioClientTransport({
  ...entry, cwd: root, env: { ...process.env, ...entry.env }, stderr: 'inherit',
});
try {
  await client.connect(transport, { timeout: 30000 });
  const { tools } = await client.listTools();
  console.log(`MCP handshake passed: ${tools.length} tools registered`);
  if (!tools.some(tool => tool.name === 'smart_read')) throw new Error('smart_read is missing');
  const result = await client.callTool({
    name: 'smart_read', arguments: { path: resolve(root, 'README.md') },
  });
  if (result.isError || !JSON.stringify(result).includes('Safaricom')) {
    throw new Error(`README read failed: ${JSON.stringify(result)}`);
  }
  console.log('smart_read passed: project README returned');
} finally {
  await client.close();
}
