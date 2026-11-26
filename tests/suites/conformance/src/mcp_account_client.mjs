// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const [url, account, toolsJson, expectConnection] = process.argv.slice(1);
let value;
if (account === 'unknown') {
  value = 'openshell:resolve:env:E2E_MCP_UNKNOWN';
} else if (account !== 'missing') {
  value = process.env[account];
  assert(value, 'the selected account has no credential placeholder');
}

const transport = new StreamableHTTPClientTransport(new URL(url), {
  requestInit: { headers: value ? { Authorization: `Bearer ${value}` } : {} }
});
const client = new Client(
  { name: 'openshell-account-policy-test', version: '1' },
  { capabilities: {} }
);
const denied = async (action) => {
  await assert.rejects(action, (err) => err.code === 403 || String(err).includes('403'));
};
try {
  if (expectConnection === 'denied') {
    await denied(() => client.connect(transport));
    console.log('SDK_CONNECT_DENIED');
  } else {
    await client.connect(transport);
    const tools = await client.listTools();
    assert.deepEqual(tools.tools.map(({ name }) => name), ['search', 'send']);
    for (const [name, allowed] of JSON.parse(toolsJson)) {
      if (allowed) {
        const result = await client.callTool({ name, arguments: {} });
        assert.equal(result.content[0].text, name);
      } else {
        await denied(() => client.callTool({ name, arguments: {} }));
      }
    }
    console.log('SDK_CALLS_OK');
  }
} finally {
  await transport.close();
}
