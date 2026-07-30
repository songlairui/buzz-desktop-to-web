#!/usr/bin/env node
const readline = require('readline');
const { spawn } = require('child_process');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

rl.on('line', (line) => {
  if (!line.trim()) return;
  try {
    const req = JSON.parse(line);
    const { id, method, params } = req;

    if (method === 'initialize') {
      send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: 1,
          agentInfo: { name: 'pi-coding-agent', version: '0.81.1' },
          agentCapabilities: {
            loadSession: true,
            promptCapabilities: { image: true, embeddedContext: true },
            sessionCapabilities: { list: {}, close: {} }
          }
        }
      });
    } else if (method === 'session/new' || method === 'session/load') {
      send({
        jsonrpc: '2.0',
        id,
        result: { sessionId: 'pi-session-' + Date.now() }
      });
    } else if (method === 'session/prompt') {
      let promptText = '';
      if (params && params.prompt) {
        if (typeof params.prompt === 'string') {
          promptText = params.prompt;
        } else if (Array.isArray(params.prompt)) {
          promptText = params.prompt
            .map(p => typeof p === 'string' ? p : (p.text || ''))
            .filter(Boolean)
            .join('\n');
        }
      }

      if (!promptText) promptText = 'Hello';

      const piPath = '/home/lary/.local/share/pnpm/bin/pi';
      const child = spawn(piPath, ['-p', promptText], {
        env: {
          ...process.env,
          PATH: '/home/lary/.local/share/pnmp/bin:/home/lary/.local/bin1' + (process.env.PATH ? ':' + process.env.PATH : '')
        }
      });

      child.stdout.on('data', (data) => {
        const text = data.toString('utf8');
        send({
          jsonrpc: '2.0',
          method: 'session/update',
          params: {
            update: {
              sessionUpdate: 'agent_message_chunk',
              content: { type: 'text', text }
            }
          }
        });
      });

      child.on('close', (code) => {
        send({
          jsonrpc: '2.0',
          id,
          result: { stopReason: 'end_turn' }
        });
      });

      child.on('error', (err) => {
        send({
          jsonrpc: '2.0',
          method: 'session/update',
          params: {
            update: {
              sessionUpdate: 'agent_message_chunk',
              content: { type: 'text', text: '[Error spawning pi: ' + err.message + ']' }
            }
          }
        });
        send({
          jsonrpc: '2.0',
          id,
          result: { stopReason: 'end_turn' }
        });
      });
    } else if (id !== undefined) {
      send({
        jsonrpc: '2.0',
        id,
        result: {}
      });
    }
  } catch (err) {
  }
});
