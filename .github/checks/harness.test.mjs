import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from './harness.mjs';

const page = { type: 'page', webSocketDebuggerUrl: 'ws://fixture/' };
const fetchImpl = async () => ({ ok: true, json: async () => [page] });
function socket(handler, { open = true } = {}) {
  return class {
    constructor() { if (open) queueMicrotask(() => this.onopen?.()); }
    send(raw) { const msg = JSON.parse(raw); queueMicrotask(() => handler(this, msg)); }
    reply(msg, result = {}) { this.onmessage?.({ data: JSON.stringify({ id: msg.id, result }) }); }
    close() { queueMicrotask(() => this.onclose?.()); }
  };
}
const good = (ws, msg) => ws.reply(msg, msg.method === 'Runtime.evaluate'
  ? { result: { value: 42 } } : {});
const options = WebSocketImpl => ({ fetchImpl, WebSocketImpl, startupTimeoutMs: 20, commandTimeoutMs: 30, pollMs: 1 });

test('positive control initializes every verification stage and evaluates', async () => {
  const stages = [];
  const client = await connect(1, options(socket((ws, msg) => { stages.push(msg.method); good(ws, msg); })));
  try {
    assert.deepEqual(stages, ['Log.enable','Runtime.enable','Page.enable','Network.enable','Network.setCacheDisabled','Emulation.setFocusEmulationEnabled']);
    assert.equal(await client.ev('40 + 2'), 42); client.assertHealthy(); assert.deepEqual(client.logs, []);
  } finally { client.close(); }
});
for (const stage of ['Log.enable', 'Network.setCacheDisabled', 'Emulation.setFocusEmulationEnabled']) {
  test('CDP error in '+stage+' rejects initialization', async () => {
    await assert.rejects(connect(1, options(socket((ws,msg) => {
      if (msg.method === stage) ws.onmessage({data:JSON.stringify({id:msg.id,error:{code:-32601,message:'unavailable stage'}})});
      else good(ws,msg);
    }))), new RegExp('Chrome CDP '+stage));
  });
}
test('a command response with missing result is unreadable', async () => {
  await assert.rejects(connect(1, options(socket((ws,msg) => ws.onmessage({data:JSON.stringify({id:msg.id})})))), /Malformed Chrome CDP/);
});
test('malformed protocol JSON rejects pending work', async () => {
  await assert.rejects(connect(1, options(socket(ws => ws.onmessage({data:'{broken'})))), /Unreadable Chrome debugger/);
});
test('command timeout rejects instead of hanging', async () => {
  await assert.rejects(connect(1, options(socket(() => {}))), /CDP timed out: Log.enable/);
});
test('disconnect rejects pending verification', async () => {
  await assert.rejects(connect(1, options(socket(ws => ws.close()))), /disconnected/);
});
test('late disconnect cannot produce a healthy finished verification', async () => {
  const client = await connect(1, options(socket(good)));
  client.close(); await new Promise(resolve => setTimeout(resolve, 0));
  assert.throws(() => client.assertHealthy(), /became unreadable/);
  await assert.rejects(client.send('Runtime.evaluate'), /closed/);
});
test('WebSocket startup timeout is explicit', async () => {
  await assert.rejects(connect(1, options(socket(good, {open:false}))), /connection timed out/);
});
test('failed Chrome process retains its actual startup diagnostic', async () => {
  await assert.rejects(connect(1, {...options(socket(good)), startupStatus:()=> 'exit=2; fixture library unavailable'}), /exit=2; fixture library unavailable/);
});
for (const [name, response, expected] of [
  ['HTTP error', {ok:false,status:503}, /HTTP 503/],
  ['malformed target list', {ok:true,json:async()=>({unexpected:true})}, /not an array/],
  ['no page target', {ok:true,json:async()=>[]}, /no page target/],
  ['missing debugger URL', {ok:true,json:async()=>[{type:'page'}]}, /no debugger URL/],
]) {
  test(name+' remains unreadable', async () => {
    await assert.rejects(connect(1, {...options(socket(good)), fetchImpl:async()=>response}), expected);
  });
}
