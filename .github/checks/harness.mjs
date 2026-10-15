// A static server, a headless Chrome, and a CDP client. No dependencies.
//
// The crate's test suite cannot see defects that exist only in the published
// page, and `check-artifact.sh` only reads the artifact without running it.
// Everything between those two — that a switch does what its caption says, that
// a link restores what it encoded, that a colour clears AA — was checked by
// hand, which means it was checked once.
//
// Deliberately no Playwright or Puppeteer. This repository pins every action to
// a commit SHA and verifies its linter against a recorded hash; adding a
// browser-automation stack with a transitive tree to a project whose argument is
// supply-chain care would cost more than it buys. Node's global WebSocket plus
// `Runtime.evaluate` is the whole client.

import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, extname, normalize } from "node:path";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm",
  ".css": "text/css; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".json": "application/json",
};

// `wasm-pack --target web` uses `instantiateStreaming`, which refuses anything
// not served as application/wasm. A server that guesses would fail here in a way
// that looks like a broken module.
export async function serve(root, port) {
  const server = createServer(async (req, res) => {
    const rel = normalize(decodeURIComponent(req.url.split("?")[0].split("#")[0]))
      .replace(/^(\.\.[/\\])+/, "");
    const path = join(root, rel === "/" ? "index.html" : rel);
    try {
      const body = await readFile(path);
      res.writeHead(200, { "content-type": MIME[extname(path)] ?? "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404).end("not found");
    }
  });
  await new Promise((r) => server.listen(port, "127.0.0.1", r));
  return server;
}

const CHROME_CANDIDATES = [
  process.env.CHROME,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium-browser",
  "/usr/bin/chromium",
].filter(Boolean);

async function findChrome() {
  const { access } = await import("node:fs/promises");
  for (const c of CHROME_CANDIDATES) {
    try { await access(c); return c; } catch { /* next */ }
  }
  throw new Error(
    "no Chrome found. Set CHROME to a binary, or install one of:\n  " +
    CHROME_CANDIDATES.slice(1).join("\n  "));
}

/** Connect a minimal CDP client to the browser's first page target. */
export async function connect(port, {
  fetchImpl = fetch, WebSocketImpl = WebSocket, startupStatus = () => null,
  /* 60s, and the number is a HANG DETECTOR rather than an estimate.
   *
   * This was 10000, which is not a budget a cold Chrome reliably meets.
   * Measured 2026-10-15: a fresh `--user-data-dir` profile took 5936 ms to
   * expose a page target on an unloaded developer machine. That is a 1.7x
   * margin, and a throttled runner spends it -- `wasm` failed twice in a row on
   * `Chrome produced no page target before the startup deadline: fetch failed`,
   * on a commit whose only change was two pinned action SHAs, while every
   * pull_request and push run of the same job passed.
   *
   * Raising it cannot mask a broken browser, which is the only reason this is
   * safe: a Chrome that dies or refuses to start is caught by `startupStatus()`
   * on EVERY poll, one line below, and throws `Chrome startup failed` with its
   * exit code and stderr immediately. The deadline bounds only the wait on a
   * LIVE browser that has not opened its debug port yet. So the old value was
   * not buying strictness, it was converting slow starts into red gates -- and
   * this job is the only thing standing between a broken wasm artifact and
   * main, so a false red here is expensive. */
  startupTimeoutMs = 60000, commandTimeoutMs = 5000, pollMs = 100,
} = {}) {
  let targets;
  let lastError = '';
  const deadline = Date.now() + startupTimeoutMs;
  while (Date.now() < deadline) {
    const stopped = startupStatus();
    if (stopped) throw new Error('Chrome startup failed: ' + stopped);
    try {
      const response = await fetchImpl(`http://127.0.0.1:${port}/json/list`, {
        signal: AbortSignal.timeout(Math.max(1, Math.min(500, deadline - Date.now()))),
      });
      if (!response.ok) throw new Error('Chrome target endpoint HTTP ' + response.status);
      targets = await response.json();
      if (!Array.isArray(targets)) throw new Error('Chrome target response is not an array');
      if (targets.some((t) => t.type === "page")) break;
    } catch (error) { lastError = error.message; }
    await new Promise((r) => setTimeout(r, pollMs));
  }
  const target = Array.isArray(targets) ? targets.find((t) => t.type === "page") : null;
  if (!target) throw new Error('Chrome produced no page target before the startup deadline' +
    (lastError ? ': ' + lastError : ''));
  if (typeof target.webSocketDebuggerUrl !== 'string') throw new Error('Chrome page has no debugger URL');

  const ws = new WebSocketImpl(target.webSocketDebuggerUrl);
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Chrome debugger connection timed out')), commandTimeoutMs);
      const finish = (fn, value) => { clearTimeout(timer); fn(value); };
      ws.onopen = () => finish(resolve);
      ws.onerror = () => finish(reject, new Error('Chrome debugger connection failed'));
      ws.onclose = () => finish(reject, new Error('Chrome debugger closed before connecting'));
    });
  } catch (error) { ws.close(); throw error; }

  let id = 0;
  const pending = new Map();
  const logs = [];
  let closed = false;
  const failPending = (error) => {
    closed = true;
    logs.push('HARNESS ' + error.message);
    for (const job of pending.values()) { clearTimeout(job.timer); job.reject(error); }
    pending.clear();
  };
  ws.onclose = () => failPending(new Error('Chrome debugger disconnected'));
  ws.onerror = () => { failPending(new Error('Chrome debugger transport failed')); ws.close(); };
  ws.onmessage = (m) => {
    try {
      const msg = JSON.parse(m.data);
      if (msg.id && pending.has(msg.id)) {
        const job = pending.get(msg.id);
        clearTimeout(job.timer); pending.delete(msg.id);
        if (msg.error) job.reject(new Error('Chrome CDP ' + job.method + ': ' + JSON.stringify(msg.error)));
        else if (!msg.result || typeof msg.result !== 'object') job.reject(new Error('Malformed Chrome CDP response for ' + job.method));
        else job.resolve(msg.result);
      } else if (msg.method === "Log.entryAdded") {
        if (!msg.params?.entry) throw new Error('Unreadable Chrome log event');
        if (msg.params.entry.level === "error") logs.push("LOG " + msg.params.entry.text);
      } else if (msg.method === "Runtime.exceptionThrown") {
        if (!msg.params?.exceptionDetails) throw new Error('Unreadable Chrome exception event');
        logs.push("EXC " + msg.params.exceptionDetails.text);
      }
    } catch (error) {
      failPending(new Error('Unreadable Chrome debugger response: ' + error.message));
      ws.close();
    }
  };
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      if (closed) { reject(new Error('Chrome debugger is closed')); return; }
      const n = ++id;
      const timer = setTimeout(() => {
        pending.delete(n); reject(new Error('Chrome CDP timed out: ' + method));
      }, commandTimeoutMs);
      pending.set(n, { resolve, reject, timer, method });
      try { ws.send(JSON.stringify({ id: n, method, params })); }
      catch (error) { clearTimeout(timer); pending.delete(n); reject(error); }
    });

  const ev = async (expression) => {
    const r = await send("Runtime.evaluate", {
      expression, awaitPromise: true, returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error(
        expression.slice(0, 70).replace(/\s+/g, " ") + " ... -> " +
        r.exceptionDetails.text + " " + (r.exceptionDetails.exception?.description ?? ""));
    }
    return r.result.value;
  };

  try {
    await send("Log.enable");
    await send("Runtime.enable");
    await send("Page.enable");
    await send("Network.enable");
  // A rerun after editing index.html otherwise serves the previous copy, which
  // once produced a screenshot of a layout bug that had already been fixed.
    await send("Network.setCacheDisabled", { cacheDisabled: true });
  // A headless page whose window is not focused never dispatches focus or blur,
  // so `el.focus()` moves document.activeElement and fires no handler. Without
  // this every keyboard-reachability check below silently tests nothing.
    await send("Emulation.setFocusEmulationEnabled", { enabled: true });
  } catch (error) { ws.close(); throw error; }

  return { send, ev, logs, assertHealthy: () => {
    if (closed) throw new Error('Chrome debugger became unreadable: ' + logs.join('\n'));
  }, close: () => ws.close() };
}

/**
 * Adjacent text that renders as one word.
 *
 * Two sibling `<span>`s authored as separate fields are inline by default, so
 * they run together and "reply { ct }" plus "encapsulates a fresh secret" reads
 * as `reply { ct }encapsulates a fresh secret`. It is invisible in the source,
 * invisible in review, and obvious in a render — which is exactly the kind of
 * defect that gets caught by whoever happens to look. It has now happened twice
 * in this repository, in the handshake sequence and in the social card, from the
 * same author making the same assumption about `<span>`.
 *
 * The signature is precise enough to check: the last line of one element's text
 * ends where the next element's first line begins, with no whitespace authored
 * between them and none at the edges of either. Measured on the *text*, via
 * `Range`, not on the boxes — a table cell whose padding separates the words is
 * separated even though the boxes abut.
 *
 * Where abutting *is* the intent, say so in the markup with `data-joined="why"`
 * rather than teaching this function a list of exceptions: the reason belongs
 * next to the thing it explains, where the next person to touch it will see it.
 *
 * Pass a CSS selector for roots to search. Returns a list of offending pairs.
 */
export const RUN_TOGETHER = (roots) => `(() => {
  const vis = (el) => {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
    // Absolutely positioned things are out of flow; abutting means nothing.
    if (cs.position === 'absolute' || cs.position === 'fixed') return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  const out = [];
  for (const parent of document.querySelectorAll(${JSON.stringify(roots)})) {
    if (parent.closest('[data-joined]')) continue;
    const kids = [...parent.children].filter((e) => (e.textContent || '').trim() && vis(e));
    for (let i = 0; i + 1 < kids.length; i++) {
      const a = kids[i], b = kids[i + 1];
      // Whitespace authored between them, or at the inner edges, means the join
      // was intended.
      let spaced = /\\s$/.test(a.textContent) || /^\\s/.test(b.textContent);
      for (let n = a.nextSibling; n && n !== b && !spaced; n = n.nextSibling) {
        if (n.nodeType === 3 && /\\s/.test(n.textContent)) spaced = true;
      }
      if (spaced) continue;

      const rects = (el) => { const r = document.createRange(); r.selectNodeContents(el);
                              return [...r.getClientRects()].filter((x) => x.width > 0); };
      const ra = rects(a), rb = rects(b);
      if (!ra.length || !rb.length) continue;
      // Where A's text stops, and where B's text starts.
      const end = ra[ra.length - 1], start = rb[0];
      const sameLine = Math.min(end.bottom, start.bottom) - Math.max(end.top, start.top) >
                       0.5 * Math.min(end.height, start.height);
      if (sameLine && start.left - end.right < 2) {
        out.push((parent.className || parent.tagName) + ' :: "' +
                 a.textContent.trim().slice(-22) + '" + "' +
                 b.textContent.trim().slice(0, 22) + '"');
      }
    }
  }
  return out;
})()`;

/** Report, and remember whether anything failed. */
export function reporter(title) {
  const rows = [];
  return {
    /* Run the suite, and turn a throw into a reported failure rather than a
       stack trace where the summary should be. A check that dies partway
       through has still found something; swallowing which one it was makes the
       failure harder to act on than the defect. */
    async run(fn) {
      try {
        await fn();
      } catch (err) {
        this.check("the suite ran to completion", false, String(err).split("\n")[0]);
      }
      return this.finish();
    },
    check(name, ok, detail = "") {
      rows.push({ name, ok });
      process.stdout.write(`${ok ? "  ok  " : " FAIL "} ${name}${detail ? "  — " + detail : ""}\n`);
    },
    finish() {
      const bad = rows.filter((r) => !r.ok);
      process.stdout.write(`\n${title}: ${rows.length - bad.length}/${rows.length} passing\n`);
      if (bad.length) {
        process.stdout.write(bad.map((r) => "  failed: " + r.name).join("\n") + "\n");
        process.exitCode = 1;
      }
      return bad.length === 0;
    },
  };
}

/**
 * Serve `web/`, drive it, tear everything down.
 *
 * `fn` receives { ev, send, goto, logs, base }.
 */
export async function withPage(fn) {
  const executable = await findChrome();
  const port = 8000 + (process.pid % 1000);
  const cdpPort = 9000 + (process.pid % 1000);
  const root = new URL("../../web/", import.meta.url).pathname;
  const base = `http://127.0.0.1:${port}/index.html`;

  const server = await serve(root, port);
  const profile = await mkdtemp(join(tmpdir(), "aw-chrome-"));
  const chrome = spawn(executable, [
    "--headless=new",
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${profile}`,
    // Required in the container CI runs in, and harmless against a throwaway
    // profile serving one local page.
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "about:blank",
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let startupOutput = '', spawnError = '';
  chrome.stderr.on('data', data => { startupOutput = (startupOutput + data.toString()).slice(-4000); });
  chrome.on('error', error => { spawnError = error.message; });
  const startupStatus = () => spawnError || (chrome.exitCode !== null || chrome.signalCode !== null
    ? `exit=${chrome.exitCode}, signal=${chrome.signalCode}; ${startupOutput}` : null);

  let client;
  try {
    client = await connect(cdpPort, { startupStatus });
    const goto = async (url, width = 1280, height = 900) => {
      await client.send("Emulation.setDeviceMetricsOverride", {
        width, height, deviceScaleFactor: 1, mobile: width < 500,
      });
      await client.send("Page.navigate", { url });
      for (let i = 0; i < 120; i++) {
        // `!document.getElementById('console')?.hidden` is `true` when there is
        // no `#console` at all, so the first version of this returned the
        // instant it was called -- on about:blank, before the navigation had
        // even started. It passed locally, where navigation beat the first
        // poll, and failed in CI, where it did not. Optional chaining is the
        // wrong tool for "is this element present and showing".
        const state = await client.ev(`(() => {
          const c = document.getElementById('console');
          const f = document.getElementById('fatal');
          if (f && !f.classList.contains('hidden')) return 'fatal';
          return c && !c.hidden ? 'ready' : 'waiting';
        })()`).catch(() => "waiting");
        if (state === "ready") return;
        // The module failing to load is a real answer, not something to keep
        // waiting twelve seconds for.
        if (state === "fatal") {
          const why = await client.ev(`document.getElementById('fatal').textContent`);
          throw new Error(`the module did not load at ${url}\n${why.trim().slice(0, 400)}`);
        }
        await new Promise((r) => setTimeout(r, 100));
      }
      throw new Error(`the console never appeared at ${url} after 12s`);
    };
    await fn({ ...client, goto, base });
    client.assertHealthy();
  } catch (error) {
    throw new Error(error.message + `\nChrome executable: ${executable}\n` +
      `exit=${chrome.exitCode}, signal=${chrome.signalCode}\n${startupOutput}`, { cause: error });
  } finally {
    client?.close();
    chrome.kill();
    await new Promise((r) => server.close(r));
    await rm(profile, { recursive: true, force: true }).catch(() => {});
  }
}
