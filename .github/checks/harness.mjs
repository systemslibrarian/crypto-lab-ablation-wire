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
async function connect(port) {
  let targets;
  for (let i = 0; i < 100; i++) {
    try {
      targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      if (targets.some((t) => t.type === "page")) break;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  const target = targets?.find((t) => t.type === "page");
  if (!target) throw new Error("Chrome came up with no page target");

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });

  let id = 0;
  const pending = new Map();
  const logs = [];
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg.result);
      pending.delete(msg.id);
    } else if (msg.method === "Log.entryAdded" && msg.params.entry.level === "error") {
      logs.push("LOG " + msg.params.entry.text);
    } else if (msg.method === "Runtime.exceptionThrown") {
      logs.push("EXC " + msg.params.exceptionDetails.text);
    }
  };
  const send = (method, params = {}) =>
    new Promise((res) => {
      const n = ++id;
      pending.set(n, res);
      ws.send(JSON.stringify({ id: n, method, params }));
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

  return { send, ev, logs, close: () => ws.close() };
}

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
  const port = 8000 + (process.pid % 1000);
  const cdpPort = 9000 + (process.pid % 1000);
  const root = new URL("../../web/", import.meta.url).pathname;
  const base = `http://127.0.0.1:${port}/index.html`;

  const server = await serve(root, port);
  const profile = await mkdtemp(join(tmpdir(), "aw-chrome-"));
  const chrome = spawn(await findChrome(), [
    "--headless=new",
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${profile}`,
    // Required in the container CI runs in, and harmless against a throwaway
    // profile serving one local page.
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "about:blank",
  ], { stdio: "ignore" });

  let client;
  try {
    client = await connect(cdpPort);
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
  } finally {
    client?.close();
    chrome.kill();
    await new Promise((r) => server.close(r));
    await rm(profile, { recursive: true, force: true }).catch(() => {});
  }
}
