// Regenerate web/og.png from .github/og-card.html.
//
// Not a check — a generator, kept beside them because it uses the same harness
// and because a social card that nobody can rebuild is one that silently goes
// stale. The previous one showed a console that predated the guided lab.
//
// Run with: node .github/checks/og.mjs

import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serve } from "./harness.mjs";

const root = new URL("../../", import.meta.url).pathname;
const OUT = join(root, "web/og.png");
const port = 8791, cdp = 9791;

const server = await serve(join(root, ".github"), port);
const profile = await mkdtemp(join(tmpdir(), "og-"));
const { default: which } = { default: null };
const candidates = [
  process.env.CHROME,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
].filter(Boolean);
const { access } = await import("node:fs/promises");
let bin = null;
for (const c of candidates) { try { await access(c); bin = c; break; } catch { /* next */ } }
if (!bin) throw new Error("no Chrome found; set CHROME");

const chrome = spawn(bin, [
  "--headless=new", `--remote-debugging-port=${cdp}`, `--user-data-dir=${profile}`,
  "--no-sandbox", "--disable-gpu", "--force-device-scale-factor=1", "about:blank",
], { stdio: "ignore" });

try {
  let target;
  for (let i = 0; i < 100; i++) {
    try {
      target = (await (await fetch(`http://127.0.0.1:${cdp}/json/list`)).json())
        .find((t) => t.type === "page");
      if (target) break;
    } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let id = 0; const pending = new Map();
  ws.onmessage = (m) => {
    const x = JSON.parse(m.data);
    if (pending.has(x.id)) { pending.get(x.id)(x.result); pending.delete(x.id); }
  };
  const send = (method, params = {}) =>
    new Promise((res) => { const n = ++id; pending.set(n, res); ws.send(JSON.stringify({ id: n, method, params })); });

  await send("Page.enable");
  // The card is exactly the dimensions og:image:width / og:image:height declare.
  await send("Emulation.setDeviceMetricsOverride",
    { width: 1200, height: 630, deviceScaleFactor: 1, mobile: false });
  await send("Page.navigate", { url: `http://127.0.0.1:${port}/og-card.html` });
  await new Promise((r) => setTimeout(r, 900));
  const { data } = await send("Page.captureScreenshot", {
    format: "png",
    clip: { x: 0, y: 0, width: 1200, height: 630, scale: 1 },
  });
  await writeFile(OUT, Buffer.from(data, "base64"));
  process.stdout.write(`wrote web/og.png (1200x630)\n`);
  ws.close();
} finally {
  chrome.kill();
  await new Promise((r) => server.close(r));
  await rm(profile, { recursive: true, force: true }).catch(() => {});
}
