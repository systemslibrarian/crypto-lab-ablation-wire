// Do the documents point at things that exist?
//
// `check-artifact.sh` verifies the *page's* references resolve inside the deploy
// directory. Nothing verified the documents': TEACHING.md hands a classroom five
// live URLs and several relative paths, and the page footer links to four
// markdown files by absolute GitHub blob URL. A rotted link in a lab handout
// fails in front of a room, which is the worst place to find out.
//
// Deliberately offline. Every link checked here is one this repository controls
// — a relative path, a blob URL into its own tree, or a URL into its own Pages
// site — so all of them are checkable against the working copy. Fetching
// third-party URLs in CI would buy a check that fails for reasons outside the
// repo and teaches everyone to ignore it.
//
// Run with: node .github/checks/links.mjs

import { readFile, access } from "node:fs/promises";
import { readdir } from "node:fs/promises";
import { join, dirname, resolve } from "node:path";

const root = new URL("../../", import.meta.url).pathname;
const SITE = "https://systemslibrarian.github.io/crypto-lab-ablation-wire/";
const BLOB = "https://github.com/systemslibrarian/crypto-lab-ablation-wire/blob/main/";

const rows = [];
const fail = (where, link, why) => rows.push({ where, link, why });

const exists = async (p) => { try { await access(p); return true; } catch { return false; } };

/** Markdown `[text](target)` and HTML `href="target"`. */
function links(text) {
  const out = [];
  for (const m of text.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) out.push(m[1]);
  for (const m of text.matchAll(/href="([^"]+)"/g)) out.push(m[1]);
  return out;
}

/** Every `## Heading` as the anchor GitHub would generate for it. */
function anchors(text) {
  return new Set([...text.matchAll(/^#{1,6}\s+(.+)$/gm)].map(([, h]) =>
    h.trim().toLowerCase()
      .replace(/[^\w\s-]/g, "")
      .replace(/\s+/g, "-")));
}

const cache = new Map();
async function read(path) {
  if (!cache.has(path)) cache.set(path, await readFile(path, "utf8").catch(() => null));
  return cache.get(path);
}

async function checkTarget(where, raw) {
  // Strip a fragment, but keep it: a link to a heading that does not exist is
  // still a broken link, just a quieter one.
  const [target, frag] = raw.split("#");
  let path = null;

  if (raw.startsWith(SITE)) {
    // Into our own Pages site. The deploy artifact is `web/`, so the path has to
    // resolve inside it; the fragment is the console's own state and is checked
    // by `console.mjs` rather than here.
    const rel = raw.slice(SITE.length).split("#")[0] || "index.html";
    if (!(await exists(join(root, "web", rel)))) fail(where, raw, `web/${rel} is not in the deploy artifact`);
    return;
  }
  if (raw.startsWith(BLOB)) {
    path = join(root, target.slice(BLOB.length));
  } else if (/^https?:|^mailto:|^data:/.test(raw)) {
    return; // third-party, deliberately not fetched
  } else if (raw.startsWith("/")) {
    // Site-absolute. GitHub Pages serves this project under
    // /crypto-lab-ablation-wire/, so a correct link carries that prefix and
    // resolves inside `web/`; one that does not is pointing off the site, which
    // is the mistake this branch exists to catch.
    const base = "/crypto-lab-ablation-wire/";
    if (!target.startsWith(base)) {
      return fail(where, raw, "site-absolute but outside the published path");
    }
    const rel = target.slice(base.length) || "index.html";
    if (!(await exists(join(root, "web", rel)))) fail(where, raw, `web/${rel} does not exist`);
    return;
  } else if (raw.startsWith("#")) {
    path = join(root, where); // an anchor within this same document
  } else {
    path = resolve(root, dirname(where), target || where);
  }

  if (!(await exists(path))) return fail(where, raw, "no such file");
  if (frag && path.endsWith(".md")) {
    const body = await read(path);
    if (body && !anchors(body).has(frag.toLowerCase())) fail(where, raw, `no heading "${frag}"`);
  }
}

const docs = (await readdir(root)).filter((f) => f.endsWith(".md"));
docs.push("web/index.html", "web/404.html", "web/README.md");

for (const doc of docs) {
  const body = await read(join(root, doc));
  if (body === null) continue;
  for (const l of links(body)) await checkTarget(doc, l);
}

const checked = docs.length;
if (rows.length) {
  for (const r of rows) process.stdout.write(` FAIL  ${r.where} -> ${r.link}  — ${r.why}\n`);
  process.stdout.write(`\nlinks: ${rows.length} broken across ${checked} documents\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`  ok   every internal link in ${checked} documents resolves\n`);
  process.stdout.write(`\nlinks: 0 broken\n`);
}
