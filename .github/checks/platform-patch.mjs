import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, lstatSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const MANIFEST_SHA256 = '98cb3bfba0427b9da2cfaa934c2e591bf0905829e69bb3c984b5593a2cfe675a';

export function verifyPlatformPatch(root) {
  const dir = join(root, 'vendor/libcrux-platform-0.0.4');
  const bytes = readFileSync(join(dir, 'UPSTREAM.json'));
  assert.equal(hash(bytes), MANIFEST_SHA256, 'Provenance manifest changed; review required');
  const metadata = JSON.parse(bytes);
  assert.equal(metadata.archiveSha256, '8bf8bee8c35d34867a3762d6ee7b74e8523a882855c3cfce30484e9554342206');
  assert.equal(metadata.sourceCommit, '42d68bd49b244b09bd02626c6ffa95e54dc64f91');
  const expected = new Set(['UPSTREAM.json', 'LICENSE', ...metadata.files.map(f => f.path)]);
  const actual = [];
  function walk(path, prefix = '') {
    for (const name of readdirSync(path)) {
      const rel = prefix + name, full = join(path, name), stat = lstatSync(full);
      assert(!stat.isSymbolicLink(), 'Unexpected symlink: ' + rel);
      if (stat.isDirectory()) walk(full, rel + '/');
      else { assert(stat.isFile(), 'Unexpected input: ' + rel); actual.push(rel); }
    }
  }
  walk(dir);
  assert.deepEqual(actual.sort(), [...expected].sort(), 'Missing or unexpected source inputs');
  assert.equal(hash(readFileSync(join(dir, 'LICENSE'))), metadata.licenseSha256);
  for (const file of metadata.files) {
    const source = readFileSync(join(dir, file.path));
    assert.equal(hash(source), file.localSha256, 'Source changed: ' + file.path);
    if (file.path !== 'src/x86.rs') assert.equal(file.localSha256, file.upstreamSha256);
    else {
      let original = source.toString('utf8');
      for (const call of ['__cpuid(0)', '__cpuid(1)', '__cpuid_count(7, 0)']) {
        const replacement = 'unsafe { ' + call + ' }';
        assert.equal(original.split(replacement).length, 2, 'Expected one compatibility change: ' + call);
        original = original.replace(replacement, call);
      }
      assert.equal(hash(original), file.upstreamSha256, 'Additional x86 changes require review');
    }
  }
  const rootManifest = readFileSync(join(root, 'Cargo.toml'), 'utf8');
  const wasmManifest = readFileSync(join(root, 'codetalker-wasm/Cargo.toml'), 'utf8');
  assert(rootManifest.includes('libcrux-platform = { path = "vendor/libcrux-platform-0.0.4" }'), 'Root patch binding missing');
  assert(wasmManifest.includes('libcrux-platform = { path = "../vendor/libcrux-platform-0.0.4" }'), 'WASM patch binding missing');
  return { files: metadata.files.length, sourceCommit: metadata.sourceCommit, patchedFiles: ['src/x86.rs'] };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(verifyPlatformPatch(fileURLToPath(new URL('../../', import.meta.url)))));
}
