import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyPlatformPatch } from './platform-patch.mjs';

const original = fileURLToPath(new URL('../../', import.meta.url));
function fixture(fn) {
  const root = mkdtempSync(join(tmpdir(), 'ablation-platform-control-'));
  try {
    mkdirSync(join(root, 'codetalker-wasm'));
    cpSync(join(original, 'Cargo.toml'), join(root, 'Cargo.toml'));
    cpSync(join(original, 'codetalker-wasm/Cargo.toml'), join(root, 'codetalker-wasm/Cargo.toml'));
    cpSync(join(original, 'vendor'), join(root, 'vendor'), { recursive: true });
    return fn(root, join(root, 'vendor/libcrux-platform-0.0.4'));
  } finally { rmSync(root, { recursive: true, force: true }); }
}
test('authentic source and only the three CPUID changes pass', () => fixture(root => assert.equal(verifyPlatformPatch(root).files, 12)));
test('changed implementation fails', () => fixture((root, dir) => {
  writeFileSync(join(dir, 'src/lib.rs'), readFileSync(join(dir, 'src/lib.rs')) + '\n// changed\n');
  assert.throws(() => verifyPlatformPatch(root), /Source changed/);
}));
test('omitted source fails', () => fixture((root, dir) => {
  rmSync(join(dir, 'src/x86.rs'));
  assert.throws(() => verifyPlatformPatch(root), /Missing or unexpected/);
}));
test('injected Cargo configuration fails', () => fixture((root, dir) => {
  mkdirSync(join(dir, '.cargo')); writeFileSync(join(dir, '.cargo/config.toml'), '[build]\nrustflags=[]\n');
  assert.throws(() => verifyPlatformPatch(root), /Missing or unexpected/);
}));
test('symlink fails', () => fixture((root, dir) => {
  rmSync(join(dir, 'src/x86.rs')); symlinkSync(join(original, 'vendor/libcrux-platform-0.0.4/src/x86.rs'), join(dir, 'src/x86.rs'));
  assert.throws(() => verifyPlatformPatch(root), /symlink/);
}));
test('changing source and its metadata cannot silently pass', () => fixture((root, dir) => {
  const meta = JSON.parse(readFileSync(join(dir, 'UPSTREAM.json'))); meta.sourceCommit = '0'.repeat(40);
  writeFileSync(join(dir, 'UPSTREAM.json'), JSON.stringify(meta));
  assert.throws(() => verifyPlatformPatch(root), /manifest changed/);
}));
test('excluded WASM crate must select the same authenticated patch', () => fixture(root => {
  writeFileSync(join(root, 'codetalker-wasm/Cargo.toml'), '[package]\nname="bad"\n');
  assert.throws(() => verifyPlatformPatch(root), /WASM patch binding/);
}));
