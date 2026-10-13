import { readFile } from "node:fs/promises";

const root = new URL("../../", import.meta.url);
const paths = {
  mlkem: new URL("vendor/libcrux-ml-kem-0.0.11/src/secret_independence.rs", root),
  xwing: new URL("vendor/libcrux-kem-0.0.10/src/kem.rs", root),
  sha3: new URL("vendor/libcrux-sha3-0.0.11/src/secret.rs", root),
};

const sources = Object.fromEntries(
  await Promise.all(
    Object.entries(paths).map(async ([name, path]) => [name, await readFile(path, "utf8")]),
  ),
);

const fail = (message) => {
  throw new Error(`secret-independence boundary changed: ${message}`);
};
const count = (source, pattern) => [...source.matchAll(pattern)].length;

// All actual declassification is centralized in one helper. The SHA-3 state
// and X-Wing composition must contain none. Adding another site requires an
// explicit review and a deliberate update to this check.
if (count(sources.mlkem, /\.declassify\(\)/g) !== 1) {
  fail("ML-KEM must contain exactly one centralized .declassify() call");
}
if (/\.declassify\(/.test(sources.xwing) || /\.declassify\(/.test(sources.sha3)) {
  fail("X-Wing and typed SHA-3 must not declassify values");
}

const normalized = sources.mlkem.replace(/\s+/g, " ");
const allowed = [
  "declassify_public(&rho_secret)",
  "declassify_public::<PUBLIC_KEY_SIZE>(&public_key_typed)",
  "declassify_public::<CIPHERTEXT_SIZE>(&ciphertext_typed)",
  "declassify_public(&decapsulation_key[public_key_offset..public_key_hash_offset])",
];
for (const boundary of allowed) {
  if (!normalized.includes(boundary)) fail(`missing reviewed public boundary: ${boundary}`);
}
if (count(sources.mlkem, /\bdeclassify_public(?:::<[^>]+>)?\s*\(/g) !== allowed.length) {
  fail("an unreviewed declassify_public call was added or a reviewed call changed");
}

console.log(JSON.stringify({ declassifyMethods: 1, reviewedPublicBoundaries: allowed.length }));
