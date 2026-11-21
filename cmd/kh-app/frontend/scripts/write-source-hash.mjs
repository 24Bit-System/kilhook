// Records a content hash of every frontend input in dist/.source-hash so the
// verify gate can detect a stale bundle without relying on file mtimes.
// Git does not preserve mtimes on checkout, so a fresh clone can make src/
// look newer than dist/ even when the bundle is current.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const inputs = [
  'src',
  'bindings',
  'public',
  'vendor', // file: dependency with a security patch; reverting it must fail the gate
  'scripts/write-source-hash.mjs',
  'index.html',
  'package.json',
  'package-lock.json',
  'svelte.config.js',
  'tsconfig.json',
  'vite.config.ts',
  '.npmrc',
];

function walk(path, out) {
  if (!existsSync(path)) return;
  const st = statSync(path);
  if (st.isDirectory()) {
    for (const name of readdirSync(path).sort()) walk(join(path, name), out);
  } else if (st.isFile()) {
    out.push(path);
  }
}

const files = [];
for (const input of inputs) walk(join(root, input), files);
files.sort();

const h = createHash('sha256');
for (const file of files) {
  const rel = relative(root, file).split(sep).join('/');
  h.update(rel + '\0');
  // Normalise CRLF so a checkout with a different autocrlf setting does not
  // make the committed hash look stale (git does not preserve line endings
  // consistently across platforms without .gitattributes).
  h.update(readFileSync(file, 'utf8').replace(/\r\n/g, '\n'));
  h.update('\0');
}
const digest = h.digest('hex');
const hashPath = join(root, 'dist', '.source-hash');

if (process.argv.includes('--check')) {
  if (!existsSync(hashPath)) {
    console.error('frontend bundle has no .source-hash (run: npm run build)');
    process.exit(1);
  }
  if (readFileSync(hashPath, 'utf8').trim() !== digest) {
    console.error('frontend/dist is stale: sources changed since the last build (run: npm run build)');
    process.exit(1);
  }
  console.log('frontend bundle matches sources');
} else {
  mkdirSync(join(root, 'dist'), { recursive: true });
  writeFileSync(hashPath, digest + '\n');
  console.log('wrote dist/.source-hash');
}
