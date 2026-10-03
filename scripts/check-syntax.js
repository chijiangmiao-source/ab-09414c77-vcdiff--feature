// Build check for a zero-dependency project: parse every JavaScript file with
// `node --check` (no execution). Exit code is non-zero on the first failure.

import { execFileSync } from 'node:child_process';
import { readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const SKIP_DIRS = new Set(['node_modules', '.git', 'coverage']);

function listJs(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...listJs(full));
    else if (entry.endsWith('.js')) out.push(full);
  }
  return out;
}

const files = listJs(root);
let failed = 0;
for (const file of files) {
  try {
    execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
    console.log(`check ok  ${file.slice(root.length + 1)}`);
  } catch (err) {
    failed += 1;
    console.error(`check FAIL ${file}\n${err.stderr?.toString() ?? err.message}`);
  }
}

console.log(failed === 0 ? `\nbuild check passed (${files.length} files)` : `\nbuild check FAILED (${failed} files)`);
process.exit(failed === 0 ? 0 : 1);
