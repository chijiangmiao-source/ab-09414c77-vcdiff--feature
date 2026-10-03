// Single-shot verification entrypoint used by the `verify` Compose service.
// Runs, in order:
//   1. decoding unit tests (node --test)
//   2. build check (node --check on every source file)
//   3. interface/HTTP smoke test against a freshly started real server
// Exits non-zero on the first failed stage.

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

function run(cmd, args, label) {
  return new Promise((resolve) => {
    console.log(`\n=== [${label}] ${cmd} ${args.join(' ')}`);
    const child = spawn(cmd, args, { cwd: root, stdio: 'inherit' });
    child.on('exit', (code) => resolve(code ?? 1));
  });
}

async function waitForHealth(baseUrl, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`${baseUrl}/healthz`);
      if (r.status === 200) return true;
    } catch {
      // server not up yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

async function smokeTest(baseUrl) {
  console.log(`\n=== [smoke] interface checks on ${baseUrl}`);
  let failures = 0;
  const expect = (cond, what) => {
    console.log(`${cond ? '  ok  ' : '  FAIL'} ${what}`);
    if (!cond) failures += 1;
  };

  const health = await fetch(`${baseUrl}/healthz`).then((r) => r.json());
  expect(health.status === 'ok', 'GET /healthz -> {"status":"ok"}');

  const page = await fetch(`${baseUrl}/`).then((r) => r.text());
  expect(page.includes('增量标定片'), 'GET / serves the workbench page');

  const samples = JSON.parse(readFileSync(join(root, 'fixtures', 'samples.json'), 'utf8'));

  // --- happy path: length + sha256 + per-window source ranges + evidence ---
  const okResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deltaBase64: samples.valid.deltaBase64,
      dictionaryBase64: samples.dictionaryBase64,
    }),
  });
  expect(okResp.status === 200, `valid sample HTTP 200 (got ${okResp.status})`);
  const ok = await okResp.json();
  expect(ok.ok === true, 'valid sample ok=true');
  expect(ok.length === samples.valid.expectedLength, `final length ${ok.length} == ${samples.valid.expectedLength}`);
  expect(ok.sha256 === samples.valid.expectedSha256, `sha256 ${ok.sha256}`);
  expect(ok.windows.length === samples.valid.expectedWindowCount, `window count ${ok.windows.length}`);
  const w2 = ok.windows[1];
  expect(w2.source.kind === 'TARGET' && w2.source.position === 5 && w2.source.length === 11,
    `window 2 source range TARGET [5,+11) (got ${w2.source.kind} [${w2.source.position},+${w2.source.length}))`);
  const copyModes = w2.instructions.filter((i) => i.op === 'COPY').map((i) => i.mode);
  expect(JSON.stringify(copyModes) === JSON.stringify(['SELF', 'NEAR0', 'SAME0']),
    `window 2 copy modes SELF/NEAR0/SAME0 (got ${copyModes})`);
  expect(w2.instructions.every((ins, idx) => ins.seq === idx), 'instructions listed in execution order');
  expect(!('trace' in ok), 'no trace section when trace fields are absent');

  // --- root-origin trace over window 2's output ------------------------------
  const trResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deltaBase64: samples.valid.deltaBase64,
      dictionaryBase64: samples.dictionaryBase64,
      traceStart: 24,
      traceLength: 13,
    }),
  });
  expect(trResp.status === 200, `trace request HTTP 200 (got ${trResp.status})`);
  const tr = await trResp.json();
  const segs = tr.trace?.segments ?? [];
  expect(
    JSON.stringify(segs.map((s) => s.kind)) ===
      JSON.stringify(['SOURCE_DICT', 'ADD', 'ADD', 'SOURCE_DICT', 'ADD']),
    `trace segment kinds (got ${segs.map((s) => s.kind)})`,
  );
  const w1copyOffset = tr.windows[0].instructions.find((i) => i.op === 'COPY').codeOffset;
  const w2copyOffsets = tr.windows[1].instructions
    .filter((i) => i.op === 'COPY')
    .map((i) => i.codeOffset);
  expect(
    segs.length > 0 &&
      segs[0].outputStart === 24 &&
      segs[segs.length - 1].outputEnd === 37 &&
      segs.every((s, i) => i === 0 || s.outputStart === segs[i - 1].outputEnd),
    'trace segments are consecutive and cover [24, 37)',
  );
  expect(
    segs[0].instOffset === w1copyOffset && !segs.some((s) => w2copyOffsets.includes(s.instOffset)),
    'root instruction is window 1 COPY, never a later window 2 COPY',
  );

  // --- invalid trace ranges reject the whole request -------------------------
  const badTraceResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deltaBase64: samples.valid.deltaBase64,
      dictionaryBase64: samples.dictionaryBase64,
      traceStart: 0,
      traceLength: 0,
    }),
  });
  const badTrace = await badTraceResp.json();
  expect(
    badTraceResp.status === 400 && badTrace.error?.code === 'BAD_TRACE',
    `zero-length trace rejected (got ${badTraceResp.status} ${badTrace.error?.code})`,
  );
  const oorTraceResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deltaBase64: samples.valid.deltaBase64,
      dictionaryBase64: samples.dictionaryBase64,
      traceStart: 0,
      traceLength: samples.valid.expectedLength + 1,
    }),
  });
  const oorTrace = await oorTraceResp.json();
  expect(
    oorTraceResp.status === 400 && oorTrace.error?.code === 'TRACE_RANGE',
    `out-of-range trace rejected (got ${oorTraceResp.status} ${oorTrace.error?.code})`,
  );

  // --- failure path: first raw offset, no output ---------------------------
  const badResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deltaBase64: samples.badCopy.deltaBase64,
      dictionaryBase64: samples.dictionaryBase64,
    }),
  });
  expect(badResp.status === 400, `bad-copy sample HTTP 400 (got ${badResp.status})`);
  const bad = await badResp.json();
  expect(bad.ok === false && bad.error.code === 'COPY_NOT_GENERATED',
    `bad-copy code COPY_NOT_GENERATED (got ${bad.error?.code})`);
  expect(bad.error.offset === samples.badCopy.expectedOffset,
    `first raw offset ${bad.error.offset} == ${samples.badCopy.expectedOffset}`);
  expect(!('length' in bad) && !('windows' in bad), 'failure response retains no partial output');

  // --- non-minimal integer failure ------------------------------------------
  const nmResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deltaBase64: samples.nonMinimal.deltaBase64,
      dictionaryBase64: samples.dictionaryBase64,
    }),
  });
  const nm = await nmResp.json();
  expect(nmResp.status === 400 && nm.error.code === 'NON_MINIMAL_INTEGER',
    `non-minimal integer rejected at offset ${nm.error?.offset}`);

  // --- malformed base64 ------------------------------------------------------
  const b64Resp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deltaBase64: 'not-base64!!' }),
  });
  expect((await b64Resp.json()).error.code === 'BAD_BASE64', 'malformed Base64 rejected');

  // --- reset endpoint --------------------------------------------------------
  const resetResp = await fetch(`${baseUrl}/api/reset`, { method: 'POST' });
  expect(resetResp.status === 200, 'POST /api/reset -> 200');

  return failures === 0;
}

async function main() {
  // In Compose, SMOKE_BASE_URL points at the running "web" service.
  // Standalone: a fresh local server is started on SMOKE_PORT.
  const externalBase = process.env.SMOKE_BASE_URL;
  const port = process.env.SMOKE_PORT ?? '18080';
  const localBase = `http://127.0.0.1:${port}`;

  const testCode = await run(process.execPath, ['--test', 'test/'], 'unit tests');
  if (testCode !== 0) {
    console.error('\nVERIFY FAILED: unit tests');
    process.exit(1);
  }

  const checkCode = await run(process.execPath, ['scripts/check-syntax.js'], 'build check');
  if (checkCode !== 0) {
    console.error('\nVERIFY FAILED: build check');
    process.exit(1);
  }

  let baseUrl = externalBase;
  let server = null;

  if (!baseUrl) {
    console.log(`\n=== [smoke] starting local server on port ${port}`);
    server = spawn(process.execPath, ['src/server.js'], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'inherit'],
      env: { ...process.env, HOST: '127.0.0.1', PORT: String(port) },
    });
    server.stdout.on('data', (d) => process.stdout.write(`[server] ${d}`));
    baseUrl = localBase;
  }

  let ok = false;
  try {
    if (!(await waitForHealth(baseUrl))) {
      console.error(`server at ${baseUrl} did not become healthy in time`);
    } else {
      ok = await smokeTest(baseUrl);
    }
  } finally {
    if (server) {
      server.kill('SIGTERM');
      await new Promise((r) => server.on('exit', r));
    }
  }

  if (ok) {
    console.log('\nVERIFY PASSED: unit tests + build check + HTTP smoke all green');
    process.exit(0);
  }
  console.error('\nVERIFY FAILED: HTTP smoke');
  process.exit(1);
}

main().catch((err) => {
  console.error('VERIFY ERRORED:', err);
  process.exit(1);
});
