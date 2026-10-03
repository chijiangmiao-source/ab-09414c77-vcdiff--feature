import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/server.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

let server;
let port;
let sample;
let base;

before(async () => {
  sample = JSON.parse(readFileSync(join(root, 'fixtures', 'samples.json'), 'utf8'));
  server = createApp();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = server.address().port;
  base = `http://127.0.0.1:${port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

async function post(path, bodyObj) {
  return fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(bodyObj),
  });
}

describe('HTTP surface', () => {
  test('GET /healthz returns ok', async () => {
    const resp = await fetch(`${base}/healthz`);
    assert.equal(resp.status, 200);
    assert.deepEqual(await resp.json(), { status: 'ok' });
  });

  test('GET / serves the page', async () => {
    const resp = await fetch(`${base}/`);
    assert.equal(resp.status, 200);
    const body = await resp.text();
    assert.match(body, /VCDIFF RFC 3284/);
    assert.match(body, /清空输入与结论/);
  });

  test('POST /api/decode with the valid sample reports length, sha256 and windows', async () => {
    const resp = await post('/api/decode', {
      deltaBase64: sample.valid.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
    });
    assert.equal(resp.status, 200);
    const data = await resp.json();
    assert.equal(data.ok, true);
    assert.equal(data.length, sample.valid.expectedLength);
    assert.equal(data.sha256, sample.valid.expectedSha256);
    assert.equal(data.windows.length, 2);

    const [w1, w2] = data.windows;
    assert.equal(w1.source.kind, 'SOURCE');
    assert.equal(w2.source.kind, 'TARGET');
    assert.deepEqual([w2.source.position, w2.source.length], [5, 11]);
    assert.equal(w2.targetLength, 13);

    // Instructions listed in execution order.
    assert.deepEqual(
      w2.instructions.map((i) => i.seq),
      [0, 1, 2, 3],
    );
    assert.deepEqual(
      w2.instructions.map((i) => i.op),
      ['COPY', 'COPY', 'ADD', 'COPY'],
    );
    assert.deepEqual(
      w2.instructions.filter((i) => i.op === 'COPY').map((i) => i.mode),
      ['SELF', 'NEAR0', 'SAME0'],
    );
    // Every COPY exposes its U-space address and its resolved source/range.
    for (const ins of w2.instructions.filter((i) => i.op === 'COPY')) {
      assert.equal(typeof ins.address, 'number');
      assert.equal(typeof ins.encodedOffset, 'number');
      assert.ok(ins.range);
      assert.ok(['PRIOR_TARGET', 'CURRENT_TARGET', 'SOURCE_DICT'].includes(ins.range.area));
      assert.ok(ins.range.end > ins.range.start);
    }
    // Window 1 has ADD/RUN/COPY evidence.
    assert.deepEqual(
      w1.instructions.map((i) => i.op),
      ['COPY', 'ADD', 'COPY', 'RUN'],
    );
    const run = w1.instructions.find((i) => i.op === 'RUN');
    assert.equal(run.byteHex, '21');
    const add = w1.instructions.find((i) => i.op === 'ADD');
    assert.equal(Buffer.from(add.dataHex, 'hex').toString(), 'WORLD');
  });

  test('failure sample reports the first raw offset and keeps nothing', async () => {
    const resp = await post('/api/decode', {
      deltaBase64: sample.badCopy.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
    });
    assert.equal(resp.status, 400);
    const data = await resp.json();
    assert.equal(data.ok, false);
    assert.equal(data.error.code, sample.badCopy.expectedCode);
    assert.equal(data.error.offset, sample.badCopy.expectedOffset);
    assert.equal(typeof data.error.message, 'string');
  });

  test('non-minimal integer and truncation are rejected with offsets', async () => {
    const r1 = await post('/api/decode', {
      deltaBase64: sample.nonMinimal.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
    });
    const d1 = await r1.json();
    assert.equal(r1.status, 400);
    assert.equal(d1.error.code, 'NON_MINIMAL_INTEGER');
    assert.equal(d1.error.offset, sample.nonMinimal.expectedOffset);

    const r2 = await post('/api/decode', {
      deltaBase64: sample.truncated.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
    });
    const d2 = await r2.json();
    assert.equal(r2.status, 400);
    assert.equal(d2.error.code, 'TRUNCATED');
  });

  test('missing delta field is a 400', async () => {
    const resp = await post('/api/decode', {});
    assert.equal(resp.status, 400);
    assert.equal((await resp.json()).error.code, 'BAD_REQUEST');
  });

  test('invalid base64 is a 400 with BAD_BASE64', async () => {
    const [a, b] = await Promise.all([
      post('/api/decode', { deltaBase64: '@@@' }),
      post('/api/decode', { deltaBase64: '1sPE=' }),
    ]);
    assert.equal((await a.json()).error.code, 'BAD_BASE64');
    assert.equal((await b.json()).error.code, 'BAD_BASE64');
  });

  test('payload above the pasted-size limit is rejected (413)', async () => {
    const resp = await post('/api/decode', { deltaBase64: 'A'.repeat(128 * 1024 + 1) });
    assert.equal(resp.status, 413);
    assert.equal((await resp.json()).error.code, 'PAYLOAD_TOO_LARGE');
  });

  test('POST /api/reset acknowledges and a following decode still works', async () => {
    const r = await post('/api/reset', {});
    assert.equal(r.status, 200);
    assert.equal((await r.json()).ok, true);

    const r2 = await post('/api/decode', {
      deltaBase64: sample.valid.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
    });
    assert.equal(r2.status, 200);
    assert.equal((await r2.json()).ok, true);
  });

  test('unknown routes are 404', async () => {
    const resp = await fetch(`${base}/nonexistent-xyz`);
    assert.equal(resp.status, 404);
    assert.equal((await resp.json()).error.code, 'NOT_FOUND');
  });
});
