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

  test('trace range returns consecutive root-origin segments', async () => {
    const resp = await post('/api/decode', {
      deltaBase64: sample.valid.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
      traceStart: 24,
      traceLength: 13,
    });
    assert.equal(resp.status, 200);
    const data = await resp.json();
    assert.equal(data.ok, true);
    assert.equal(data.trace.start, 24);
    assert.equal(data.trace.length, 13);

    const segs = data.trace.segments;
    assert.deepEqual(
      segs.map((s) => s.kind),
      ['SOURCE_DICT', 'ADD', 'ADD', 'SOURCE_DICT', 'ADD'],
    );
    // Segments are consecutive and exactly cover the queried range.
    assert.equal(segs[0].outputStart, 24);
    assert.equal(segs[segs.length - 1].outputEnd, 37);
    for (let i = 1; i < segs.length; i++) {
      assert.equal(segs[i].outputStart, segs[i - 1].outputEnd);
    }

    // Window 2's COPYs (incl. the SAME0 one) re-emit window 1 bytes: the root
    // instruction must be window 1's COPY/ADD, never window 2's COPY.
    const w1copy = data.windows[0].instructions.find((i) => i.op === 'COPY');
    const w1add = data.windows[0].instructions.find((i) => i.op === 'ADD');
    const w2add = data.windows[1].instructions.find((i) => i.op === 'ADD');
    const w2copyOffsets = data.windows[1].instructions
      .filter((i) => i.op === 'COPY')
      .map((i) => i.codeOffset);
    for (const s of segs) {
      assert.ok(!w2copyOffsets.includes(s.instOffset), `segment ${s.outputStart}`);
    }
    assert.equal(segs[0].instOffset, w1copy.codeOffset);
    assert.deepEqual([segs[0].originStart, segs[0].originEnd], [10, 11]);
    assert.equal(segs[1].instOffset, w1add.codeOffset);
    assert.equal(segs[2].instOffset, w2add.codeOffset); // window 2's own ADD
    assert.equal(segs[3].instOffset, w1copy.codeOffset);
    assert.equal(segs[4].instOffset, w1add.codeOffset);
  });

  test('trace over the full output covers every byte', async () => {
    const resp = await post('/api/decode', {
      deltaBase64: sample.valid.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
      traceStart: 0,
      traceLength: sample.valid.expectedLength,
    });
    assert.equal(resp.status, 200);
    const data = await resp.json();
    const segs = data.trace.segments;
    assert.equal(segs[0].outputStart, 0);
    assert.equal(segs[segs.length - 1].outputEnd, sample.valid.expectedLength);
    for (const s of segs) {
      assert.ok(['ADD', 'RUN', 'SOURCE_DICT'].includes(s.kind));
      assert.ok(s.originEnd > s.originStart);
      assert.equal(typeof s.instOffset, 'number');
    }
  });

  test('decode without trace fields keeps the original response shape', async () => {
    const resp = await post('/api/decode', {
      deltaBase64: sample.valid.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
    });
    assert.equal(resp.status, 200);
    const data = await resp.json();
    assert.equal(data.ok, true);
    assert.ok(!('trace' in data));
    assert.equal(data.length, sample.valid.expectedLength);
    assert.equal(data.windows.length, 2);
  });

  test('trace range rejects non-integers, zero length and lone fields', async () => {
    const base = {
      deltaBase64: sample.valid.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
    };
    const cases = [
      { traceStart: 0 }, // missing traceLength
      { traceLength: 4 }, // missing traceStart
      { traceStart: 0, traceLength: 0 }, // zero length
      { traceStart: -1, traceLength: 2 }, // negative start
      { traceStart: 1.5, traceLength: 2 }, // non-integer
      { traceStart: '4', traceLength: 2 }, // string
      { traceStart: 0, traceLength: null }, // null
    ];
    for (const extra of cases) {
      const resp = await post('/api/decode', { ...base, ...extra });
      assert.equal(resp.status, 400, JSON.stringify(extra));
      const data = await resp.json();
      assert.equal(data.ok, false);
      assert.equal(data.error.code, 'BAD_TRACE', JSON.stringify(extra));
    }
  });

  test('trace range outside the decoded output is rejected', async () => {
    const base = {
      deltaBase64: sample.valid.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
    };
    for (const extra of [
      { traceStart: sample.valid.expectedLength, traceLength: 1 },
      { traceStart: 0, traceLength: sample.valid.expectedLength + 1 },
      { traceStart: 30, traceLength: 100 },
    ]) {
      const resp = await post('/api/decode', { ...base, ...extra });
      assert.equal(resp.status, 400, JSON.stringify(extra));
      const data = await resp.json();
      assert.equal(data.ok, false);
      assert.equal(data.error.code, 'TRACE_RANGE', JSON.stringify(extra));
      assert.ok(!('length' in data) && !('windows' in data));
    }
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
