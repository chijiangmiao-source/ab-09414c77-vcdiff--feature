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

  test('POST /api/decode with a trace range returns contiguous provenance segments', async () => {
    const resp = await post('/api/decode', {
      deltaBase64: sample.valid.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
      traceStart: 24,
      traceLength: 13,
    });
    assert.equal(resp.status, 200);
    const data = await resp.json();
    assert.equal(data.ok, true);
    assert.ok(data.trace, 'trace must be present when requested');
    assert.equal(data.trace.start, 24);
    assert.equal(data.trace.length, 13);

    // Segments tile [24, 37) exactly and carry all required fields.
    let pos = 24;
    for (const seg of data.trace.segments) {
      assert.equal(seg.outputStart, pos, 'segments must be contiguous');
      assert.ok(seg.outputEnd > seg.outputStart);
      pos = seg.outputEnd;
      assert.ok(['SOURCE_DICT', 'ADD', 'RUN'].includes(seg.kind));
      assert.ok(seg.originEnd > seg.originStart);
      assert.ok(Number.isInteger(seg.codeOffset));
    }
    assert.equal(pos, 37);

    // Window 2 only re-emits earlier bytes through COPY: every root offset
    // must belong to the instruction that first produced the byte, never to
    // one of window 2's propagating COPYs.
    const w2copyOffsets = new Set(
      data.windows[1].instructions.filter((i) => i.op === 'COPY').map((i) => i.codeOffset),
    );
    assert.ok(w2copyOffsets.size > 0);
    for (const seg of data.trace.segments) {
      assert.ok(!w2copyOffsets.has(seg.codeOffset), 'segment root must not be a later COPY');
    }

    // Expected layout of the sample over [24, 37):
    //   [24,25) dict '-' -> [25,30) ADD "WORLD" -> [30,32) ADD ">>"
    //   -> [32,33) dict '-' -> [33,37) ADD "WORL"
    const segs = data.trace.segments;
    assert.equal(segs.length, 5);
    const w1copy = data.windows[0].instructions[0];
    const w1add = data.windows[0].instructions[1];
    const w2add = data.windows[1].instructions[2];

    assert.equal(segs[0].kind, 'SOURCE_DICT');
    assert.deepEqual([segs[0].outputStart, segs[0].outputEnd], [24, 25]);
    assert.deepEqual([segs[0].originStart, segs[0].originEnd], [10, 11]);
    assert.equal(segs[0].codeOffset, w1copy.codeOffset);
    const dict = Buffer.from(sample.dictionaryBase64, 'base64');
    assert.equal(dict.subarray(10, 11).toString(), '-');

    assert.equal(segs[1].kind, 'ADD');
    assert.deepEqual([segs[1].outputStart, segs[1].outputEnd], [25, 30]);
    assert.equal(segs[1].codeOffset, w1add.codeOffset);

    assert.equal(segs[2].kind, 'ADD');
    assert.deepEqual([segs[2].outputStart, segs[2].outputEnd], [30, 32]);
    assert.equal(segs[2].codeOffset, w2add.codeOffset);

    assert.equal(segs[3].kind, 'SOURCE_DICT');
    assert.deepEqual([segs[3].outputStart, segs[3].outputEnd], [32, 33]);
    assert.deepEqual([segs[3].originStart, segs[3].originEnd], [10, 11]);
    assert.equal(segs[3].codeOffset, w1copy.codeOffset);

    assert.equal(segs[4].kind, 'ADD');
    assert.deepEqual([segs[4].outputStart, segs[4].outputEnd], [33, 37]);
    assert.equal(segs[4].codeOffset, w1add.codeOffset);
  });

  test('trace range rejections return 400 and retain no conclusions', async () => {
    const cases = [
      [{ traceStart: 0, traceLength: 0 }, 'TRACE_RANGE'],
      [{ traceStart: -1, traceLength: 3 }, 'TRACE_RANGE'],
      [{ traceStart: 1.5, traceLength: 3 }, 'TRACE_NOT_INTEGER'],
      [{ traceStart: 0, traceLength: 2.5 }, 'TRACE_NOT_INTEGER'],
      [{ traceStart: '24', traceLength: 13 }, 'TRACE_NOT_INTEGER'],
      [{ traceStart: 36, traceLength: 2 }, 'TRACE_RANGE'], // 36+2 > 37 decoded bytes
      [{ traceStart: 37, traceLength: 1 }, 'TRACE_RANGE'],
      [{ traceStart: 0, traceLength: 1024 }, 'TRACE_RANGE'],
    ];
    for (const [extra, code] of cases) {
      const resp = await post('/api/decode', {
        deltaBase64: sample.valid.deltaBase64,
        dictionaryBase64: sample.dictionaryBase64,
        ...extra,
      });
      assert.equal(resp.status, 400, `${JSON.stringify(extra)} must be rejected`);
      const data = await resp.json();
      assert.equal(data.ok, false);
      assert.equal(data.error.code, code, `${JSON.stringify(extra)}: ${data.error.code}`);
      assert.ok(!('windows' in data) && !('trace' in data), 'rejection keeps no conclusions');
    }
  });

  test('a lone traceStart without traceLength is rejected', async () => {
    const resp = await post('/api/decode', {
      deltaBase64: sample.valid.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
      traceStart: 24,
    });
    assert.equal(resp.status, 400);
    assert.equal((await resp.json()).error.code, 'BAD_REQUEST');
  });

  test('requests without a trace range keep the original response shape', async () => {
    const resp = await post('/api/decode', {
      deltaBase64: sample.valid.deltaBase64,
      dictionaryBase64: sample.dictionaryBase64,
    });
    const data = await resp.json();
    assert.equal(data.ok, true);
    assert.ok(!('trace' in data), 'no trace key unless requested');
    assert.equal(data.length, sample.valid.expectedLength);
    assert.equal(data.sha256, sample.valid.expectedSha256);
    assert.equal(data.windows.length, 2);
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
