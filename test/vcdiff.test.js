import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import {
  decodeVcdiff,
  buildDefaultCodeTable,
  DEFAULT_CODE_TABLE,
  VcdiffError,
  ADD,
  RUN,
  COPY,
  NOOP,
  MAX_OUTPUT_BYTES,
} from '../src/vcdiff.js';
import { WindowEncoder, assemble, header, encodeInteger } from './helpers/encoder.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const goldenDir = join(root, 'fixtures', 'golden');

const read = (p) => new Uint8Array(readFileSync(p));
const te = new TextEncoder();

function loadGolden(name) {
  return {
    delta: read(join(goldenDir, `${name}.delta`)),
    dict: read(join(goldenDir, `${name}.dict`)),
    target: read(join(goldenDir, `${name}.target`)),
  };
}

function expectError(fn, code) {
  assert.throws(
    fn,
    (err) => {
      assert.ok(err instanceof VcdiffError, `expected VcdiffError, got ${err}`);
      if (code) assert.equal(err.code, code, `expected code ${code}, got ${err.code}`);
      return true;
    },
  );
}

// ---------------------------------------------------------------------------
// Default code table
// ---------------------------------------------------------------------------

describe('default code table', () => {
  test('contains 256 entries with the RFC 3284 anchor entries', () => {
    const t = buildDefaultCodeTable();
    assert.equal(t.length, 256);
    assert.deepEqual(t[0], [RUN, 0, 0, NOOP, 0, 0]);
    assert.deepEqual(t[1], [ADD, 0, 0, NOOP, 0, 0]);
    assert.deepEqual(t[2], [ADD, 1, 0, NOOP, 0, 0]);
    assert.deepEqual(t[18], [ADD, 17, 0, NOOP, 0, 0]);
    assert.deepEqual(t[19], [COPY, 0, 0, NOOP, 0, 0]);
    assert.deepEqual(t[20], [COPY, 4, 0, NOOP, 0, 0]);
    assert.deepEqual(t[35], [COPY, 0, 1, NOOP, 0, 0]);
    assert.deepEqual(t[147], [COPY, 0, 8, NOOP, 0, 0]);
    assert.deepEqual(t[163], [ADD, 1, 0, COPY, 4, 0, 0]);
    assert.deepEqual(t[174], [ADD, 4, 0, COPY, 6, 0, 0]);
    assert.deepEqual(t[235], [ADD, 1, 0, COPY, 4, 6, 0]);
    assert.deepEqual(t[247], [COPY, 4, 0, ADD, 1, 0, 0]);
    assert.deepEqual(t[255], [COPY, 4, 8, ADD, 1, 0, 0]);
  });

  test('every entry is well-formed (valid inst types, modes only on COPY)', () => {
    for (let i = 0; i < 256; i++) {
      const [i1, , m1, i2, , m2] = DEFAULT_CODE_TABLE[i];
      assert.ok([NOOP, ADD, RUN, COPY].includes(i1), `bad inst1 at ${i}`);
      assert.ok([NOOP, ADD, RUN, COPY].includes(i2), `bad inst2 at ${i}`);
      if (i1 !== COPY) assert.equal(m1, 0);
      if (i2 !== COPY) assert.equal(m2, 0);
      if (i1 === COPY) assert.ok(m1 >= 0 && m1 <= 8);
      if (i2 === COPY) assert.ok(m2 >= 0 && m2 <= 8);
    }
  });
});

// ---------------------------------------------------------------------------
// Cross-validation against the open-vcdiff reference implementation vectors
// ---------------------------------------------------------------------------

describe('open-vcdiff golden vectors', () => {
  for (const name of ['plain', 'patterns', 'binary', 'nodict', 'multi', 'near', 'same1']) {
    test(`reproduces ${name} byte-for-byte`, () => {
      const { delta, dict, target } = loadGolden(name);
      const res = decodeVcdiff(delta, dict);
      assert.equal(res.length, target.length);
      assert.deepEqual(res.output, target);
      const sha = createHash('sha256').update(res.output).digest('hex');
      assert.match(sha, /^[0-9a-f]{64}$/);
    });
  }

  test('golden multi vector spans two windows', () => {
    const { delta, dict } = loadGolden('multi');
    const res = decodeVcdiff(delta, dict);
    assert.equal(res.windows.length, 2);
  });

  test('golden vectors collectively exercise every address mode', () => {
    const modes = new Set();
    for (const name of ['plain', 'patterns', 'binary', 'nodict', 'multi', 'near', 'same1']) {
      const { delta, dict } = loadGolden(name);
      for (const w of decodeVcdiff(delta, dict).windows) {
        for (const ins of w.instructions) if (ins.op === 'COPY') modes.add(ins.mode);
      }
    }
    for (const m of ['SELF', 'HERE', 'NEAR0', 'NEAR1', 'NEAR2', 'NEAR3', 'SAME0', 'SAME1', 'SAME2']) {
      assert.ok(modes.has(m), `mode ${m} never exercised by golden vectors`);
    }
  });
});

// ---------------------------------------------------------------------------
// Hand-built streams: target windows, caches, overlap, combined codes
// ---------------------------------------------------------------------------

describe('window sources and address caches', () => {
  const dict = te.encode('0123456789-HELLO-DICT');

  test('window 2 can use VCD_TARGET bytes produced by window 1', () => {
    const w1 = new WindowEncoder('SOURCE', 0, dict.length);
    w1.copy(0, 11);
    w1.add(te.encode('WORLD'));
    const w2 = new WindowEncoder('TARGET', 5, 11); // output[5:16]
    w2.copy(5, 5); // "-WORL"
    w2.copy(10, 1); // "D"
    const res = decodeVcdiff(assemble(w1.build(), w2.build()), dict);
    assert.deepEqual(res.output, te.encode('0123456789-WORLD-WORLD'));
    const win2 = res.windows[1];
    assert.equal(win2.source.kind, 'TARGET');
    assert.deepEqual([win2.source.position, win2.source.length], [5, 11]);
    assert.deepEqual(
      win2.instructions.map((i) => i.mode),
      ['SELF', 'NEAR0'],
    );
  });

  test('SAME cache mode resolves to an exactly repeated address', () => {
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.copy(0, 4); // primes same[0] = 0
    w.add(te.encode('xx'));
    w.copy(0, 4, { mode: 6 }); // SAME0 byte 0
    const res = decodeVcdiff(assemble(w.build()), dict);
    const copies = res.windows[0].instructions.filter((i) => i.op === 'COPY');
    assert.equal(copies[1].mode, 'SAME0');
    assert.equal(copies[1].address, 0);
    assert.deepEqual(res.output, te.encode('0123xx0123'));
  });

  test('HERE mode uses current target position (s + here - encoded)', () => {
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.copy(0, 4); // "0123"
    w.copy(4, 6, { mode: 1 }); // HERE: copy "456789" from source just emitted... addr 4
    const res = decodeVcdiff(assemble(w.build()), dict);
    assert.deepEqual(res.output, te.encode('0123456789'));
    const hereCopy = res.windows[0].instructions[1];
    assert.equal(hereCopy.mode, 'HERE');
    assert.equal(hereCopy.address, 4);
  });

  test('self-overlapping COPY is reproduced byte-by-byte', () => {
    const w = new WindowEncoder('NONE');
    w.add(te.encode('ab'));
    w.copy(0, 10, { mode: 1 }); // here=2, encoded 2 -> addr 0, "ab" repeated
    const res = decodeVcdiff(assemble(w.build()));
    assert.deepEqual(res.output, te.encode('abababababab'));
    const copy = res.windows[0].instructions.find((i) => i.op === 'COPY');
    assert.equal(copy.overlaps, true);
  });

  test('combined ADD+COPY and COPY+ADD code table entries work', () => {
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.addCopyPair(te.encode('ZZ'), 11, 5, 0); // ADD "ZZ" + COPY "HELLO"
    const res = decodeVcdiff(assemble(w.build()), dict);
    assert.deepEqual(res.output, te.encode('ZZHELLO'));
    assert.deepEqual(
      res.windows[0].instructions.map((i) => i.op),
      ['ADD', 'COPY'],
    );
  });

  test('RUN emits the repeated byte', () => {
    const w = new WindowEncoder('NONE');
    w.run(0x51, 5); // 'Q' x5
    const res = decodeVcdiff(assemble(w.build()));
    assert.deepEqual(res.output, new Uint8Array([0x51, 0x51, 0x51, 0x51, 0x51]));
  });

  test('caches are reset between windows', () => {
    // Window 2's forced NEAR0 must not see window 1's cached address: near[0]
    // starts at 0 so NEAR0(encoded 10) == 10 in a fresh window.
    const w1 = new WindowEncoder('SOURCE', 0, dict.length);
    w1.copy(0, 4);
    const w2 = new WindowEncoder('SOURCE', 0, dict.length);
    w2.copy(10, 1, { mode: 2 });
    const res = decodeVcdiff(assemble(w1.build(), w2.build()), dict);
    assert.equal(res.windows[1].instructions[0].mode, 'NEAR0');
    assert.equal(res.windows[1].instructions[0].address, 10);
  });

  test('instructions and windows carry raw offsets', () => {
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.copy(0, 4);
    const res = decodeVcdiff(assemble(w.build()), dict);
    const win = res.windows[0];
    assert.equal(win.windowOffset, 5);
    assert.equal(typeof win.instructions[0].codeOffset, 'number');
    assert.ok(win.instructions[0].codeOffset >= win.windowOffset);
  });
});

// ---------------------------------------------------------------------------
// Rejection cases: each must report a code and a raw offset, and no output
// ---------------------------------------------------------------------------

describe('strict rejection', () => {
  const dict = te.encode('0123456789-HELLO-DICT');

  function reject(delta, dictionary = dict, code) {
    let caught;
    try {
      decodeVcdiff(delta, dictionary);
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof VcdiffError, 'expected a VcdiffError');
    if (code) assert.equal(caught.code, code, `code mismatch: ${caught.message}`);
    assert.equal(typeof caught.offset, 'number', `${caught.code} must carry an offset`);
    assert.ok(caught.offset >= 0 && caught.offset <= delta.length, 'offset must be inside stream');
  }

  test('bad magic', () => reject(Uint8Array.from([0, 0, 0, 0, 0]), dict, 'BAD_MAGIC'));
  test('unsupported header4', () => reject(Uint8Array.from([0xd6, 0xc3, 0xc4, 1, 0]), dict, 'UNSUPPORTED_VERSION'));
  test('secondary compression header', () => reject(Uint8Array.from([0xd6, 0xc3, 0xc4, 0, 1, 0]), dict, 'SECONDARY_COMPRESSION'));
  test('custom code table header', () => reject(Uint8Array.from([0xd6, 0xc3, 0xc4, 0, 2]), dict, 'CUSTOM_CODE_TABLE'));
  test('reserved header bits', () => reject(Uint8Array.from([0xd6, 0xc3, 0xc4, 0, 0x80]), dict, 'BAD_INDICATOR'));
  test('truncated header', () => reject(Uint8Array.from([0xd6, 0xc3]), dict, 'TRUNCATED'));

  test('non-minimal (leading zero group) integer', () => {
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.run(0x41, 4, { nonMinimalSize: true });
    reject(assemble(w.build()), dict, 'NON_MINIMAL_INTEGER');
  });

  test('truncated window body', () => {
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.copy(0, 4);
    const full = assemble(w.build());
    reject(full.subarray(0, full.length - 2), dict, 'TRUNCATED');
  });

  test('COPY of bytes not yet generated (offset reported, no partial output)', () => {
    const w = new WindowEncoder('TARGET', 5, 11);
    w.add(te.encode('XY'));
    w.copy(13, 4, { mode: 1 }); // HERE encoded 0 -> future target addr
    const delta = assemble(w1WithSource(dict), w.build());
    reject(delta, dict, 'COPY_NOT_GENERATED');
  });

  test('source segment outside the dictionary', () => {
    const w = new WindowEncoder('SOURCE', 100, 8);
    w.copy(0, 4);
    reject(assemble(w.build()), dict, 'SOURCE_RANGE');
  });

  test('target source segment outside prior windows output', () => {
    const w1 = new WindowEncoder('SOURCE', 0, dict.length);
    w1.copy(0, 4);
    const w2 = new WindowEncoder('TARGET', 0, 100);
    w2.copy(0, 4);
    reject(assemble(w1.build(), w2.build()), dict, 'SOURCE_RANGE');
  });

  test('negative HERE address (encoded distance larger than s + here)', () => {
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.copy(0, 1, { mode: 1, encodedOverride: 99 }); // addr = 20 + 0 - 99 < 0
    reject(assemble(w.build()), dict, 'ADDRESS_OUT_OF_RANGE');
  });

  test('COPY straddling the source/target boundary is rejected', () => {
    // s = 20; address 18 size 4 would read two source bytes and then target.
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.copy(18, 4, { mode: 0 });
    reject(assemble(w.build()), dict, 'COPY_CROSSES_BOUNDARY');
  });

  test('window indicator with both SOURCE and TARGET', () => {
    const raw = new Uint8Array([...header(), 0x03]);
    reject(raw, dict, 'BAD_INDICATOR');
  });

  test('delta indicator compression bits are rejected', () => {
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.copy(0, 4);
    reject(assemble(w.build({ deltaIndicator: 1 })), dict, 'SECONDARY_COMPRESSION');
  });

  test('declared section lengths that do not fill the window are rejected', () => {
    // Declare the window delta one byte longer than the three sections sum to,
    // with a padding byte present so the stream is not merely truncated.
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.copy(0, 4);
    const built = w.build();
    const bodyLen = built[built.length - 0]; // (not used directly; see below)
    void bodyLen;
    const padded = padDeltaLength(w);
    reject(assemble(padded), dict, 'SEGMENT_LENGTH');
  });

  test('more than 8 windows are rejected', () => {
    const wins = [];
    for (let i = 0; i < 9; i++) {
      const w = new WindowEncoder('NONE');
      w.add(te.encode('x'));
      wins.push(w.build());
    }
    reject(assemble(...wins), dict, 'TOO_MANY_WINDOWS');
  });

  test('output exceeding 512 KiB is rejected before expansion', () => {
    const w = new WindowEncoder('NONE');
    w.run(0x41, MAX_OUTPUT_BYTES + 1);
    reject(assemble(w.build()), new Uint8Array(0), 'OUTPUT_LIMIT');
  });

  test('instruction size of zero is rejected', () => {
    const w = new WindowEncoder('NONE');
    w.add(te.encode('')); // size 0 ADD via separate size integer
    reject(assemble(w.build()), new Uint8Array(0), 'ZERO_SIZE_INSTRUCTION');
  });

  test('generated bytes short of declared target length are rejected', () => {
    // Tamper: target window length integer says 99 but instructions make less.
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.copy(0, 4);
    const raw = assemble(w.build());
    const patched = tamperTargetLength(raw, 99);
    reject(patched, dict, 'TARGET_LENGTH');
  });
});

// ---------------------------------------------------------------------------
// Provenance trace: every output byte carries a recomputable root label
// ---------------------------------------------------------------------------

describe('provenance trace', () => {
  const dict = te.encode('0123456789-HELLO-DICT');

  // Segments must tile [start, start+length) with no gaps or overlaps.
  function assertTiling(trace, start, length) {
    assert.equal(trace.start, start);
    assert.equal(trace.length, length);
    assert.ok(trace.segments.length > 0);
    let pos = start;
    for (const seg of trace.segments) {
      assert.equal(seg.outputStart, pos, 'segments must be contiguous');
      assert.ok(seg.outputEnd > seg.outputStart);
      pos = seg.outputEnd;
    }
    assert.equal(pos, start + length, 'segments must cover the whole range');
  }

  // The root range must recompute the output bytes of the segment.
  function assertSegmentBytes(res, delta, dictBytes, seg) {
    const outSlice = res.output.subarray(seg.outputStart, seg.outputEnd);
    if (seg.kind === 'SOURCE_DICT') {
      assert.deepEqual(outSlice, dictBytes.subarray(seg.originStart, seg.originEnd));
    } else if (seg.kind === 'ADD') {
      assert.deepEqual(outSlice, delta.subarray(seg.originStart, seg.originEnd));
    } else if (seg.kind === 'RUN') {
      assert.equal(seg.originEnd, seg.originStart + 1, 'RUN root is a single byte');
      for (const b of outSlice) assert.equal(b, delta[seg.originStart]);
    } else {
      assert.fail(`unexpected segment kind ${seg.kind}`);
    }
  }

  test('ADD, RUN and dictionary copies create roots with recomputable bytes', () => {
    const w = new WindowEncoder('SOURCE', 0, dict.length);
    w.copy(0, 6); // dict [0,6) -> output [0,6)
    w.add(te.encode('XY')); // output [6,8)
    w.run(0x7e, 3); // output [8,11)
    const delta = assemble(w.build());
    const res = decodeVcdiff(delta, dict, { trace: { start: 0, length: 11 } });
    assertTiling(res.trace, 0, 11);
    assert.equal(res.trace.segments.length, 3);
    const [s0, s1, s2] = res.trace.segments;
    const [copyIns, addIns, runIns] = res.windows[0].instructions;

    assert.deepEqual([s0.outputStart, s0.outputEnd], [0, 6]);
    assert.equal(s0.kind, 'SOURCE_DICT');
    assert.deepEqual([s0.originStart, s0.originEnd], [0, 6]);
    assert.equal(s0.codeOffset, copyIns.codeOffset);

    assert.deepEqual([s1.outputStart, s1.outputEnd], [6, 8]);
    assert.equal(s1.kind, 'ADD');
    assert.deepEqual(delta.subarray(s1.originStart, s1.originEnd), te.encode('XY'));
    assert.equal(s1.codeOffset, addIns.codeOffset);

    assert.deepEqual([s2.outputStart, s2.outputEnd], [8, 11]);
    assert.equal(s2.kind, 'RUN');
    assert.equal(s2.originEnd, s2.originStart + 1);
    assert.equal(delta[s2.originStart], 0x7e);
    assert.equal(s2.codeOffset, runIns.codeOffset);
  });

  test('a mid-instruction subrange slices the root range precisely', () => {
    const w = new WindowEncoder('NONE');
    w.add(te.encode('abcdef'));
    const delta = assemble(w.build());
    const res = decodeVcdiff(delta, new Uint8Array(0), { trace: { start: 2, length: 3 } });
    assert.equal(res.trace.segments.length, 1);
    const seg = res.trace.segments[0];
    assert.deepEqual([seg.outputStart, seg.outputEnd], [2, 5]);
    assert.equal(seg.kind, 'ADD');
    assert.deepEqual(delta.subarray(seg.originStart, seg.originEnd), te.encode('cde'));
  });

  test('copies from prior windows inherit the first producer, never the later COPY', () => {
    const w1 = new WindowEncoder('SOURCE', 0, dict.length);
    w1.copy(0, 11); // "0123456789-" -> output [0,11)
    w1.add(te.encode('WORLD')); // output [11,16)
    const w2 = new WindowEncoder('TARGET', 5, 11); // source = prior output [5,16)
    w2.copy(5, 5); // "-WORL" -> output [16,21)
    w2.copy(10, 1); // "D" -> output [21,22)
    const delta = assemble(w1.build(), w2.build());
    const res = decodeVcdiff(delta, dict, { trace: { start: 16, length: 6 } });
    assertTiling(res.trace, 16, 6);

    const w1copy = res.windows[0].instructions[0];
    const w1add = res.windows[0].instructions[1];
    const w2win = res.windows[1];
    const w2copyOffsets = w2win.instructions.filter((i) => i.op === 'COPY').map((i) => i.codeOffset);

    const segs = res.trace.segments;
    assert.equal(segs.length, 2);
    // output[16] <- prior output[10] <- dictionary[10]
    assert.equal(segs[0].kind, 'SOURCE_DICT');
    assert.deepEqual([segs[0].outputStart, segs[0].outputEnd], [16, 17]);
    assert.deepEqual([segs[0].originStart, segs[0].originEnd], [10, 11]);
    assert.equal(segs[0].codeOffset, w1copy.codeOffset);
    // output[17..21] <- prior output[11..15] <- the ADD "WORLD" literals
    assert.equal(segs[1].kind, 'ADD');
    assert.deepEqual([segs[1].outputStart, segs[1].outputEnd], [17, 22]);
    assert.deepEqual(delta.subarray(segs[1].originStart, segs[1].originEnd), te.encode('WORLD'));
    assert.equal(segs[1].codeOffset, w1add.codeOffset);
    // The root instruction offsets live in window 1, before window 2 begins:
    // the propagating COPYs of window 2 must not be reported as roots.
    for (const seg of segs) {
      assert.ok(seg.codeOffset < w2win.windowOffset, 'root offset must precede window 2');
      assert.ok(!w2copyOffsets.includes(seg.codeOffset), 'root must not be a later COPY');
    }
  });

  test('self-overlapping COPY propagates the original ADD root byte-by-byte', () => {
    const w = new WindowEncoder('NONE');
    w.add(te.encode('ab'));
    w.copy(0, 10, { mode: 1 }); // HERE: repeat "ab" out to 12 bytes
    const delta = assemble(w.build());
    const res = decodeVcdiff(delta, new Uint8Array(0), { trace: { start: 0, length: 12 } });
    assertTiling(res.trace, 0, 12);
    const addIns = res.windows[0].instructions[0];
    // 12 bytes with a 2-byte root period -> six segments, all rooted at the ADD.
    assert.equal(res.trace.segments.length, 6);
    for (const seg of res.trace.segments) {
      assert.equal(seg.kind, 'ADD');
      assert.equal(seg.codeOffset, addIns.codeOffset);
      assert.deepEqual(delta.subarray(seg.originStart, seg.originEnd), te.encode('ab'));
    }
  });

  test('RUN roots survive being copied across windows (segments merge at the seam)', () => {
    const w1 = new WindowEncoder('NONE');
    w1.run(0x51, 4); // "QQQQ" -> output [0,4)
    const w2 = new WindowEncoder('TARGET', 0, 4);
    w2.copy(0, 4); // re-emits the run bytes -> output [4,8)
    const delta = assemble(w1.build(), w2.build());
    const res = decodeVcdiff(delta, new Uint8Array(0), { trace: { start: 0, length: 8 } });
    const runIns = res.windows[0].instructions[0];
    assert.equal(res.trace.segments.length, 1);
    const seg = res.trace.segments[0];
    assert.equal(seg.kind, 'RUN');
    assert.deepEqual([seg.outputStart, seg.outputEnd], [0, 8]);
    assert.equal(seg.codeOffset, runIns.codeOffset);
    assert.equal(seg.originEnd, seg.originStart + 1);
    assert.equal(delta[seg.originStart], 0x51);
  });

  test('golden vectors: full-output trace tiles the range and recomputes every byte', () => {
    for (const name of ['plain', 'patterns', 'binary', 'nodict', 'multi', 'near', 'same1']) {
      const { delta, dict: dictBytes, target } = loadGolden(name);
      const res = decodeVcdiff(delta, dictBytes, { trace: { start: 0, length: target.length } });
      assertTiling(res.trace, 0, target.length);
      const offsets = new Set();
      for (const w of res.windows) for (const ins of w.instructions) offsets.add(ins.codeOffset);
      for (const seg of res.trace.segments) {
        assertSegmentBytes(res, delta, dictBytes, seg);
        assert.ok(
          offsets.has(seg.codeOffset),
          `${name}: codeOffset ${seg.codeOffset} is not a real instruction offset`,
        );
      }
    }
  });

  test('trace range validation rejects the request (no partial answer)', () => {
    const w = new WindowEncoder('NONE');
    w.add(te.encode('abc'));
    const delta = assemble(w.build());
    const bad = [
      [{ start: 0, length: 0 }, 'TRACE_RANGE'],
      [{ start: 0, length: -2 }, 'TRACE_RANGE'],
      [{ start: -1, length: 2 }, 'TRACE_RANGE'],
      [{ start: 1.5, length: 2 }, 'TRACE_NOT_INTEGER'],
      [{ start: 0, length: 1.5 }, 'TRACE_NOT_INTEGER'],
      [{ start: '0', length: 2 }, 'TRACE_NOT_INTEGER'],
      [{ start: 0, length: 4 }, 'TRACE_RANGE'], // beyond the 3 decoded bytes
      [{ start: 3, length: 1 }, 'TRACE_RANGE'],
      [{ start: 2, length: 2 }, 'TRACE_RANGE'],
    ];
    for (const [trace, code] of bad) {
      let caught;
      try {
        decodeVcdiff(delta, new Uint8Array(0), { trace });
      } catch (err) {
        caught = err;
      }
      assert.ok(caught instanceof VcdiffError, `expected rejection for ${JSON.stringify(trace)}`);
      assert.equal(caught.code, code, `code mismatch for ${JSON.stringify(trace)}: ${caught.code}`);
      assert.equal(caught.offset, null, 'trace errors are not tied to a delta offset');
    }
  });

  test('requests without a trace range keep the original result shape', () => {
    const w = new WindowEncoder('NONE');
    w.add(te.encode('abc'));
    const res = decodeVcdiff(assemble(w.build()));
    assert.ok(!('trace' in res));
    assert.equal(res.length, 3);
    assert.equal(res.windows.length, 1);
    assert.deepEqual(res.windows[0].instructions.map((i) => i.op), ['ADD']);
  });
});

// ---------------------------------------------------------------------------
// helpers for crafted corruptions
// ---------------------------------------------------------------------------

function w1WithSource(dict) {
  const w = new WindowEncoder('SOURCE', 0, dict.length);
  // Generate 16 bytes so that window 2's TARGET segment [5, +11) is valid;
  // the failure must come from the COPY of not-yet-generated bytes.
  w.add(te.encode('0123456789ABCDEF'));
  return w.build();
}

function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// One window whose declared address-section length is inflated by one, so the
// three section lengths cannot exactly fill the window delta encoding.
function padDeltaLength(w) {
  const data = w.data.toBuffer();
  const inst = w.inst.toBuffer();
  const addr = w.addr.toBuffer();
  const body = concatBytes(
    encodeInteger(w.targetLength),
    Uint8Array.from([0]),
    encodeInteger(data.length),
    encodeInteger(inst.length),
    encodeInteger(addr.length + 1), // lie about this section
    data,
    inst,
    addr,
  );
  return concatBytes(
    Uint8Array.from([1]),
    encodeInteger(w.sourceLength),
    encodeInteger(w.sourcePosition),
    encodeInteger(body.length),
    body,
  );
}

function tamperTargetLength(raw, newLength) {
  // Layout: header(5) win_indicator(1) src_len(int) src_pos(int) delta_len(int)
  // target_len(int) ...; patch the target length integer in place when the
  // replacement is the same byte length (both small single-byte values).
  const patched = new Uint8Array(raw);
  let p = 5;
  p += 1; // win indicator
  const skipInt = () => {
    while (patched[p] & 0x80) p++;
    p++;
  };
  skipInt(); skipInt(); skipInt(); // src len, src pos, delta len
  const targetLenStart = p;
  skipInt();
  const repl = encodeInteger(newLength);
  assert.equal(repl.length, p - targetLenStart, 'test helper needs same-length varint');
  patched.set(repl, targetLenStart);
  return patched;
}
