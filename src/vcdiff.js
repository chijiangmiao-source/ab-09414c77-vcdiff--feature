// RFC 3284 VCDIFF decoder (default code table only, no secondary compression).
//
// Strict acceptance rules enforced here:
//   * magic D6 C3 C4 + header4 == 0
//   * Hdr_Indicator: VCD_DECOMPRESS / VCD_CODETABLE rejected, unknown bits rejected
//   * at most 8 windows, output hard cap (default 512 KiB)
//   * integers must use the shortest (minimal) base-128 encoding
//   * window delta payload and the three sections must match their declared lengths
//   * COPY addresses may only read source segment bytes or target bytes already
//     generated (byte-by-byte, so self-overlapping copies are supported)
//   * every detected error reports the first raw (original) delta byte offset,
//     and callers discard all output on failure.

export const NOOP = 0;
export const ADD = 1;
export const RUN = 2;
export const COPY = 3;

export const VCD_SOURCE = 0x01;
export const VCD_TARGET = 0x02;

export const VCD_DECOMPRESS = 0x01;
export const VCD_CODETABLE = 0x02;

export const VCD_DATACOMP = 0x01;
export const VCD_INSTCOMP = 0x02;
export const VCD_ADDRCOMP = 0x04;

export const DEFAULT_NEAR = 4;
export const DEFAULT_SAME = 3; // same cache has DEFAULT_SAME * 256 slots
export const ADDRESS_MODES = DEFAULT_NEAR + DEFAULT_SAME + 2; // 9

export const MAX_OUTPUT_BYTES = 512 * 1024;
export const MAX_WINDOWS = 8;

// Provenance root kinds attached to every output byte. ADD and RUN create
// fresh roots (their bytes live in the delta's data section); SOURCE_DICT
// roots point into the dictionary; COPY instructions never create roots —
// they propagate the label of the byte they read, so a later COPY's own
// position is never mistaken for the origin.
export const PROV_NONE = 0;
export const PROV_SOURCE_DICT = 1;
export const PROV_ADD = 2;
export const PROV_RUN = 3;

export const PROV_KIND_NAMES = ['NONE', 'SOURCE_DICT', 'ADD', 'RUN'];

export class VcdiffError extends Error {
  constructor(code, message, offset = null) {
    super(message);
    this.name = 'VcdiffError';
    this.code = code;
    // Offset into the raw delta bytes supplied by the caller (0-based).
    // null means the failure is not tied to a delta offset (e.g. bad input).
    this.offset = offset;
  }
}

// ---------------------------------------------------------------------------
// Default instruction code table (RFC 3284 5.6, s_near=4, s_same=3).
// Each entry is [inst1, size1, mode1, inst2, size2, mode2].
// ---------------------------------------------------------------------------

export function buildDefaultCodeTable() {
  const table = Array.from({ length: 256 }, () => [NOOP, 0, 0, NOOP, 0, 0]);

  // Index 0: RUN, separately coded size.
  table[0] = [RUN, 0, 0, NOOP, 0, 0];

  // Indices 1..18: ADD, sizes 0 (separate), 1..17.
  for (let size = 0; size <= 17; size++) {
    table[1 + size] = [ADD, size, 0, NOOP, 0, 0];
  }

  // Indices 19..162: single COPY, 9 modes, size 0 (separate) then 4..18.
  for (let mode = 0; mode <= 8; mode++) {
    const base = 19 + mode * 16;
    table[base] = [COPY, 0, mode, NOOP, 0, 0];
    for (let size = 4; size <= 18; size++) {
      table[base + (size - 3)] = [COPY, size, mode, NOOP, 0, 0];
    }
  }

  // Indices 163..234: ADD size 1..4 followed by COPY size 4..6, modes 0..5.
  for (let mode = 0; mode <= 5; mode++) {
    let index = 163 + mode * 12;
    for (let addSize = 1; addSize <= 4; addSize++) {
      for (let copySize = 4; copySize <= 6; copySize++) {
        table[index++] = [ADD, addSize, 0, COPY, copySize, mode, 0];
      }
    }
  }

  // Indices 235..246: ADD size 1..4 followed by COPY size 4, modes 6..8.
  for (let mode = 6; mode <= 8; mode++) {
    let index = 235 + (mode - 6) * 4;
    for (let addSize = 1; addSize <= 4; addSize++) {
      table[index++] = [ADD, addSize, 0, COPY, 4, mode, 0];
    }
  }

  // Indices 247..255: COPY size 4 (modes 0..8) followed by ADD size 1.
  for (let mode = 0; mode <= 8; mode++) {
    table[247 + mode] = [COPY, 4, mode, ADD, 1, 0, 0];
  }

  return table;
}

export const DEFAULT_CODE_TABLE = buildDefaultCodeTable();

export function modeName(mode) {
  if (mode === 0) return 'SELF';
  if (mode === 1) return 'HERE';
  if (mode >= 2 && mode <= 1 + DEFAULT_NEAR) return `NEAR${mode - 2}`;
  return `SAME${mode - 2 - DEFAULT_NEAR}`;
}

// ---------------------------------------------------------------------------
// Bounded cursor over a raw byte array. All positions are absolute offsets
// into the caller's delta buffer so error locations are "original offsets".
// ---------------------------------------------------------------------------

class Cursor {
  constructor(buf, base, end) {
    this.buf = buf;
    this.pos = base;
    this.base = base;
    this.end = end;
  }

  byte() {
    if (this.pos >= this.end) {
      throw new VcdiffError('TRUNCATED', 'stream ended while another byte was required', this.end);
    }
    return this.buf[this.pos++];
  }

  // Reads a minimal base-128 integer (RFC 3284 section 2).
  integer() {
    const start = this.pos;
    let value = 0;
    let digits = 0;
    let mostSignificantGroup = 0;
    for (;;) {
      if (this.pos >= this.end) {
        throw new VcdiffError('TRUNCATED', 'integer encoding is truncated', this.end);
      }
      const b = this.buf[this.pos++];
      if (digits === 0) mostSignificantGroup = b & 0x7f;
      value = value * 128 + (b & 0x7f);
      digits += 1;
      if ((b & 0x80) === 0) break;
      if (digits >= 8) {
        throw new VcdiffError('INTEGER_TOO_LARGE', 'integer encoding is too long', start);
      }
    }
    if (digits > 1 && mostSignificantGroup === 0) {
      throw new VcdiffError(
        'NON_MINIMAL_INTEGER',
        'integer is not encoded in its shortest form',
        start,
      );
    }
    if (!Number.isSafeInteger(value)) {
      throw new VcdiffError('INTEGER_TOO_LARGE', 'integer value exceeds the supported range', start);
    }
    return { value, start };
  }

  bytes(length, what) {
    if (length < 0 || this.pos + length > this.end) {
      throw new VcdiffError(
        'TRUNCATED',
        `${what} section is shorter than its declared length`,
        this.end,
      );
    }
    const view = this.buf.subarray(this.pos, this.pos + length);
    this.pos += length;
    return view;
  }
}

// ---------------------------------------------------------------------------
// Address caches (RFC 3284 section 5). Freshly initialised per window.
// ---------------------------------------------------------------------------

class AddressCache {
  constructor() {
    this.sNear = DEFAULT_NEAR;
    this.sSame = DEFAULT_SAME;
    this.near = new Uint32Array(this.sNear);
    this.same = new Uint32Array(this.sSame * 256);
    this.nextSlot = 0;
  }

  update(addr) {
    this.near[this.nextSlot] = addr;
    this.nextSlot = (this.nextSlot + 1) % this.sNear;
    this.same[addr % (this.sSame * 256)] = addr;
  }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Provenance trace: collapse the per-byte labels over [start, start+length)
// into maximal contiguous segments. Adjacent bytes merge when they share the
// root kind and the first-producing instruction, and their root positions
// continue smoothly (RUN bytes all point at the same data-section byte).
// ---------------------------------------------------------------------------

function buildTraceSegments(provKind, provOrigin, provCode, start, length) {
  const end = start + length;
  const segments = [];
  let i = start;
  while (i < end) {
    const kind = provKind[i];
    const origin = provOrigin[i];
    const code = provCode[i];
    let j = i + 1;
    while (j < end && provKind[j] === kind && provCode[j] === code) {
      const continues = kind === PROV_RUN
        ? provOrigin[j] === origin
        : provOrigin[j] === origin + (j - i);
      if (!continues) break;
      j += 1;
    }
    segments.push({
      outputStart: i,
      outputEnd: j,
      kind: PROV_KIND_NAMES[kind],
      originStart: origin,
      originEnd: kind === PROV_RUN ? origin + 1 : origin + (j - i),
      codeOffset: code,
    });
    i = j;
  }
  return segments;
}

export function decodeVcdiff(delta, dictionary = new Uint8Array(0), options = {}) {
  const maxOutput = options.maxOutput ?? MAX_OUTPUT_BYTES;
  const maxWindows = options.maxWindows ?? MAX_WINDOWS;
  const table = DEFAULT_CODE_TABLE;

  if (!(delta instanceof Uint8Array)) {
    throw new VcdiffError('BAD_INPUT', 'delta must be a byte array');
  }
  if (!(dictionary instanceof Uint8Array)) {
    throw new VcdiffError('BAD_INPUT', 'dictionary must be a byte array');
  }

  // Optional provenance trace over the final output: { start, length }.
  // Shape checks that do not need the decoded length happen up front so a
  // malformed trace request rejects the whole decode before any work.
  const traceReq = options.trace ?? null;
  if (traceReq !== null) {
    if (typeof traceReq !== 'object') {
      throw new VcdiffError('BAD_TRACE', 'trace must be an object with start and length');
    }
    if (!Number.isInteger(traceReq.start) || !Number.isInteger(traceReq.length)) {
      throw new VcdiffError(
        'TRACE_NOT_INTEGER',
        'trace start and length must be integers',
      );
    }
    if (traceReq.start < 0 || traceReq.length <= 0) {
      throw new VcdiffError(
        'TRACE_RANGE',
        'trace start must be >= 0 and trace length must be > 0',
      );
    }
  }

  const r = new Cursor(delta, 0, delta.length);

  // --- Header -------------------------------------------------------------
  if (delta.length < 5) {
    throw new VcdiffError('TRUNCATED', 'header is truncated', delta.length);
  }
  const magicOffset = 0;
  if (
    delta[0] !== 0xd6 ||
    delta[1] !== 0xc3 ||
    delta[2] !== 0xc4
  ) {
    throw new VcdiffError('BAD_MAGIC', 'missing VCDIFF magic bytes 0xD6 0xC3 0xC4', magicOffset);
  }
  if (delta[3] !== 0x00) {
    throw new VcdiffError('UNSUPPORTED_VERSION', 'header4 must be 0x00 for RFC 3284', 3);
  }
  r.pos = 4; // magic + header4 inspected directly above
  const hdrIndicator = r.byte(); // offset 4
  if (hdrIndicator & ~(VCD_DECOMPRESS | VCD_CODETABLE)) {
    throw new VcdiffError('BAD_INDICATOR', 'header indicator contains reserved bits', 4);
  }
  if (hdrIndicator & VCD_DECOMPRESS) {
    throw new VcdiffError(
      'SECONDARY_COMPRESSION',
      'secondary (post) compression is not accepted',
      4,
    );
  }
  if (hdrIndicator & VCD_CODETABLE) {
    throw new VcdiffError(
      'CUSTOM_CODE_TABLE',
      'only the RFC 3284 default code table is accepted',
      4,
    );
  }

  // Output buffer shared by all windows; discarded by the caller on failure.
  const output = new Uint8Array(maxOutput);
  let outputLen = 0;
  // Per-output-byte provenance labels, written alongside `output` by every
  // instruction. provKind: PROV_* root kind; provOrigin: root byte position
  // (dictionary offset for SOURCE_DICT, raw delta data-section offset for
  // ADD/RUN); provCode: raw offset of the instruction that first produced
  // the byte. COPY inherits all three from the byte it reads.
  const provKind = new Uint8Array(maxOutput);
  const provOrigin = new Uint32Array(maxOutput);
  const provCode = new Uint32Array(maxOutput);
  const windows = [];

  // --- Windows ------------------------------------------------------------
  while (r.pos < r.end) {
    if (windows.length >= maxWindows) {
      throw new VcdiffError(
        'TOO_MANY_WINDOWS',
        `streams with more than ${maxWindows} windows are not accepted`,
        r.pos,
      );
    }

    const winOffset = r.pos;
    const winIndicatorOffset = r.pos;
    const winIndicator = r.byte();
    if (winIndicator & ~(VCD_SOURCE | VCD_TARGET)) {
      throw new VcdiffError(
        'BAD_INDICATOR',
        'window indicator contains reserved bits',
        winIndicatorOffset,
      );
    }
    if ((winIndicator & VCD_SOURCE) && (winIndicator & VCD_TARGET)) {
      throw new VcdiffError(
        'BAD_INDICATOR',
        'window indicator sets both VCD_SOURCE and VCD_TARGET',
        winIndicatorOffset,
      );
    }

    let sourceKind = 'NONE'; // SOURCE (dictionary) | TARGET (earlier output) | NONE
    let sourcePosition = 0;
    let sourceLength = 0;
    let source = new Uint8Array(0);

    if (winIndicator !== 0) {
      const lenInfo = r.integer();
      const posInfo = r.integer();
      sourceLength = lenInfo.value;
      sourcePosition = posInfo.value;
      if (winIndicator & VCD_SOURCE) {
        sourceKind = 'SOURCE';
        if (sourcePosition > dictionary.length ||
            sourceLength > dictionary.length - sourcePosition) {
          throw new VcdiffError(
            'SOURCE_RANGE',
            `source segment [${sourcePosition}, +${sourceLength}) is outside the ` +
              `dictionary of length ${dictionary.length}`,
            lenInfo.start,
          );
        }
        source = dictionary.subarray(sourcePosition, sourcePosition + sourceLength);
      } else {
        sourceKind = 'TARGET';
        if (sourcePosition > outputLen ||
            sourceLength > outputLen - sourcePosition) {
          throw new VcdiffError(
            'SOURCE_RANGE',
            `target source segment [${sourcePosition}, +${sourceLength}) is outside ` +
              `the ${outputLen} bytes generated by earlier windows`,
            lenInfo.start,
          );
        }
        source = output.subarray(sourcePosition, sourcePosition + sourceLength);
      }
    }

    const deltaLenInfo = r.integer();
    const deltaLength = deltaLenInfo.value;
    if (r.pos + deltaLength > r.end) {
      throw new VcdiffError(
        'TRUNCATED',
        'window delta encoding is truncated',
        r.end,
      );
    }
    const deltaStart = r.pos;
    const deltaEnd = deltaStart + deltaLength;
    const w = new Cursor(delta, deltaStart, deltaEnd);

    const targetLenInfo = w.integer();
    const targetLength = targetLenInfo.value;

    const deltaIndicatorOffset = w.pos;
    const deltaIndicator = w.byte();
    if (deltaIndicator & ~(VCD_DATACOMP | VCD_INSTCOMP | VCD_ADDRCOMP)) {
      throw new VcdiffError(
        'BAD_INDICATOR',
        'delta indicator contains reserved bits',
        deltaIndicatorOffset,
      );
    }
    if (deltaIndicator & VCD_DATACOMP) {
      throw new VcdiffError('SECONDARY_COMPRESSION', 'compressed ADD/RUN data section rejected', deltaIndicatorOffset);
    }
    if (deltaIndicator & VCD_INSTCOMP) {
      throw new VcdiffError('SECONDARY_COMPRESSION', 'compressed instruction section rejected', deltaIndicatorOffset);
    }
    if (deltaIndicator & VCD_ADDRCOMP) {
      throw new VcdiffError('SECONDARY_COMPRESSION', 'compressed address section rejected', deltaIndicatorOffset);
    }

    const dataLenInfo = w.integer();
    const instLenInfo = w.integer();
    const addrLenInfo = w.integer();
    const dataLength = dataLenInfo.value;
    const instLength = instLenInfo.value;
    const addrLength = addrLenInfo.value;

    const headerConsumed = w.pos - deltaStart;
    if (dataLength + instLength + addrLength !== deltaLength - headerConsumed) {
      throw new VcdiffError(
        'SEGMENT_LENGTH',
        'declared section lengths do not exactly fill the window delta encoding',
        dataLenInfo.start,
      );
    }

    const dataStart = w.pos;
    const data = w.bytes(dataLength, 'data');
    const instStart = w.pos;
    const inst = w.bytes(instLength, 'instruction');
    const addrStart = w.pos;
    const addr = w.bytes(addrLength, 'address');
    if (w.pos !== deltaEnd) {
      throw new VcdiffError('SEGMENT_LENGTH', 'trailing bytes after window sections', w.pos);
    }

    if (targetLength > maxOutput - outputLen) {
      throw new VcdiffError(
        'OUTPUT_LIMIT',
        `decoded output would exceed the ${maxOutput} byte limit`,
        targetLenInfo.start,
      );
    }

    const windowOutputStart = outputLen;
    let generated = 0; // bytes generated within this window
    const cache = new AddressCache();
    const instructions = [];
    let seq = 0;

    const dcur = new Cursor(delta, dataStart, dataStart + dataLength);
    const icur = new Cursor(delta, instStart, instStart + instLength);
    const acur = new Cursor(delta, addrStart, addrStart + addrLength);

    const checkGrowth = (need, codeOffset) => {
      if (generated + need > targetLength) {
        throw new VcdiffError(
          'TARGET_LENGTH',
          'instructions generate more bytes than the declared target window length',
          codeOffset,
        );
      }
    };

    const readAddress = (mode, codeOffset) => {
      if (mode < 0 || mode >= ADDRESS_MODES) {
        throw new VcdiffError('BAD_ADDRESS_MODE', `address mode ${mode} is invalid`, codeOffset);
      }
      let encoded;
      let encodedOffset;
      let address;
      if (mode === 0) {
        // VCD_SELF
        const info = acur.integer();
        encoded = info.value;
        encodedOffset = info.start;
        address = encoded;
      } else if (mode === 1) {
        // VCD_HERE: encoded as (s + here) - addr
        const info = acur.integer();
        encoded = info.value;
        encodedOffset = info.start;
        address = sourceLength + generated - encoded;
      } else if (mode <= 1 + DEFAULT_NEAR) {
        // Near modes 2..5
        const info = acur.integer();
        encoded = info.value;
        encodedOffset = info.start;
        address = cache.near[mode - 2] + encoded;
      } else {
        // Same modes 6..8: one byte
        encodedOffset = acur.pos;
        const b = acur.byte();
        encoded = b;
        const k = mode - (2 + DEFAULT_NEAR);
        address = cache.same[k * 256 + b];
      }
      if (address < 0 || address > 0xffffffff) {
        throw new VcdiffError(
          'ADDRESS_OUT_OF_RANGE',
          `decoded copy address ${address} is not valid`,
          codeOffset,
        );
      }
      cache.update(address);
      return { address, encoded, encodedOffset };
    };

    const describeRange = (uAddress, size) => {
      if (uAddress < sourceLength) {
        return {
          area: sourceKind === 'TARGET' ? 'PRIOR_TARGET' : 'SOURCE_DICT',
          start: sourcePosition + uAddress,
          end: sourcePosition + uAddress + size,
        };
      }
      return {
        area: 'CURRENT_TARGET',
        start: windowOutputStart + (uAddress - sourceLength),
        end: windowOutputStart + (uAddress - sourceLength) + size,
      };
    };

    const runInstruction = (instType, size, mode, codeOffset) => {
      if (size === 0) {
        throw new VcdiffError('ZERO_SIZE_INSTRUCTION', 'instruction size must be non-zero', codeOffset);
      }
      const order = seq++;
      if (instType === ADD) {
        checkGrowth(size, codeOffset);
        if (dcur.pos + size > dcur.end) {
          throw new VcdiffError(
            'SEGMENT_LENGTH',
            'ADD runs past the end of the data section',
            codeOffset,
          );
        }
        const addDataOffset = dcur.pos; // raw delta offset of the literal bytes
        const addData = delta.slice(dcur.pos, dcur.pos + size);
        dcur.pos += size;
        const outBase = windowOutputStart + generated;
        output.set(addData, outBase);
        for (let i = 0; i < size; i++) {
          provKind[outBase + i] = PROV_ADD;
          provOrigin[outBase + i] = addDataOffset + i;
          provCode[outBase + i] = codeOffset;
        }
        generated += size;
        instructions.push({
          seq: order,
          op: 'ADD',
          size,
          dataHex: Buffer.from(addData).toString('hex'),
          codeOffset,
        });
      } else if (instType === RUN) {
        checkGrowth(size, codeOffset);
        if (dcur.pos >= dcur.end) {
          throw new VcdiffError(
            'SEGMENT_LENGTH',
            'RUN byte is missing from the data section',
            codeOffset,
          );
        }
        const runByteOffset = dcur.pos; // raw delta offset of the repeated byte
        const runByte = dcur.byte();
        const outBase = windowOutputStart + generated;
        output.fill(runByte, outBase, outBase + size);
        for (let i = 0; i < size; i++) {
          provKind[outBase + i] = PROV_RUN;
          provOrigin[outBase + i] = runByteOffset;
          provCode[outBase + i] = codeOffset;
        }
        generated += size;
        instructions.push({
          seq: order,
          op: 'RUN',
          size,
          byteHex: runByte.toString(16).padStart(2, '0'),
          codeOffset,
        });
      } else if (instType === COPY) {
        checkGrowth(size, codeOffset);
        const { address, encoded, encodedOffset } = readAddress(mode, codeOffset);
        // RFC 3284 section 3: the copied substring must be entirely contained
        // in either S or T. A COPY that starts in the source segment and runs
        // into the target window straddles the boundary and is invalid.
        if (address < sourceLength && address + size > sourceLength) {
          throw new VcdiffError(
            'COPY_CROSSES_BOUNDARY',
            `COPY at address ${address} size ${size} crosses the source/target boundary`,
            codeOffset,
          );
        }
        const overlaps = address >= sourceLength &&
          address - sourceLength < generated;
        // Byte-by-byte copy. A byte is legal when it lies in the source
        // segment or has already been generated in this target window.
        // Every copied byte inherits the provenance label of the byte it
        // reads; only a read from a SOURCE (dictionary) segment creates a
        // fresh root, stamped with this COPY's raw offset.
        for (let i = 0; i < size; i++) {
          const u = address + i;
          let value;
          const dst = windowOutputStart + generated;
          if (u < sourceLength) {
            value = source[u];
            if (sourceKind === 'TARGET') {
              // Prior-window output: propagate the existing root label.
              const srcPos = sourcePosition + u;
              provKind[dst] = provKind[srcPos];
              provOrigin[dst] = provOrigin[srcPos];
              provCode[dst] = provCode[srcPos];
            } else {
              provKind[dst] = PROV_SOURCE_DICT;
              provOrigin[dst] = sourcePosition + u;
              provCode[dst] = codeOffset;
            }
          } else {
            const targetIndex = u - sourceLength;
            if (targetIndex < 0 || targetIndex >= generated) {
              throw new VcdiffError(
                'COPY_NOT_GENERATED',
                `COPY at address ${address} size ${size} reads bytes that have not ` +
                  `been generated yet`,
                codeOffset,
              );
            }
            // Current-window bytes (including self-overlap reads of bytes
            // written earlier in this loop) carry their labels with them.
            const srcPos = windowOutputStart + targetIndex;
            value = output[srcPos];
            provKind[dst] = provKind[srcPos];
            provOrigin[dst] = provOrigin[srcPos];
            provCode[dst] = provCode[srcPos];
          }
          output[dst] = value;
          generated += 1;
        }
        instructions.push({
          seq: order,
          op: 'COPY',
          size,
          mode: modeName(mode),
          modeValue: mode,
          encoded,
          encodedOffset,
          address,
          range: describeRange(address, size),
          overlaps,
          codeOffset,
        });
      } else {
        throw new VcdiffError('BAD_CODE_TABLE', `illegal instruction type ${instType}`, codeOffset);
      }
    };

    while (icur.pos < icur.end) {
      const codeOffset = icur.pos;
      const index = icur.byte();
      const entry = table[index];
      if (!entry) {
        throw new VcdiffError('BAD_CODE_TABLE', `illegal code table index ${index}`, codeOffset);
      }
      const [i1, s1, m1, i2, s2, m2] = entry;

      const slots = [
        [i1, s1, m1],
        [i2, s2, m2],
      ];
      for (const [instType, tableSize, mode] of slots) {
        if (instType === NOOP) continue;
        if (instType !== ADD && instType !== RUN && instType !== COPY) {
          throw new VcdiffError('BAD_CODE_TABLE', `illegal instruction type ${instType}`, codeOffset);
        }
        if (instType !== COPY && mode !== 0) {
          throw new VcdiffError('BAD_CODE_TABLE', 'non-COPY instruction carries an address mode', codeOffset);
        }
        let size = tableSize;
        if (size === 0) {
          size = icur.integer().value;
        }
        runInstruction(instType, size, mode, codeOffset);
      }
    }

    if (icur.pos !== icur.end) {
      throw new VcdiffError('TRUNCATED', 'instruction tuple encoding is truncated', icur.pos);
    }
    if (dcur.pos !== dcur.end) {
      throw new VcdiffError(
        'SEGMENT_LENGTH',
        `${dcur.end - dcur.pos} byte(s) of the ADD/RUN data section were not consumed`,
        dcur.pos,
      );
    }
    if (acur.pos !== acur.end) {
      throw new VcdiffError(
        'SEGMENT_LENGTH',
        `${acur.end - acur.pos} byte(s) of the COPY address section were not consumed`,
        acur.pos,
      );
    }
    if (generated !== targetLength) {
      throw new VcdiffError(
        'TARGET_LENGTH',
        `instructions generated ${generated} bytes but target window declares ${targetLength}`,
        deltaIndicatorOffset,
      );
    }

    windows.push({
      index: windows.length,
      windowOffset: winOffset,
      source:
        sourceKind === 'NONE'
          ? { kind: 'NONE', position: 0, length: 0 }
          : { kind: sourceKind, position: sourcePosition, length: sourceLength },
      targetOffset: windowOutputStart,
      targetLength,
      deltaLength,
      sections: {
        data: dataLength,
        instructions: instLength,
        addresses: addrLength,
      },
      instructions,
    });

    outputLen += targetLength;
    r.pos = deltaEnd;
  }

  // A requested trace range is validated against the final output length;
  // an out-of-bounds range rejects the whole request (no partial answer).
  let trace = null;
  if (traceReq !== null) {
    const { start, length } = traceReq;
    if (start > outputLen || length > outputLen - start) {
      throw new VcdiffError(
        'TRACE_RANGE',
        `trace range [${start}, +${length}) lies outside the ${outputLen} decoded bytes`,
      );
    }
    trace = {
      start,
      length,
      segments: buildTraceSegments(provKind, provOrigin, provCode, start, length),
    };
  }

  const result = {
    output: output.slice(0, outputLen),
    length: outputLen,
    windows,
    truncated: false,
  };
  if (trace !== null) result.trace = trace;
  return result;
}
