// Minimal RFC 3284 VCDIFF *encoder* used only by tests and the sample
// generator. It mirrors the decoder's cache logic and can deliberately
// emit malformed streams (non-minimal integers, bad lengths, ...).

import {
  ADD,
  RUN,
  COPY,
  VCD_SOURCE,
  VCD_TARGET,
  DEFAULT_NEAR,
  DEFAULT_SAME,
  ADDRESS_MODES,
} from '../../src/vcdiff.js';

export function encodeInteger(value, { nonMinimal = false } = {}) {
  if (value < 0) throw new Error('negative integer');
  const groups = [];
  let v = value;
  do {
    groups.push(v % 128);
    v = Math.floor(v / 128);
  } while (v > 0);
  groups.reverse();
  const out = [];
  for (let i = 0; i < groups.length; i++) {
    let b = groups[i];
    if (i < groups.length - 1) b |= 0x80;
    out.push(b);
  }
  if (nonMinimal) out.unshift(0x80); // leading zero group
  return Uint8Array.from(out);
}

class Writer {
  constructor() {
    this.parts = [];
  }
  u8(b) {
    this.parts.push(Uint8Array.from([b & 0xff]));
  }
  int(value, opts) {
    this.parts.push(encodeInteger(value, opts));
  }
  bytes(arr) {
    this.parts.push(arr instanceof Uint8Array ? arr : Uint8Array.from(arr));
  }
  toBuffer() {
    let len = 0;
    for (const p of this.parts) len += p.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const p of this.parts) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  }
}

export function header({ indicator = 0x00 } = {}) {
  return Uint8Array.from([0xd6, 0xc3, 0xc4, 0x00, indicator]);
}

export class WindowEncoder {
  // sourceKind: 'SOURCE' | 'TARGET' | 'NONE'
  constructor(sourceKind = 'NONE', sourcePosition = 0, sourceLength = 0) {
    this.sourceKind = sourceKind;
    this.sourcePosition = sourcePosition;
    this.sourceLength = sourceLength;
    this.data = new Writer();
    this.inst = new Writer();
    this.addr = new Writer();
    this.targetLength = 0;
    this.near = new Uint32Array(DEFAULT_NEAR);
    this.same = new Uint32Array(DEFAULT_SAME * 256);
    this.nextSlot = 0;
  }

  updateCache(addr) {
    this.near[this.nextSlot] = addr;
    this.nextSlot = (this.nextSlot + 1) % DEFAULT_NEAR;
    this.same[addr % (DEFAULT_SAME * 256)] = addr;
  }

  add(bytes) {
    const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    this.data.bytes(b);
    if (b.length >= 1 && b.length <= 17) {
      this.inst.u8(1 + b.length);
    } else {
      this.inst.u8(1);
      this.inst.int(b.length);
    }
    this.targetLength += b.length;
  }

  run(byte, size, { nonMinimalSize = false } = {}) {
    this.data.u8(byte);
    this.inst.u8(0);
    this.inst.int(size, { nonMinimal: nonMinimalSize });
    this.targetLength += size;
  }

  copyIndex(size, mode) {
    const base = 19 + 16 * mode;
    if (size === 0) return base;
    if (size >= 4 && size <= 18) return base + (size - 3);
    return -1;
  }

  // Emit a COPY. mode may be forced (e.g. SAME against an uncached address
  // to manufacture a failure); otherwise the encoder picks per RFC 5.4.
  copy(address, size, { mode = null, nonMinimalSize = false, encodedOverride = null } = {}) {
    let chosenMode;
    let encoded;
    const here = this.sourceLength + this.targetLength;
    if (mode === null) {
      let bestD = address;
      let bestM = 0;
      let d = here - address;
      if (d >= 0 && d < bestD) {
        bestD = d;
        bestM = 1;
      }
      for (let i = 0; i < DEFAULT_NEAR; i++) {
        d = address - this.near[i];
        if (d >= 0 && d < bestD) {
          bestD = d;
          bestM = i + 2;
        }
      }
      const h = address % (DEFAULT_SAME * 256);
      if (this.same[h] === address) {
        bestD = h % 256;
        bestM = DEFAULT_NEAR + 2 + Math.floor(h / 256);
      }
      chosenMode = bestM;
      encoded = bestD;
    } else {
      chosenMode = mode;
      if (chosenMode === 0) encoded = address;
      else if (chosenMode === 1) encoded = here - address;
      else if (chosenMode <= 1 + DEFAULT_NEAR) encoded = address - this.near[chosenMode - 2];
      else encoded = address % 256;
    }

    const fixed = this.copyIndex(size, chosenMode);
    if (fixed >= 0) {
      this.inst.u8(fixed);
    } else {
      this.inst.u8(19 + 16 * chosenMode);
      this.inst.int(size, { nonMinimal: nonMinimalSize });
    }

    if (chosenMode >= 2 + DEFAULT_NEAR) {
      this.addr.u8((encodedOverride ?? encoded) & 0xff);
    } else {
      this.addr.int(encodedOverride ?? encoded);
    }
    this.updateCache(address);
    this.targetLength += size;
  }

  // Emit one of the combined ADD+COPY code table entries (163+).
  addCopyPair(addBytes, address, copySize, pairMode) {
    const addSize = addBytes.length;
    let index;
    if (pairMode <= 5) {
      if (copySize < 4 || copySize > 6) throw new Error('pair copy size must be 4..6');
      index = 163 + pairMode * 12 + (addSize - 1) * 3 + (copySize - 4);
    } else if (pairMode <= 8) {
      if (copySize !== 4) throw new Error('pair copy size must be 4 for modes 6..8');
      index = 235 + (pairMode - 6) * 4 + (addSize - 1);
    } else {
      throw new Error('bad pair mode');
    }
    this.data.bytes(addBytes);
    this.inst.u8(index);
    const here = this.sourceLength + this.targetLength;
    let encoded;
    if (pairMode === 0) encoded = address;
    else if (pairMode === 1) encoded = here - address;
    else if (pairMode <= 5) encoded = address - this.near[pairMode - 2];
    else encoded = address % 256;
    if (pairMode >= 2 + DEFAULT_NEAR) this.addr.u8(encoded & 0xff);
    else this.addr.int(encoded);
    this.updateCache(address);
    this.targetLength += addSize + copySize;
  }

  build({ deltaIndicator = 0x00, lengthOverride = null } = {}) {
    const data = this.data.toBuffer();
    const inst = this.inst.toBuffer();
    const addr = this.addr.toBuffer();

    const body = new Writer();
    body.int(this.targetLength);
    body.u8(deltaIndicator);
    body.int(data.length);
    body.int(inst.length);
    body.int(addr.length);
    body.bytes(data);
    body.bytes(inst);
    body.bytes(addr);
    const bodyBuf = body.toBuffer();

    const w = new Writer();
    let indicator = 0;
    if (this.sourceKind === 'SOURCE') indicator |= VCD_SOURCE;
    if (this.sourceKind === 'TARGET') indicator |= VCD_TARGET;
    if (indicator !== 0) {
      w.u8(indicator);
      w.int(this.sourceLength);
      w.int(this.sourcePosition);
    } else {
      w.u8(0x00);
    }
    w.int(lengthOverride ?? bodyBuf.length);
    w.bytes(bodyBuf);
    return w.toBuffer();
  }
}

export function assemble(...windows) {
  const w = new Writer();
  w.bytes(header());
  for (const win of windows) w.bytes(win);
  return w.toBuffer();
}

export { ADDRESS_MODES };
