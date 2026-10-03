// HTTP front-end for the VCDIFF import verification service.
// Zero runtime dependencies: node:http only.

import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeVcdiff, collectRootSegments, MAX_OUTPUT_BYTES, MAX_WINDOWS, VcdiffError } from './vcdiff.js';

const here = dirname(fileURLToPath(import.meta.url));
const PAGE_HTML = readFileSync(join(here, '..', 'static', 'index.html'));

// Pasted payload limits (checked on the raw Base64 text as well).
export const MAX_DELTA_BASE64_BYTES = 128 * 1024;
export const MAX_DICT_BASE64_BYTES = 64 * 1024;

const STRICT_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
  });
  res.end(payload);
}

function decodeBase64Field(value, label) {
  if (typeof value !== 'string') {
    throw new VcdiffError('BAD_REQUEST', `${label} must be a Base64 string`);
  }
  if (value.length === 0) return new Uint8Array(0);
  if (!STRICT_BASE64.test(value)) {
    throw new VcdiffError('BAD_BASE64', `${label} is not valid canonical Base64`);
  }
  const buf = Buffer.from(value, 'base64');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function serializeInstruction(ins) {
  const out = {
    seq: ins.seq,
    op: ins.op,
    size: ins.size,
    codeOffset: ins.codeOffset,
  };
  if (ins.op === 'ADD') out.dataHex = ins.dataHex;
  if (ins.op === 'RUN') out.byteHex = ins.byteHex;
  if (ins.op === 'COPY') {
    out.mode = ins.mode;
    out.modeValue = ins.modeValue;
    out.encoded = ins.encoded;
    out.encodedOffset = ins.encodedOffset;
    out.address = ins.address; // address inside the window's U = source||target space
    out.overlaps = ins.overlaps;
    out.range = ins.range; // resolved location in dictionary / output
  }
  return out;
}

export function handleDecode(rawBody) {
  let parsed;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    throw new VcdiffError('BAD_JSON', 'request body must be a JSON object');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new VcdiffError('BAD_REQUEST', 'request body must be a JSON object');
  }

  const { deltaBase64, dictionaryBase64 } = parsed;
  if (typeof deltaBase64 !== 'string') {
    throw new VcdiffError('BAD_REQUEST', 'field "deltaBase64" is required');
  }
  if (deltaBase64.length > MAX_DELTA_BASE64_BYTES) {
    throw new VcdiffError(
      'PAYLOAD_TOO_LARGE',
      `delta Base64 payload exceeds ${MAX_DELTA_BASE64_BYTES} bytes`,
    );
  }
  const dictText = typeof dictionaryBase64 === 'string' ? dictionaryBase64 : '';
  if (dictText.length > MAX_DICT_BASE64_BYTES) {
    throw new VcdiffError(
      'PAYLOAD_TOO_LARGE',
      `dictionary Base64 payload exceeds ${MAX_DICT_BASE64_BYTES} bytes`,
    );
  }

  const delta = decodeBase64Field(deltaBase64, 'deltaBase64');
  const dictionary = decodeBase64Field(dictText, 'dictionaryBase64');

  // Optional root-origin trace over the final output. Both fields must be
  // supplied together and must be integers (start >= 0, length >= 1);
  // anything else rejects the whole request.
  const { traceStart, traceLength } = parsed;
  const traceRequested = traceStart !== undefined || traceLength !== undefined;
  if (traceRequested) {
    if (
      typeof traceStart !== 'number' ||
      !Number.isInteger(traceStart) ||
      traceStart < 0 ||
      typeof traceLength !== 'number' ||
      !Number.isInteger(traceLength) ||
      traceLength < 1
    ) {
      throw new VcdiffError(
        'BAD_TRACE',
        'traceStart and traceLength must be supplied together as integers ' +
          '(start >= 0, length >= 1)',
      );
    }
  }

  // The decoder either returns the complete output, or throws; on failure no
  // partial output leaves this function.
  const result = decodeVcdiff(delta, dictionary, { provenance: traceRequested });

  let trace = null;
  if (traceRequested) {
    if (traceStart > result.length || traceLength > result.length - traceStart) {
      throw new VcdiffError(
        'TRACE_RANGE',
        `trace range [${traceStart}, +${traceLength}) lies outside the ` +
          `${result.length} bytes of decoded output`,
      );
    }
    trace = {
      start: traceStart,
      length: traceLength,
      segments: collectRootSegments(result.provenance, traceStart, traceLength),
    };
  }

  const sha256 = createHash('sha256').update(result.output).digest('hex');
  const body = {
    ok: true,
    length: result.length,
    sha256,
    windows: result.windows.map((w) => ({
      index: w.index,
      windowOffset: w.windowOffset,
      source: w.source,
      targetOffset: w.targetOffset,
      targetLength: w.targetLength,
      deltaLength: w.deltaLength,
      sections: w.sections,
      instructions: w.instructions.map(serializeInstruction),
    })),
    limits: { maxOutputBytes: MAX_OUTPUT_BYTES, maxWindows: MAX_WINDOWS },
  };
  if (trace) body.trace = trace;
  return body;
}

export function createApp() {
  return createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');

    if (req.method === 'GET' && url.pathname === '/healthz') {
      return json(res, 200, { status: 'ok' });
    }

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'content-length': PAGE_HTML.length,
        'cache-control': 'no-store',
      });
      return res.end(PAGE_HTML);
    }

    if (req.method === 'POST' && url.pathname === '/api/decode') {
      const chunks = [];
      let size = 0;
      req.on('data', (chunk) => {
        size += chunk.length;
        // Bound the raw JSON body generously above the field limits.
        if (size > MAX_DELTA_BASE64_BYTES + MAX_DICT_BASE64_BYTES + 4096) {
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        try {
          const answer = handleDecode(Buffer.concat(chunks));
          return json(res, 200, answer);
        } catch (err) {
          if (err instanceof VcdiffError) {
            const status = err.code === 'PAYLOAD_TOO_LARGE' ? 413 : 400;
            return json(res, status, {
              ok: false,
              error: { code: err.code, message: err.message, offset: err.offset },
            });
          }
          return json(res, 500, {
            ok: false,
            error: { code: 'INTERNAL', message: 'internal error', offset: null },
          });
        }
      });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/reset') {
      // The service is stateless; this endpoint exists so the page can report
      // that server-side conclusions have been cleared.
      return json(res, 200, { ok: true });
    }

    if (req.method === 'GET' && url.pathname === '/favicon.ico') {
      res.writeHead(204);
      return res.end();
    }

    json(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: 'not found', offset: null } });
  });
}

function startServer() {
  const host = process.env.HOST ?? '0.0.0.0';
  const port = Number.parseInt(process.env.PORT ?? '8080', 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error(`invalid PORT: ${process.env.PORT}`);
    process.exit(2);
  }
  const server = createApp();
  server.listen(port, host, () => {
    console.log(`vcdiff-archive-guard listening on http://${host}:${port}`);
  });

  const shutdown = (signal) => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
    signal;
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// Run directly (node src/server.js); importable for tests without binding.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  startServer();
}
