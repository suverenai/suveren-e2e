/**
 * File fixtures for the files connector suites: real bytes, built here so the
 * tests compute every expectation (type, size, SHA-256) themselves and share
 * nothing with the connector under test.
 *
 * The PDFs carry a correct xref table / xref stream, so a real PDF reader opens
 * them; a hostile fixture that only "looks like" a PDF would prove little.
 */
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';

export const MIB = 1024 * 1024;
/** Andreas's decision (2026-11-09): at most 18,000,000 bytes (18 MB), at save, per file and per email. */
export const MAX_BYTES = 18_000_000;

export const sha256 = (buf: Buffer): string => createHash('sha256').update(buf).digest('hex');

// ── CRC-32 (PNG chunks, zip entries) ─────────────────────────────────────────
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// ── Images and video ─────────────────────────────────────────────────────────
function pngChunk(type: string, data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

/** A valid solid 8x8 RGB PNG; `salt` changes the colour, so each call can be unique bytes. */
export function png(salt = 0): Buffer {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(8, 0);
  ihdr.writeUInt32BE(8, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // RGB
  const row = Buffer.concat([Buffer.from([0]), Buffer.alloc(8 * 3, salt & 0xff)]);
  const raw = Buffer.concat(Array.from({ length: 8 }, () => row));
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr), pngChunk('IDAT', deflateSync(raw)), pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

export const gif = (): Buffer => Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
export const webp = (): Buffer => Buffer.from('UklGRiIAAABXRUJQVlA4IBYAAAAwAQCdASoBAAEADsD+JaQAA3AAAAAA', 'base64');
/** A JPEG header and end-of-image marker: enough for content detection, not a decodable picture. */
export const jpeg = (): Buffer => Buffer.concat([
  Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]), Buffer.from('JFIF\0', 'latin1'),
  Buffer.from([0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9]),
]);
/** An ISO-BMFF `ftyp` box and a small `mdat`: detected as MP4, not playable. */
export const mp4 = (): Buffer => Buffer.concat([
  Buffer.from([0, 0, 0, 0x18]), Buffer.from('ftypisom', 'latin1'), Buffer.from([0, 0, 2, 0]), Buffer.from('isomiso2', 'latin1'),
  Buffer.from([0, 0, 0, 0x10]), Buffer.from('mdat', 'latin1'), Buffer.alloc(8, 0x11),
]);
/** An EBML header with DocType "webm". */
export function webm(): Buffer {
  const doctype = Buffer.concat([Buffer.from([0x42, 0x82, 0x84]), Buffer.from('webm', 'latin1')]);
  const body = Buffer.concat([
    Buffer.from([0x42, 0x86, 0x81, 0x01, 0x42, 0xf7, 0x81, 0x01, 0x42, 0xf2, 0x81, 0x04, 0x42, 0xf3, 0x81, 0x08]),
    doctype, Buffer.from([0x42, 0x87, 0x81, 0x04, 0x42, 0x85, 0x81, 0x02]),
  ]);
  return Buffer.concat([Buffer.from([0x1a, 0x45, 0xdf, 0xa3, 0x80 | body.length]), body]);
}

/** A RIFF container that is not WebP: a check of only the first four bytes passes it. */
export const wav = (): Buffer => Buffer.concat([
  Buffer.from('RIFF', 'latin1'), Buffer.from([0x24, 0, 0, 0]), Buffer.from('WAVEfmt ', 'latin1'), Buffer.alloc(32, 1),
]);

// ── Zip, Word, Excel ─────────────────────────────────────────────────────────
/** A valid stored (uncompressed) zip with the given entries. */
export function zip(entries: Record<string, string>): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [name, text] of Object.entries(entries)) {
    const nameBuf = Buffer.from(name, 'utf8');
    const data = Buffer.from(text, 'utf8');
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    parts.push(local, nameBuf, data);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt32LE(offset, 42);
    central.push(cd, nameBuf);
    offset += local.length + nameBuf.length + data.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  const count = Object.keys(entries).length;
  eocd.writeUInt16LE(count, 8);
  eocd.writeUInt16LE(count, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cdBuf, eocd]);
}

export const docx = (): Buffer => zip({
  '[Content_Types].xml': '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
  'word/document.xml': '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p/></w:body></w:document>',
});
export const xlsx = (): Buffer => zip({
  '[Content_Types].xml': '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>',
  'xl/workbook.xml': '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>',
});
/** The legacy Office container (.doc, .xls): the OLE2 signature and an empty header sector. */
export const ole2 = (): Buffer => Buffer.concat([Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), Buffer.alloc(504)]);

// ── PDF ──────────────────────────────────────────────────────────────────────
export interface PdfOptions {
  /** Extra entries in the document catalog, as PDF source. */
  catalogExtra?: string;
  /** Extra entries in the page dictionary, as PDF source. */
  pageExtra?: string;
  /** Extra objects, numbered from 6, each as the source between `obj` and `endobj`. */
  extraObjects?: string[];
  /** Text on the page, so two PDFs can differ in bytes. */
  text?: string;
  /** Digits in an unused stream object, to reach a size. */
  padding?: number;
}

function streamObject(data: Buffer, dictExtra = ''): Buffer {
  return Buffer.concat([Buffer.from(`<< /Length ${data.length}${dictExtra} >>\nstream\n`, 'latin1'), data, Buffer.from('\nendstream', 'latin1')]);
}

/** Digits only: nothing in the padding can spell a PDF keyword by accident. */
function digits(n: number): Buffer {
  const b = Buffer.allocUnsafe(n);
  let x = 0x2545f491;
  for (let i = 0; i < n; i++) {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    b[i] = 0x30 + ((x >>> 0) % 10);
  }
  return b;
}

function serializeClassic(objects: Buffer[]): Buffer {
  const chunks: Buffer[] = [Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
  let pos = chunks[0].length;
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(pos);
    const b = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`, 'latin1'), body, Buffer.from('\nendobj\n', 'latin1')]);
    chunks.push(b);
    pos += b.length;
  });
  const size = objects.length + 1;
  const table = [`xref\n0 ${size}\n0000000000 65535 f \n`, ...offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`)].join('');
  chunks.push(Buffer.from(`${table}trailer\n<< /Size ${size} /Root 1 0 R >>\nstartxref\n${pos}\n%%EOF\n`, 'latin1'));
  return Buffer.concat(chunks);
}

export function buildPdf(o: PdfOptions = {}): Buffer {
  const content = Buffer.from(`BT /F1 12 Tf 72 720 Td (${o.text ?? 'Hello'}) Tj ET`, 'latin1');
  const objects: Buffer[] = [
    `<< /Type /Catalog /Pages 2 0 R ${o.catalogExtra ?? ''}>>`,
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> ${o.pageExtra ?? ''}>>`,
  ].map((s) => Buffer.from(s, 'latin1'));
  objects.push(streamObject(content));
  objects.push(Buffer.from('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>', 'latin1'));
  for (const extra of o.extraObjects ?? []) objects.push(Buffer.from(extra, 'latin1'));
  if (o.padding) objects.push(streamObject(digits(o.padding)));
  return serializeClassic(objects);
}

/** A clean PDF of exactly `target` bytes. */
export function pdfOfSize(target: number, text = 'large'): Buffer {
  let padding = Math.max(1, target - buildPdf({ text, padding: 1 }).length);
  for (let i = 0; i < 8; i++) {
    const pdf = buildPdf({ text, padding });
    if (pdf.length === target) return pdf;
    padding += target - pdf.length;
  }
  throw new Error(`could not build a PDF of exactly ${target} bytes`);
}

export const pdfJavaScriptNameTree = (): Buffer => buildPdf({
  catalogExtra: '/Names << /JavaScript 6 0 R >> ',
  extraObjects: ['<< /Names [(a) 7 0 R] >>', '<< /S /JavaScript /JS (app.alert\\(1\\)) >>'],
});
export const pdfOpenActionScript = (): Buffer => buildPdf({ catalogExtra: '/OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> ' });
/** The same script, its PDF names written with #xx escapes: readers decode them, a byte search does not. */
export const pdfObfuscatedOpenAction = (): Buffer => buildPdf({ catalogExtra: '/Open#41ction << /S /J#61vaScript /#4AS (app.alert\\(1\\)) >> ' });
export const pdfEmbeddedFile = (): Buffer => buildPdf({
  catalogExtra: '/Names << /EmbeddedFiles 6 0 R >> ',
  extraObjects: [
    '<< /Names [(a.txt) 7 0 R] >>',
    '<< /Type /Filespec /F (a.txt) /EF << /F 8 0 R >> >>',
    '<< /Type /EmbeddedFile /Length 5 >>\nstream\nhello\nendstream',
  ],
});

/**
 * A script hidden in a compressed object stream (PDF 1.5). Neither "/OpenAction"
 * nor "/JavaScript" appears in the file's raw bytes; a reader finds both after
 * inflating the object stream.
 */
export function pdfScriptInObjectStream(): Buffer {
  const catalog = '<< /Type /Catalog /Pages 2 0 R /OpenAction 7 0 R >>';
  const action = '<< /S /JavaScript /JS (app.alert\\(1\\)) >>';
  // Object numbers and their offsets after /First: the catalog at 0, the action after it.
  const header = `1 0 7 ${catalog.length + 1} `;
  const first = header.length;
  const objStm = deflateSync(Buffer.from(`${header}${catalog} ${action}`, 'latin1'));

  const content = Buffer.from('BT /F1 12 Tf 72 720 Td (Hello) Tj ET', 'latin1');
  const plain: Array<[number, Buffer]> = [
    [2, Buffer.from('<< /Type /Pages /Kids [3 0 R] /Count 1 >>', 'latin1')],
    [3, Buffer.from('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>', 'latin1')],
    [4, streamObject(content)],
    [5, Buffer.from('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>', 'latin1')],
    [6, streamObject(objStm, ` /Type /ObjStm /N 2 /First ${first} /Filter /FlateDecode`)],
  ];
  const chunks: Buffer[] = [Buffer.from('%PDF-1.5\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
  let pos = chunks[0].length;
  const offsets = new Map<number, number>();
  for (const [num, body] of plain) {
    offsets.set(num, pos);
    const b = Buffer.concat([Buffer.from(`${num} 0 obj\n`, 'latin1'), body, Buffer.from('\nendobj\n', 'latin1')]);
    chunks.push(b);
    pos += b.length;
  }
  const xrefOffset = pos;
  const entry = (type: number, a: number, b: number) => {
    const e = Buffer.alloc(7);
    e[0] = type;
    e.writeUInt32BE(a, 1);
    e.writeUInt16BE(b, 5);
    return e;
  };
  const table = deflateSync(Buffer.concat([
    entry(0, 0, 65535), entry(2, 6, 0),
    entry(1, offsets.get(2)!, 0), entry(1, offsets.get(3)!, 0), entry(1, offsets.get(4)!, 0), entry(1, offsets.get(5)!, 0), entry(1, offsets.get(6)!, 0),
    entry(2, 6, 1), entry(1, xrefOffset, 0),
  ]));
  chunks.push(Buffer.concat([
    Buffer.from('8 0 obj\n', 'latin1'),
    streamObject(table, ' /Type /XRef /Size 9 /W [1 4 2] /Root 1 0 R /Filter /FlateDecode'),
    Buffer.from(`\nendobj\nstartxref\n${xrefOffset}\n%%EOF\n`, 'latin1'),
  ]));
  return Buffer.concat(chunks);
}

export const pdfForm = (text = 'form'): Buffer => buildPdf({ text, catalogExtra: '/AcroForm << /Fields [] >> ' });

/** A text annotation; `note` is text inside the file, which must never reach the card. */
export const pdfAnnotated = (note: string, text = 'annotated'): Buffer => buildPdf({
  text,
  pageExtra: '/Annots [6 0 R] ',
  extraObjects: [`<< /Type /Annot /Subtype /Text /Rect [10 10 40 40] /Contents (${note}) >>`],
});

/** A clean PDF with one incremental update appended (a second body, xref and %%EOF). */
export function pdfIncrementalUpdate(): Buffer {
  const base = buildPdf({ text: 'original' });
  const prev = Number(/startxref\n(\d+)\n%%EOF\n$/.exec(base.toString('latin1'))![1]);
  const obj = '6 0 obj\n<< /Producer (later edit) >>\nendobj\n';
  const objOffset = base.length;
  const xrefOffset = objOffset + obj.length;
  const update = `${obj}xref\n6 1\n${String(objOffset).padStart(10, '0')} 00000 n \ntrailer\n<< /Size 7 /Root 1 0 R /Prev ${prev} >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return Buffer.concat([base, Buffer.from(update, 'latin1')]);
}
