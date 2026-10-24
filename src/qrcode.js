// 纯前端离线二维码生成器（ISO/IEC 18004，Version 1–10，ECC Level M，Byte 模式）。
// 零外部依赖、不发任何网络请求，适配 PS5 离线/内网 DNS 劫持环境。

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(degree) {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    const root = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], root);
    }
    poly = next;
  }
  return poly;
}

function rsEncode(data, ecLen) {
  const gen = rsGeneratorPoly(ecLen);
  const rem = new Uint8Array(ecLen);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ rem[0];
    rem.copyWithin(0, 1);
    rem[ecLen - 1] = 0;
    if (factor !== 0) {
      for (let j = 0; j < ecLen; j++) {
        rem[j] ^= gfMul(gen[j + 1], factor);
      }
    }
  }
  return rem;
}

// Version 1..10 参数表（ECC Level M）：
// [dataCodewords, ecCodewordsPerBlock, [numBlocks1, dataPerBlock1, numBlocks2?, dataPerBlock2?], alignmentCenters]
const VERSION_TABLE_M = [
  null,
  [16, 10, [1, 16], []],
  [28, 16, [1, 28], [6, 18]],
  [44, 26, [1, 44], [6, 22]],
  [64, 18, [2, 32], [6, 26]],
  [86, 24, [2, 43], [6, 30]],
  [108, 16, [4, 27], [6, 34]],
  [124, 18, [4, 31], [6, 22, 38]],
  [154, 22, [2, 38, 2, 39], [6, 24, 42]],
  [182, 22, [3, 36, 2, 37], [6, 26, 46]],
  [216, 26, [4, 43, 1, 44], [6, 28, 50]],
];

function utf8Bytes(text) {
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(String(text));
  }
  const out = [];
  const str = unescape(encodeURIComponent(String(text)));
  for (let i = 0; i < str.length; i++) out.push(str.charCodeAt(i));
  return new Uint8Array(out);
}

function selectVersion(byteLen) {
  for (let v = 1; v <= 10; v++) {
    const dataCap = VERSION_TABLE_M[v][0];
    const headerBits = 4 + (v <= 9 ? 8 : 16);
    if (headerBits + byteLen * 8 <= dataCap * 8) return v;
  }
  throw new Error("QR 内容过长（超过 Version 10 容量）");
}

function buildCodewords(bytes, version) {
  const [totalData, ecPerBlock, blocks] = VERSION_TABLE_M[version];
  const bits = [];
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };

  // Byte mode = 0100
  pushBits(0b0100, 4);
  pushBits(bytes.length, version <= 9 ? 8 : 16);
  for (let i = 0; i < bytes.length; i++) pushBits(bytes[i], 8);

  const maxBits = totalData * 8;
  const term = Math.min(4, maxBits - bits.length);
  pushBits(0, term);
  while (bits.length % 8 !== 0) bits.push(0);

  const dataWords = new Uint8Array(totalData);
  for (let i = 0; i < bits.length / 8; i++) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
    dataWords[i] = b;
  }
  let padIdx = 0;
  for (let i = bits.length / 8; i < totalData; i++) {
    dataWords[i] = padIdx++ % 2 === 0 ? 0xec : 0x11;
  }

  // 分块并计算 Reed-Solomon 纠错码
  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (let g = 0; g < blocks.length; g += 2) {
    const count = blocks[g];
    const len = blocks[g + 1];
    for (let b = 0; b < count; b++) {
      const slice = dataWords.subarray(offset, offset + len);
      offset += len;
      dataBlocks.push(slice);
      ecBlocks.push(rsEncode(slice, ecPerBlock));
    }
  }

  const out = [];
  const maxDataLen = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxDataLen; i++) {
    for (let b = 0; b < dataBlocks.length; b++) {
      if (i < dataBlocks[b].length) out.push(dataBlocks[b][i]);
    }
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (let b = 0; b < ecBlocks.length; b++) {
      out.push(ecBlocks[b][i]);
    }
  }
  return out;
}

function createBaseMatrix(version) {
  const size = 17 + version * 4;
  const modules = Array.from({ length: size }, () => new Uint8Array(size));
  const isFunc = Array.from({ length: size }, () => new Uint8Array(size));

  const setFunc = (r, c, dark) => {
    if (r < 0 || r >= size || c < 0 || c >= size) return;
    modules[r][c] = dark ? 1 : 0;
    isFunc[r][c] = 1;
  };

  // Finder patterns + 1px 隔离带
  const placeFinder = (topR, leftC) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const inOuter = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
        const onBorder = dr === 0 || dr === 6 || dc === 0 || dc === 6;
        const inCore = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        setFunc(topR + dr, leftC + dc, inOuter && (onBorder || inCore));
      }
    }
  };
  placeFinder(0, 0);
  placeFinder(0, size - 7);
  placeFinder(size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    setFunc(6, i, i % 2 === 0);
    setFunc(i, 6, i % 2 === 0);
  }

  // Alignment patterns
  const centers = VERSION_TABLE_M[version][3];
  for (let i = 0; i < centers.length; i++) {
    for (let j = 0; j < centers.length; j++) {
      const cr = centers[i];
      const cc = centers[j];
      if (isFunc[cr][cc]) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const dist = Math.max(Math.abs(dr), Math.abs(dc));
          setFunc(cr + dr, cc + dc, dist !== 1);
        }
      }
    }
  }

  // Dark module + 预留 Format Info 区域
  setFunc(size - 8, 8, true);
  for (let i = 0; i < 9; i++) {
    if (!isFunc[8][i]) setFunc(8, i, false);
    if (!isFunc[i][8]) setFunc(i, 8, false);
  }
  for (let i = 0; i < 8; i++) {
    if (!isFunc[8][size - 1 - i]) setFunc(8, size - 1 - i, false);
    if (!isFunc[size - 1 - i][8]) setFunc(size - 1 - i, 8, false);
  }

  // Version >= 7 的 Version Info 区域
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const verBits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = ((verBits >>> i) & 1) === 1;
      const a = Math.floor(i / 3);
      const b = size - 11 + (i % 3);
      setFunc(a, b, bit);
      setFunc(b, a, bit);
    }
  }

  return { size, modules, isFunc };
}

function placeDataBits(modules, isFunc, size, codewords) {
  let bitIdx = 0;
  const totalBits = codewords.length * 8;
  let upward = true;

  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // 跳过垂直 timing 列
    for (let vert = 0; vert < size; vert++) {
      const r = upward ? size - 1 - vert : vert;
      for (let j = 0; j < 2; j++) {
        const c = right - j;
        if (isFunc[r][c]) continue;
        let dark = false;
        if (bitIdx < totalBits) {
          dark = ((codewords[bitIdx >>> 3] >>> (7 - (bitIdx & 7))) & 1) === 1;
          bitIdx++;
        }
        modules[r][c] = dark ? 1 : 0;
      }
    }
    upward = !upward;
  }
}

function maskBit(mask, r, c) {
  switch (mask) {
    case 0: return (r + c) % 2 === 0;
    case 1: return r % 2 === 0;
    case 2: return c % 3 === 0;
    case 3: return (r + c) % 3 === 0;
    case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    case 7: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
    default: return false;
  }
}

function writeFormatBits(modules, size, mask) {
  // ECC Level M = 00
  const data = (0b00 << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;

  const bit = (i) => (bits >>> i) & 1;

  // 左上角 Format Info
  const tlCoords = [
    [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
    [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8],
  ];
  for (let i = 0; i < 15; i++) {
    const [r, c] = tlCoords[i];
    modules[r][c] = bit(14 - i);
  }

  // 左下角 + 右上角 Format Info
  for (let i = 0; i < 7; i++) {
    modules[size - 1 - i][8] = bit(14 - i);
  }
  for (let i = 0; i < 8; i++) {
    modules[8][size - 8 + i] = bit(7 - i);
  }
}

function scorePenalty(modules, size) {
  let penalty = 0;

  // N1: 同色连续 >= 5
  const scoreLine = (getCell) => {
    let runColor = getCell(0);
    let runLen = 1;
    for (let i = 1; i < size; i++) {
      const c = getCell(i);
      if (c === runColor) {
        runLen++;
        if (runLen === 5) penalty += 3;
        else if (runLen > 5) penalty += 1;
      } else {
        runColor = c;
        runLen = 1;
      }
    }
  };
  for (let r = 0; r < size; r++) scoreLine((c) => modules[r][c]);
  for (let c = 0; c < size; c++) scoreLine((r) => modules[r][c]);

  // N2: 2x2 同色块
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = modules[r][c];
      if (v === modules[r][c + 1] && v === modules[r + 1][c] && v === modules[r + 1][c + 1]) {
        penalty += 3;
      }
    }
  }

  // N3: 1:1:3:1:1 finder-like 模式
  const checkFinderLike = (getCell) => {
    for (let i = 0; i <= size - 11; i++) {
      const p1 =
        getCell(i) === 1 && getCell(i + 1) === 0 && getCell(i + 2) === 1 &&
        getCell(i + 3) === 1 && getCell(i + 4) === 1 && getCell(i + 5) === 0 &&
        getCell(i + 6) === 1 && getCell(i + 7) === 0 && getCell(i + 8) === 0 &&
        getCell(i + 9) === 0 && getCell(i + 10) === 0;
      const p2 =
        getCell(i) === 0 && getCell(i + 1) === 0 && getCell(i + 2) === 0 &&
        getCell(i + 3) === 0 && getCell(i + 4) === 1 && getCell(i + 5) === 0 &&
        getCell(i + 6) === 1 && getCell(i + 7) === 1 && getCell(i + 8) === 1 &&
        getCell(i + 9) === 0 && getCell(i + 10) === 1;
      if (p1 || p2) penalty += 40;
    }
  };
  for (let r = 0; r < size; r++) checkFinderLike((c) => modules[r][c]);
  for (let c = 0; c < size; c++) checkFinderLike((r) => modules[r][c]);

  // N4: 深色比例偏离 50%
  let dark = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) dark += modules[r][c];
  }
  const total = size * size;
  const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
  if (k > 0) penalty += k * 10;

  return penalty;
}

export function encodeQRMatrix(text) {
  const bytes = utf8Bytes(text);
  const version = selectVersion(bytes.length);
  const codewords = buildCodewords(bytes, version);
  const base = createBaseMatrix(version);
  placeDataBits(base.modules, base.isFunc, base.size, codewords);

  let bestMatrix = null;
  let bestScore = Infinity;

  for (let mask = 0; mask < 8; mask++) {
    const candidate = base.modules.map((row) => new Uint8Array(row));
    for (let r = 0; r < base.size; r++) {
      for (let c = 0; c < base.size; c++) {
        if (!base.isFunc[r][c] && maskBit(mask, r, c)) {
          candidate[r][c] ^= 1;
        }
      }
    }
    writeFormatBits(candidate, base.size, mask);
    const score = scorePenalty(candidate, base.size);
    if (score < bestScore) {
      bestScore = score;
      bestMatrix = candidate;
    }
  }

  return { version, size: base.size, modules: bestMatrix };
}

export function renderQRSvg(text, options = {}) {
  const margin = options.margin ?? 3;
  const fg = options.fg || "#020d05";
  const bg = options.bg || "#d8ffe2";
  const label = options.label || text;
  const { size, modules } = encodeQRMatrix(text);
  const total = size + margin * 2;

  let path = "";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (modules[r][c]) {
        path += `M${c + margin},${r + margin}h1v1h-1z`;
      }
    }
  }

  const safeLabel = String(label)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  return (
    `<svg class="qr-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" ` +
    `shape-rendering="crispEdges" role="img" aria-label="扫码访问 ${safeLabel}">` +
    `<rect width="${total}" height="${total}" rx="1.5" fill="${bg}"/>` +
    `<path d="${path}" fill="${fg}"/>` +
    `</svg>`
  );
}
