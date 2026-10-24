/**
 * 浏览器端 FTP 客户端（被动模式 PASV）。
 * 通过 TCPSocket 直连 PS5 的 ftpsrv (:2121) / zftpd (:2120)。
 * 需 Chrome 等支持 Direct Sockets 的环境；普通浏览器请走 HTTP 中转或 ZHTTP :8888。
 */

export function browserFtpSupported() {
  return typeof globalThis.TCPSocket === "function";
}

function encodeCmd(cmd) {
  return new TextEncoder().encode(cmd + "\r\n");
}

function parseListLine(line) {
  // Unix ls -l 风格（ftpsrv 常见）
  const m = line.match(
    /^([-dl])(?:\S+\s+){3,}(\d+)\s+\S+\s+\d+\s+[\d:]+\s+(.+)$/
  );
  if (m) {
    return {
      name: m[3].trim(),
      dir: m[1] === "d",
      size: m[1] === "d" ? 0 : parseInt(m[2], 10) || 0,
      mtime: "",
    };
  }
  const name = line.trim();
  if (!name || name === "." || name === "..") return null;
  return { name, dir: false, size: 0, mtime: "" };
}

export class BrowserFtpClient {
  constructor(host, port = 2121) {
    this.host = host;
    this.port = port;
    this._ctrl = null;
    this._reader = null;
    this._writer = null;
    this._buf = "";
    this._cwd = "/";
  }

  async connect() {
    if (!browserFtpSupported()) {
      throw new Error("当前浏览器不支持 TCPSocket，无法直连 FTP");
    }
    const socket = new TCPSocket(this.host, this.port, { keepAlive: true });
    const opened = await socket.opened;
    this._ctrl = socket;
    this._reader = opened.readable.getReader();
    this._writer = opened.writable.getWriter();
    await this._expect(220);
    await this._cmd("USER anonymous");
    await this._cmd("PASS anonymous@");
    await this._cmd("TYPE I");
    try { await this._cmd("OPTS UTF8 ON"); } catch (_) { /* 可选 */ }
  }

  async close() {
    try { await this._cmd("QUIT"); } catch (_) { /* ignore */ }
    try { await this._writer.close(); } catch (_) {}
    try { await this._reader.cancel(); } catch (_) {}
    try { this._ctrl.close(); } catch (_) {}
    this._ctrl = this._reader = this._writer = null;
  }

  async _write(text) {
    await this._writer.write(encodeCmd(text));
  }

  async _readLine() {
    const dec = new TextDecoder();
    while (true) {
      const nl = this._buf.indexOf("\n");
      if (nl >= 0) {
        const line = this._buf.slice(0, nl).replace(/\r$/, "");
        this._buf = this._buf.slice(nl + 1);
        return line;
      }
      const { value, done } = await this._reader.read();
      if (done) throw new Error("FTP 控制连接已断开");
      this._buf += dec.decode(value, { stream: true });
    }
  }

  async _readReply() {
    const lines = [];
    while (true) {
      const line = await this._readLine();
      lines.push(line);
      if (/^\d{3} /.test(line)) break;
    }
    const last = lines[lines.length - 1];
    const code = parseInt(last.slice(0, 3), 10);
    const text = lines.join("\n");
    if (code >= 400) throw new Error(text.trim());
    return { code, text };
  }

  async _cmd(command) {
    await this._write(command);
    return this._readReply();
  }

  async _expect(codePrefix) {
    const { code, text } = await this._readReply();
    if (Math.floor(code / 100) !== Math.floor(codePrefix / 100) && code !== codePrefix) {
      throw new Error(text.trim());
    }
    return { code, text };
  }

  async _openData() {
    const { text } = await this._cmd("PASV");
    const m = text.match(/\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/);
    if (!m) throw new Error("PASV 解析失败：" + text);
    const dataHost = m.slice(1, 5).join(".");
    const dataPort = parseInt(m[5], 10) * 256 + parseInt(m[6], 10);
    const ds = new TCPSocket(dataHost, dataPort);
    const opened = await ds.opened;
    return {
      socket: ds,
      reader: opened.readable.getReader(),
      writer: opened.writable.getWriter(),
    };
  }

  async _readData(reader) {
    const chunks = [];
    let total = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.byteLength;
    }
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      out.set(c, off);
      off += c.byteLength;
    }
    return out;
  }

  _norm(path) {
    const parts = ("/" + String(path || "").replace(/\\/g, "/")).split("/");
    const out = [];
    for (const p of parts) {
      if (!p || p === ".") continue;
      if (p === "..") out.pop();
      else out.push(p);
    }
    return "/" + out.join("/");
  }

  async _cwd(path) {
    const p = this._norm(path);
    if (p === this._cwd) return p;
    await this._cmd("CWD " + p);
    this._cwd = p;
    return p;
  }

  async list(path, offset = 0, limit = 500) {
    const p = await this._cwd(path);
    let entries = [];
    const data = await this._openData();
    try {
      await this._write("LIST");
      const { code } = await this._readReply();
      if (code !== 150 && code !== 125) throw new Error("LIST 被拒绝：" + code);
      const raw = await this._readData(data.reader);
      await this._expect(226);
      const text = new TextDecoder().decode(raw);
      for (const line of text.split(/\r?\n/)) {
        if (!line.trim()) continue;
        if (line.includes(";")) {
          // MLSD: type=dir;size=0;modify=...; name
          const semi = line.lastIndexOf("; ");
          if (semi < 0) continue;
          const facts = line.slice(0, semi + 1);
          const name = line.slice(semi + 2).trim();
          if (!name || name === "." || name === "..") continue;
          entries.push({
            name,
            dir: /type=dir/i.test(facts),
            size: parseInt((facts.match(/size=(\d+)/i) || [])[1] || "0", 10),
            mtime: (facts.match(/modify=(\d+)/i) || [])[1] || "",
          });
        } else {
          const e = parseListLine(line);
          if (e) entries.push(e);
        }
      }
    } finally {
      try { await data.reader.cancel(); } catch (_) {}
      try { data.socket.close(); } catch (_) {}
    }
    const dirs = entries.filter((e) => e.dir).sort((a, b) => a.name.localeCompare(b.name));
    const files = entries.filter((e) => !e.dir);
    files.sort((a, b) => (b.mtime || "").localeCompare(a.mtime || "") || a.name.localeCompare(b.name));
    entries = dirs.concat(files);
    return {
      path: p,
      total: entries.length,
      entries: entries.slice(offset, offset + limit),
    };
  }

  async mkdir(path) {
    const p = this._norm(path);
    await this._cmd("MKD " + p);
    return { path: p };
  }

  async remove(path, isDir, recursive) {
    const p = this._norm(path);
    if (isDir) {
      if (recursive) await this._rmdirTree(p);
      else await this._cmd("RMD " + p);
    } else {
      await this._cmd("DELE " + p);
    }
  }

  async _rmdirTree(path) {
    const listing = await this.list(path, 0, 10000);
    for (const e of listing.entries) {
      const full = this._norm(path + "/" + e.name);
      if (e.dir) await this._rmdirTree(full);
      else await this._cmd("DELE " + full);
    }
    await this._cwd(posixDirname(path));
    await this._cmd("RMD " + path);
  }

  async rename(from, to) {
    const src = this._norm(from);
    let dst = String(to || "").trim();
    if (!dst.startsWith("/")) {
      dst = this._norm(posixDirname(src) + "/" + dst);
    } else {
      dst = this._norm(dst);
    }
    await this._cmd("RNFR " + src);
    await this._cmd("RNTO " + dst);
    return { path: dst };
  }

  async upload(remotePath, file, onProgress) {
    const p = this._norm(remotePath);
    const dir = posixDirname(p);
    const name = p.split("/").pop();
    await this._cwd(dir);
    await this._ensureDir(dir);
    const data = await this._openData();
    try {
      await this._write("STOR " + name);
      const { code } = await this._readReply();
      if (code !== 150 && code !== 125) throw new Error("STOR 被拒绝：" + code);
      const reader = file.stream().getReader();
      let sent = 0;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        await data.writer.write(value);
        sent += value.byteLength;
        if (onProgress) onProgress(sent, file.size);
      }
      await data.writer.close();
      await this._expect(226);
      return { remote: p, bytes: sent };
    } catch (e) {
      try { await data.reader.cancel(); } catch (_) {}
      try { data.socket.close(); } catch (_) {}
      throw e;
    }
  }

  async _ensureDir(path) {
    const p = this._norm(path);
    if (p === "/") return;
    const parent = posixDirname(p);
    if (parent !== "/") await this._ensureDir(parent);
    try { await this._cmd("MKD " + p); } catch (_) { /* 已存在 */ }
  }

  async download(path) {
    const p = this._norm(path);
    await this._cwd(posixDirname(p));
    const name = p.split("/").pop();
    const data = await this._openData();
    try {
      await this._write("RETR " + name);
      const { code } = await this._readReply();
      if (code !== 150 && code !== 125) throw new Error("RETR 被拒绝：" + code);
      const body = await this._readData(data.reader);
      await this._expect(226);
      return body;
    } finally {
      try { data.socket.close(); } catch (_) {}
    }
  }

  async check(dir, manifest) {
    const existing = {};
    const walk = async (base, rel) => {
      const listing = await this.list(base, 0, 10000);
      for (const e of listing.entries) {
        const r = rel ? rel + "/" + e.name : e.name;
        if (e.dir) await walk(this._norm(base + "/" + e.name), r);
        else existing[r] = e.size;
      }
    };
    await walk(this._norm(dir), "");
    const need = [];
    for (const m of manifest) {
      if (existing[m.name] !== m.size) need.push(m.name);
    }
    return { total: manifest.length, need, skip: manifest.length - need.length };
  }
}

function posixDirname(p) {
  const n = p.replace(/\/+$/, "");
  const i = n.lastIndexOf("/");
  return i <= 0 ? "/" : n.slice(0, i);
}
