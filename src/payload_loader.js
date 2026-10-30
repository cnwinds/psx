// 页面内加载 payload：漏洞链跑通后 elfldr 监听 127.0.0.1:9021。
// 浏览器不把 ELF 读进内存，而是用 ROP socket 向本机 9021 发
// GET /?uri=<本站 ELF 的绝对地址>。elfldr 自己下载并执行。
// 这样页面可以停在 HTTPS（用户指南），不必再 fetch('http://127.0.0.1:9021')。
// 发送哪些、按什么顺序，全部由 elfplan（幕二的勾选与排序）决定。

import { loadPlan, itemById, itemByFile } from "./elfplan.js";

const AF_INET = 2;
const SOCK_STREAM = 1;
const ELFLDR_PORT = 9021;
const AUTO_STEP_DELAY_MS = 4000;
const REPLY_MAX = 8192;

let runtime = null;
let running = false;
let chainRunning = false;

function log(message, type = "log") {
  if (typeof window.writeLog !== "function") return;
  window.writeLog(message, type);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function setRow(file, state, bytes) {
  const item = itemByFile(file);
  if (item && window.setElfRowState) window.setElfRowState(item.id, state, bytes);
}

function enabledChain() {
  // 幕二当前顺序里的勾选项：[{id, file, name}]
  const plan = loadPlan();
  return plan.order
    .map((id) => itemById(id))
    .filter((item) => item && !plan.off.has(item.id))
    .map((item) => ({ id: item.id, file: item.file, name: item.name }));
}

function isPrivateIpv4(hostname) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if ([a, b, Number(m[3]), Number(m[4])].some((n) => n > 255)) return false;
  if (a === 10 || a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

// 自签的用户指南站 / 内网 HTTPS 同时在 80 提供同一份文件。
// elfldr 自己下载，用明文 HTTP 避开它不认浏览器已放行的自签证书。
// 公网 HTTPS（如 GitHub Pages）保持原样。
function preferPlainHttp(page) {
  const defaultHttps = page.protocol === "https:" && (page.port === "" || page.port === "443");
  if (!defaultHttps) return false;
  return page.hostname === "manuals.playstation.net" || isPrivateIpv4(page.hostname);
}

export function payloadFetchUrl(file, pageHref) {
  if (!/^[A-Za-z0-9._-]+$/.test(file)) throw new Error("非法 payload 文件名");
  const page = new URL(pageHref);
  if (!page.pathname.endsWith("/") && !/\.html?$/i.test(page.pathname)) page.pathname += "/";
  const same = new URL("payloads/" + file, page);
  same.search = "";
  same.hash = "";
  if (preferPlainHttp(page)) return "http://" + page.hostname + same.pathname;
  return same.href;
}

export function elfldrGetRequest(payloadUrl) {
  return "GET /?uri=" + encodeURIComponent(payloadUrl) + " HTTP/1.1\r\n" +
    "Host: 127.0.0.1:" + ELFLDR_PORT + "\r\n" +
    "Connection: close\r\n\r\n";
}

function pageHref() {
  if (typeof location !== "undefined" && location && location.href) return location.href;
  throw new Error("无法确定本站地址");
}

// elfldr 打印"监听中"与套接字真正就绪之间存在竞态（kstuff 是第一个连接，
// 最容易撞上），connect 失败时退避重试而不是直接放弃。
const CONNECT_ATTEMPTS = 4;

async function connectElfldr(addr) {
  const chain = runtime.chain;
  for (let attempt = 1; ; attempt++) {
    const fd = ((await chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0)).low | 0);
    if (fd < 0) throw new Error("socket() 失败 (" + fd + ")");
    const connected = (await chain.syscall(SYS_CONNECT, fd, addr, 0x10)).low | 0;
    if (connected === 0) return fd;
    await chain.syscall(SYS_CLOSE, fd);
    if (attempt >= CONNECT_ATTEMPTS)
      throw new Error(
        "connect() 127.0.0.1:" + ELFLDR_PORT + " 失败"
      );
    log("  connect 未就绪，" + (attempt * 1.2).toFixed(1) + " 秒后重试（" + attempt + "/" + CONNECT_ATTEMPTS + "）…");
    await sleep(1200 * attempt);
  }
}

function writeAscii(ptr, text) {
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i) & 0xff;
  if (!ptr.backing || typeof ptr.backing.set !== "function")
    throw new Error("发送缓冲区不可写");
  ptr.backing.set(bytes);
}

function readAscii(ptr, length) {
  const backing = ptr.backing;
  if (!backing) throw new Error("无法读取 elfldr 响应");
  let text = "";
  const n = Math.min(length, backing.length);
  for (let i = 0; i < n; i++) text += String.fromCharCode(backing[i]);
  return text;
}

function replyRejected(text) {
  return /Error reading|Unknown payload|Error spawning/i.test(text);
}

async function sendUriToElfldr(payloadUrl) {
  const p = runtime.p;
  const chain = runtime.chain;
  const request = elfldrGetRequest(payloadUrl);

  // sockaddr_in: { len: 0x10, family: AF_INET, port: htons(9021), addr: htonl(127.0.0.1) }
  const addr = p.malloc(0x10, 1);
  for (let i = 0; i < 0x10; i++) p.write1(addr.add32(i), 0);
  p.write1(addr.add32(0x0), 0x10);
  p.write1(addr.add32(0x1), AF_INET);
  p.write2(addr.add32(0x2), ((ELFLDR_PORT & 0xff) << 8) | ((ELFLDR_PORT >> 8) & 0xff));
  p.write4(addr.add32(0x4), (127) | (0 << 8) | (0 << 16) | (1 << 24));

  const reqBuf = p.malloc(request.length + 1, 1);
  writeAscii(reqBuf, request);
  const replyBuf = p.malloc(0x400, 1);

  const fd = await connectElfldr(addr);
  try {
    let sent = 0;
    while (sent < request.length) {
      const written = (await chain.syscall(SYS_WRITE, fd, reqBuf.add32(sent), request.length - sent)).low | 0;
      if (written < 0) throw new Error("write() 失败 (" + written + ")");
      if (written === 0) throw new Error("write() 返回 0，连接被对端关闭");
      sent += written;
    }
    log("  已通知 elfldr 下载，等待它拉取并启动…");

    let reply = "";
    for (;;) {
      const n = (await chain.syscall(SYS_READ, fd, replyBuf, 0x400)).low | 0;
      if (n < 0) {
        if (reply) break;
        throw new Error("read() 失败 (" + n + ")");
      }
      if (n === 0) break;
      reply += readAscii(replyBuf, n);
      if (reply.length >= REPLY_MAX) break;
    }
    const brief = reply.replace(/\s+/g, " ").trim().slice(0, 180);
    if (!reply.trim()) throw new Error("elfldr 没有返回结果");
    if (replyRejected(reply) || !/HTTP\/1\.[01] 200/.test(reply))
      throw new Error(brief || "elfldr 拒绝了该地址");
    return brief;
  } finally {
    await chain.syscall(SYS_CLOSE, fd);
  }
}

export async function sendPayload(file, fromChain = false) {
  if (!runtime) throw new Error("漏洞利用尚未完成");
  if (chainRunning && !fromChain) {
    log("自动加载正在运行", "info");
    return false;
  }
  if (running) {
    log("正在发送", "error");
    return false;
  }

  const item = itemByFile(file);
  const title = item ? item.name : file;
  running = true;
  setRow(file, "sending");

  try {
    const url = payloadFetchUrl(file, pageHref());
    log("让 elfldr 从本站加载 " + title + " ← " + url, "info");
    const reply = await sendUriToElfldr(url);
    setRow(file, "done");
    log(title + " 已交给 elfldr" + (reply ? "（" + reply.slice(0, 80) + "）" : ""), "success");
    return true;
  } catch (error) {
    setRow(file, "failed");
    log(title + " 发送失败: " + (error instanceof Error ? error.message : error), "error");
    return false;
  } finally {
    running = false;
  }
}

export async function runAutoChain() {
  if (!runtime || running || chainRunning) return;
  chainRunning = true;
  const button = document.getElementById("btn-runplan");
  if (button) button.disabled = true;
  try {
    const wanted = enabledChain();
    if (!wanted.length) {
      log("没有勾选 ELF", "error");
      return;
    }

    log("按顺序加载: " + wanted.map((it) => it.file).join(" → "), "info");
    for (let i = 0; i < wanted.length; i++) {
      if (!await sendPayload(wanted[i].file, true)) {
        log(wanted[i].name + " 加载失败，已停止", "error");
        return;
      }
      if (i < wanted.length - 1) {
        log("等待 " + AUTO_STEP_DELAY_MS / 1000 + " 秒后发送下一个…");
        await sleep(AUTO_STEP_DELAY_MS);
      }
    }
    log("顺序加载结束", "success");
    if (typeof window.onFlowComplete === "function") window.onFlowComplete();
  } finally {
    chainRunning = false;
    if (button) button.disabled = false;
  }
}

export function initializePayloadSender(p, chain) {
  runtime = { p, chain };

  const rows = document.getElementById("elf-rows");
  if (rows && typeof rows.addEventListener === "function" && !rows._psxSendWired) {
    rows._psxSendWired = true;
    rows.addEventListener("click", (event) => {
      const button = event.target && event.target.closest ? event.target.closest("[data-file]") : null;
      if (!button || button.disabled) return;
      sendPayload(button.dataset.file);
    });
  }

  const run = document.getElementById("btn-runplan");
  if (run && typeof run.addEventListener === "function" && !run._psxRunWired) {
    run._psxRunWired = true;
    run.addEventListener("click", () => {
      runAutoChain();
    });
  }
}
