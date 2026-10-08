// All-in-one payload sender: after the kernel exploit leaves elfldr listening
// on 127.0.0.1:9021, payloads are pushed through a ROP-driven TCP connection
// so the whole chain runs from this single page.

const AF_INET = 2;
const SOCK_STREAM = 1;
const ELFLDR_PORT = 9021;

const PAYLOADS = [
  {
    file: "kstuff.elf",
    id: "kstuff",
    title: "kstuff-lite 1.11",
    desc: "内核补丁：FSELF / FPKG 支持（FW 1.00 - 13.60）",
    source: "https://github.com/EchoStretch/kstuff-lite",
  },
  {
    file: "etaHEN-2.5B.bin",
    id: "etahen",
    title: "etaHEN 2.5B",
    desc: "AIO HEN：Toolbox / FTP(1337) / PKG 安装器(9090)",
    source: "https://github.com/etaHEN/etaHEN",
  },
  {
    file: "shadowmountplus.elf",
    id: "smp",
    title: "ShadowMountPlus 1.7beta3",
    desc: "游戏镜像自动挂载（需要 kstuff 运行中）",
    source: "https://github.com/drakmor/ShadowMountPlus",
  },
];

// kstuff patches the kernel first, etaHEN builds HEN on top of it, and
// ShadowMountPlus then mounts game images (its kstuff auto-pause logic
// expects kstuff to be alive).
const AUTO_CHAIN = ["kstuff.elf", "etaHEN-2.5B.bin", "shadowmountplus.elf"];
const AUTO_STEP_DELAY_MS = 4000;

let runtime = null;
let running = false;

function log(message, type = "log") {
  if (typeof window.writeLog === "function") window.writeLog(message, type);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function findPayload(file) {
  const entry = PAYLOADS.find((p) => p.file === file);
  if (!entry) throw new Error("未知 payload: " + file);
  return entry;
}

function card(file) {
  return document.getElementById("card-" + findPayload(file).id);
}

function setStatus(file, state, text) {
  const node = card(file);
  if (!node) return;
  node.dataset.state = state;
  const label = node.querySelector(".status");
  if (label && text) label.textContent = text;
}

async function loadIntoMemory(file) {
  const response = await fetch("payloads/" + file + "?v=" + Date.now());
  if (!response.ok) throw new Error(file + " 下载失败 HTTP " + response.status);
  const bytes = new Uint8Array(await response.arrayBuffer());

  const magic = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;
  if (magic !== 0x464c457f) throw new Error(file + " 不是有效的 ELF 文件");

  const buffer = runtime.p.malloc(bytes.length + 0x10, 1);
  buffer.backing.set(bytes);
  if (runtime.p.read4(buffer) >>> 0 !== 0x464c457f)
    throw new Error(file + " 内存副本校验失败");

  return { ptr: buffer, size: bytes.length };
}

async function sendToElfldr(ptr, size) {
  const p = runtime.p;
  const chain = runtime.chain;

  // sockaddr_in: { len: 0x10, family: AF_INET, port: htons(9021), addr: htonl(127.0.0.1) }
  const addr = p.malloc(0x10, 1);
  for (let i = 0; i < 0x10; i++) p.write1(addr.add32(i), 0);
  p.write1(addr.add32(0x0), 0x10);
  p.write1(addr.add32(0x1), AF_INET);
  p.write2(addr.add32(0x2), ((ELFLDR_PORT & 0xff) << 8) | ((ELFLDR_PORT >> 8) & 0xff));
  p.write4(addr.add32(0x4), (127) | (0 << 8) | (0 << 16) | (1 << 24));

  const fd = ((await chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0)).low | 0);
  if (fd < 0) throw new Error("socket() 失败 (" + fd + ")");

  try {
    const connected = (await chain.syscall(SYS_CONNECT, fd, addr, 0x10)).low | 0;
    if (connected < 0)
      throw new Error("connect() 127.0.0.1:" + ELFLDR_PORT + " 失败，elfldr 是否在监听？");

    let sent = 0;
    while (sent < size) {
      const written = (await chain.syscall(SYS_WRITE, fd, ptr.add32(sent), size - sent)).low | 0;
      if (written < 0) throw new Error("write() 失败 (" + written + ")");
      if (written === 0) throw new Error("write() 返回 0，连接被对端关闭");
      sent += written;
      log("  已发送 " + sent + " / " + size + " 字节");
    }
  } finally {
    await chain.syscall(SYS_CLOSE, fd);
  }
}

export async function sendPayload(file) {
  if (!runtime) throw new Error("漏洞利用尚未完成");
  if (running) {
    log("已有 payload 正在发送，请稍候", "error");
    return false;
  }

  const entry = findPayload(file);
  running = true;
  setStatus(file, "sending", "发送中…");
  log("发送 " + entry.title + " → 127.0.0.1:" + ELFLDR_PORT, "info");

  try {
    const { ptr, size } = await loadIntoMemory(file);
    await sendToElfldr(ptr, size);
    setStatus(file, "done", "已发送");
    log(entry.title + " 发送完成（" + size + " 字节）", "success");
    return true;
  } catch (error) {
    setStatus(file, "failed", "失败");
    log(entry.title + " 发送失败: " + (error instanceof Error ? error.message : error), "error");
    return false;
  } finally {
    running = false;
  }
}

export async function runAutoChain() {
  if (!runtime || running) return;
  const button = document.getElementById("btn-autochain");
  if (button) button.disabled = true;

  log("开始一键加载: " + AUTO_CHAIN.join(" → "), "info");
  for (let i = 0; i < AUTO_CHAIN.length; i++) {
    await sendPayload(AUTO_CHAIN[i]);
    if (i < AUTO_CHAIN.length - 1) {
      log("等待 " + AUTO_STEP_DELAY_MS / 1000 + " 秒后发送下一个…");
      await sleep(AUTO_STEP_DELAY_MS);
    }
  }
  log("一键加载流程结束，查看主机屏幕上的通知确认", "success");
  if (button) button.disabled = false;
}

export function initializePayloadSender(p, chain) {
  runtime = { p, chain };

  const panel = document.getElementById("payload-panel");
  if (panel) panel.classList.remove("hidden");

  for (const entry of PAYLOADS) {
    const button = document.getElementById("send-" + entry.id);
    if (button)
      button.addEventListener("click", () => {
        sendPayload(entry.file);
      });
  }

  const auto = document.getElementById("btn-autochain");
  if (auto)
    auto.addEventListener("click", () => {
      runAutoChain();
    });

  const checkbox = document.getElementById("autochain-opt");
  if (checkbox && checkbox.checked) runAutoChain();
}
