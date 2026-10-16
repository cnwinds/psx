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
    file: "shadowmountplus.elf",
    id: "smp",
    title: "ShadowMountPlus 1.7beta4",
    desc: "游戏镜像自动挂载（需要 kstuff 运行中）",
    source: "https://github.com/drakmor/ShadowMountPlus",
  },
  {
    file: "zftpd.elf",
    id: "zftpd",
    title: "zftpd（2120 / 8888）",
    desc: "FTP(:2120) + ZHTTP 网页管理(:8888)，随一键加载自动发送；之后打开 ftp.html（端口 2120）或直连 PS5:8888 即可管理文件。",
    source: "https://github.com/seregonwar/zftpd",
  },
  {
    file: "websrv.elf",
    id: "websrv",
    title: "websrv（8080）",
    desc: "Homebrew 网页启动器，监听 8080；加载后用电脑/手机浏览器打开 http://<PS5 IP>:8080 浏览并启动 homebrew。",
    source: "https://github.com/ps5-payload-dev/websrv",
  },
];

// kstuff patches the kernel first, ShadowMountPlus then mounts game images
// (its kstuff auto-pause logic expects kstuff to be alive); zftpd brings up
// FTP/ZHTTP, websrv the homebrew launcher.
const AUTO_CHAIN = ["kstuff.elf", "shadowmountplus.elf", "zftpd.elf", "websrv.elf"];
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
        "connect() 127.0.0.1:" + ELFLDR_PORT + " 失败（已重试 " + CONNECT_ATTEMPTS + " 次），elfldr 是否在监听？"
      );
    log("  connect 未就绪，" + (attempt * 1.2).toFixed(1) + " 秒后重试（" + attempt + "/" + CONNECT_ATTEMPTS + "）…");
    await sleep(1200 * attempt);
  }
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

  const fd = await connectElfldr(addr);

  try {
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
  log("一键加载流程结束，向主机确认端口状态…");
  if (button) button.disabled = false;
  await verifyPorts();
}

// 让主机端探测发起请求的设备（就是本机 PS5）的端口，逐个报告监听状态。
const PORT_INFO = {
  9021: { name: "elfldr（payload 加载器）", hint: "已退出，需重跑一遍破解流程" },
  2120: { name: "FTP（zftpd）", hint: "传文件前先发送「zftpd」卡片" },
  8888: { name: "ZHTTP（zftpd）", hint: "网页文件管理，直连 PS5:8888" },
  8080: { name: "websrv（homebrew）", hint: "先发送「websrv」卡片" },
};

async function verifyPorts() {
  const probe = async () => {
    try {
      return await (await fetch("/api/jbstate", { cache: "no-store" })).json();
    } catch (error) {
      return null;
    }
  };

  let state = await probe();
  // zftpd / websrv 刚发的话监听可能晚几秒：没探齐就等 3 秒复查一次再下结论
  if (!state || !state.ports["9021"] || !state.ports["2120"]) {
    log("等待 3 秒后复查端口…");
    await sleep(3000);
    state = await probe();
  }
  if (!state) {
    log("无法向主机确认状态（探测接口无响应），请在 ftp.html 里手动连接验证", "error");
    return;
  }

  log("—— 端口验证（" + state.ip + "）——", "info");
  for (const [port, info] of Object.entries(PORT_INFO)) {
    const up = !!state.ports[port];
    log((up ? "✓ " : "✗ ") + port + "  " + info.name + (up ? "  在监听" : "  未监听（" + info.hint + "）"),
      up ? "success" : "error");
  }
  if (state.ports["2120"] || state.ports["8888"]) {
    log("结论：zftpd 可用 —— /ftp.html（端口 2120）或直连 PS5:8888 传文件", "success");
  } else if (state.ports["9021"]) {
    log("结论：kstuff / ShadowMountPlus 已加载 —— 要传文件点「zftpd」卡片发送", "success");
  } else {
    log("结论：elfldr 已不在监听 —— payload 需要重跑一遍破解流程再发", "error");
  }
  if (state.ports["8080"])
    log("websrv 可用 —— 浏览器打开 http://" + state.ip + ":8080 启动 homebrew", "success");
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
