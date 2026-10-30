// 页面内直发 payload：漏洞链跑通后 elfldr 监听 127.0.0.1:9021，
// 通过 ROP 驱动的 TCP 连接把 ELF 逐个推过去。发送哪些、按什么顺序，
// 全部由 elfplan（幕二的勾选与排序）决定。

import { loadPlan, itemById, itemByFile, probePortInfo } from "./elfplan.js";

const AF_INET = 2;
const SOCK_STREAM = 1;
const ELFLDR_PORT = 9021;
const AUTO_STEP_DELAY_MS = 4000;

let runtime = null;
let running = false;
let chainRunning = false;

function log(message, type = "log") {
  if (typeof window.writeLog !== "function") return;
  const cls = type === "error" ? "e" : type === "success" ? "g" : type;
  window.writeLog(message, cls);
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

export async function sendPayload(file, fromChain = false) {
  if (!runtime) throw new Error("漏洞利用尚未完成");
  if (chainRunning && !fromChain) {
    log("自动加载正在运行，请等待结束后再手动发送", "info");
    return false;
  }
  if (running) {
    log("已有 payload 正在发送，请稍候", "error");
    return false;
  }

  const item = itemByFile(file);
  const title = item ? item.name : file;
  running = true;
  setRow(file, "sending");
  log("发送 " + title + " → 127.0.0.1:" + ELFLDR_PORT, "info");

  try {
    const { ptr, size } = await loadIntoMemory(file);
    await sendToElfldr(ptr, size);
    setRow(file, "done", size);
    log(title + " 发送完成（" + size + " 字节）", "success");
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
      log("没有勾选任何 ELF，先在幕二勾选", "error");
      return;
    }

    // 先探测一轮端口，跳过已加载的 ELF（websrv 监听 8080 即视为已加载；
    // kstuff / ShadowMountPlus 无端口可探，照常发送）
    let loaded = {};
    try {
      const state = await (await fetch("/api/jbstate", { cache: "no-store" })).json();
      if (state && state.ports)
        loaded = {
          ftpsrv: !!state.ports["2121"],
          panplay: !!state.ports["8734"],
          websrv: !!state.ports["8080"],
        };
    } catch (error) { /* 探测失败就全部照发 */ }
    const chain = wanted.filter((it) => !loaded[it.id]);
    const skipped = wanted.filter((it) => loaded[it.id]);
    for (const it of skipped) {
      if (window.setElfRowState) window.setElfRowState(it.id, "loaded");
      log(it.name + " 已在本机运行（端口监听中），跳过不重发", "info");
    }
    if (!chain.length) {
      log("勾选的 ELF 都已加载过，本次无需发送", "success");
      const finalState = await verifyPorts();
      if (typeof window.onFlowComplete === "function") window.onFlowComplete(finalState);
      return;
    }

    log("按顺序加载: " + chain.map((it) => it.file).join(" → "), "info");
    for (let i = 0; i < chain.length; i++) {
      if (!await sendPayload(chain[i].file, true)) {
        log(chain[i].name + " 加载失败，已停止后续 ELF；检查后重试", "error");
        return;                 // 后续项可能依赖当前 ELF，不能继续发
      }
      if (i < chain.length - 1) {
        log("等待 " + AUTO_STEP_DELAY_MS / 1000 + " 秒后发送下一个…");
        await sleep(AUTO_STEP_DELAY_MS);
      }
    }
    log("顺序加载结束，向主机确认端口状态…");
    const finalState = await verifyPorts();
    if (typeof window.onFlowComplete === "function") window.onFlowComplete(finalState);
  } finally {
    chainRunning = false;
    if (button) button.disabled = false;
  }
}

async function verifyPorts() {
  const PORT_INFO = probePortInfo();
  const probe = async () => {
    try {
      return await (await fetch("/api/jbstate", { cache: "no-store" })).json();
    } catch (error) {
      return null;
    }
  };

  let state = await probe();
  // websrv 刚发的话监听可能晚几秒：elfldr 还在但 8080 未起就等 3 秒复查
  if (!state || !state.ports || !state.ports["9021"]) {
    log("等待 3 秒后复查端口…");
    await sleep(3000);
    state = await probe();
  }
  if (!state || !state.ports) {
    log("无法向主机确认状态（探测接口无响应），请手动验证端口", "error");
    return null;
  }

  log("—— 端口验证（" + state.ip + "）——", "info");
  if (window.applyElfState) window.applyElfState(state.ports, state);   // 行胶囊同步「已加载」并更新二维码
  for (const portKey of Object.keys(PORT_INFO)) {
    const info = PORT_INFO[portKey];
    const up = !!state.ports[portKey];
    log((up ? "✓ " : "✗ ") + portKey + "  " + info.name + (up ? "  在监听" : "  未监听（" + info.hint + "）"),
      up ? "success" : "error");
  }
  if (state.ports["8080"]) {
    log("结论：websrv 可用 —— 手机或电脑浏览器打开 http://" + state.ip + ":8080 追发 payload", "success");
  } else if (state.ports["9021"]) {
    log("结论：elfldr 在线但 websrv 未监听 —— 要网页追发就勾选 websrv 再发一次", "success");
  } else {
    log("结论：elfldr 已不在监听 —— 需重启后重跑破解流程", "error");
  }
  return state;
}

export function initializePayloadSender(p, chain) {
  runtime = { p, chain };

  document.querySelectorAll("#elf-rows [data-file]").forEach((button) => {
    button.addEventListener("click", () => {
      sendPayload(button.dataset.file);
    });
  });

  const run = document.getElementById("btn-runplan");
  if (run)
    run.addEventListener("click", () => {
      runAutoChain();
    });

  const autorun = document.getElementById("autorun-opt");
  if (autorun && autorun.checked) runAutoChain();
}
