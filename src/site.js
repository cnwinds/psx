import { establishPrimitive } from "./webkit.js";
import { installWindowP } from "./utils/mem.js";

const output = document.getElementById("console");

function writeLog(message, type = "log", replace = false) {
  let line = replace ? output.lastElementChild : null;
  if (!line) {
    line = document.createElement("div");
    output.appendChild(line);
  }
  let marker = "*";
  if (type === "error") marker = "-";
  if (type === "info" || type === "success") marker = "+";
  line.textContent = `[${marker}] ${message}`;
  output.scrollTop = output.scrollHeight;
}

function writeEvent(name, detail, type) {
  writeLog(detail == null || detail === "" ? name : `${name}: ${detail}`,
    type || (name === "Failed" ? "error" : "log"));
}

window.writeLog = writeLog;
window.jb = { mark: writeEvent };

async function getPrimitive() {
  writeLog("Starting WebKit exploit");
  const primitive = installWindowP(await establishPrimitive(writeEvent));
  if (!primitive || typeof primitive.read8 !== "function")
    throw new Error("Memory primitive unavailable");

  writeLog("ARW ready", "success");
  return primitive;
}

function getWebKitBase() {
  const ctor = globalThis.__ps5NativeCtor;
  if (typeof ctor !== "number" || typeof OFFSET_wk_host_constructor_candidates === "undefined")
    throw new Error("WebKit base inputs are unavailable");

  for (const offset of OFFSET_wk_host_constructor_candidates) {
    const base = ctor - offset;
    if (base >= 0x800000000 && base < 0x900000000 && base % 0x4000 === 0)
      return base;
  }

  throw new Error("WebKit base not found");
}

let exploitRunning = false;

function showStartPanel(visible) {
  const panel = document.getElementById("jb-start");
  if (panel) panel.classList.toggle("hidden", !visible);
}

function setStartBusy(busy) {
  const btn = document.getElementById("btn-jailbreak");
  if (!btn) return;
  btn.disabled = !!busy;
  btn.textContent = busy ? "破解进行中…" : "一键破解";
}

async function startJailbreak() {
  if (exploitRunning) return;
  exploitRunning = true;
  showStartPanel(false);
  document.getElementById("jb-banner")?.classList.add("hidden");
  setStartBusy(true);
  try {
    await runExploit();
  } catch (error) {
    fail(error);
    showStartPanel(true);
    setStartBusy(false);
  } finally {
    exploitRunning = false;
  }
}

const LOCAL_SERVICES = [
  { port: 9021, name: "elfldr" },
  { port: 2121, name: "ftpsrv" },
  { port: 8734, name: "panplay" },
];

// 在 PS5 浏览器里探测本机端口：不经过主机，避免公网/局域网 IP 误判。
// 非 HTTP 服务连上后往往拖到超时 → AbortError 视为端口开放；立刻 Failed to fetch 视为关闭。
async function probeLocalPort(port, ms = 800) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    await fetch("http://127.0.0.1:" + port + "/", {
      mode: "no-cors",
      cache: "no-store",
      signal: ctrl.signal,
    });
    return true;
  } catch (error) {
    return !!(error && error.name === "AbortError");
  } finally {
    clearTimeout(timer);
  }
}

async function probeLocalServices() {
  writeLog("—— 服务存活检测（127.0.0.1）——", "info");
  const results = [];
  for (const svc of LOCAL_SERVICES) {
    const alive = await probeLocalPort(svc.port);
    results.push({ ...svc, alive });
    writeLog(
      (alive ? "✓ " : "✗ ") + "127.0.0.1:" + svc.port + "  " + svc.name + (alive ? "  存活" : "  未存活"),
      alive ? "success" : "error",
    );
  }

  const box = document.getElementById("jb-ports");
  if (box) {
    box.innerHTML =
      `<div style="color:#9ab;margin-bottom:4px">探测目标：127.0.0.1（PS5 本机）</div>` +
      results.map((svc) => {
        const color = svc.alive ? "#81c784" : "#e57373";
        const mark = svc.alive ? "存活" : "未存活";
        return `<div style="color:${color}">${svc.alive ? "✓" : "✗"} :${svc.port}  ${svc.name}  — ${mark}</div>`;
      }).join("");
  }

  const title = document.getElementById("jb-banner-title");
  const elfldrAlive = results.some((s) => s.port === 9021 && s.alive);
  const anyAlive = results.some((s) => s.alive);
  if (title) {
    title.textContent = anyAlive
      ? "本机服务存活检测（127.0.0.1）"
      : "本机服务存活检测 —— 全部未在线";
    title.style.color = anyAlive ? "#81c784" : "#e57373";
  }
  return { results, elfldrAlive, anyAlive };
}

async function run() {
  const btn = document.getElementById("btn-jailbreak");
  if (btn) btn.onclick = () => startJailbreak();
  const re = document.getElementById("btn-reexploit");
  if (re) re.onclick = () => startJailbreak();

  const rejection = window.firmware.rejection();
  if (rejection) {
    // 非 PS5 / 不支持固件：不做本机探测
    document.getElementById("jb-banner")?.classList.add("hidden");
    showStartPanel(true);
    setStartBusy(false);
    writeLog(rejection + " —— 跳过本机端口探测。", "info");
    return;
  }

  writeLog(`PS5 浏览器 FW ${window.fw_str}，开始本机 127.0.0.1 端口探测…`, "info");
  const { elfldrAlive, anyAlive } = await probeLocalServices();

  if (anyAlive) {
    document.getElementById("jb-banner")?.classList.remove("hidden");
  } else {
    document.getElementById("jb-banner")?.classList.add("hidden");
  }

  if (elfldrAlive) {
    showStartPanel(false);
    writeLog(
      "elfldr(9021) 存活，内核破解可能仍有效。页面内直发仍需漏洞原语：点「重新走完整破解流程」或用电脑 nc。",
      "success",
    );
  } else {
    showStartPanel(true);
    setStartBusy(false);
    writeLog("elfldr(9021) 未存活。点击「一键破解」开始（不会自动开始）。", "info");
  }
}

function fail(error) {
  writeLog(error instanceof Error ? error.message : String(error), "error");
}

async function runExploit() {
  const rejection = window.firmware.rejection();
  if (rejection)
    throw new Error(rejection);
  writeLog("Credits: Sonic_Iso, Jordy, ntfargo, ufm42, Dr. Yenyen, TheFlow, SlidyBat, Flatz, cow, nhk, bollarz, Sleirsgoevy, EchoStretch, EarthOnion", "info");
  writeLog(`Agent: ${navigator.userAgent}`, "info");
  writeLog(`Firmware: ${window.fw_str}`, "info");
  const primitive = await getPrimitive();
  writeLog(`WebKit base: 0x${getWebKitBase().toString(16)}`, "info");

  await import("./relapse_exploit.js");
  const runtime = await main(primitive);
  if (runtime && runtime.payloadsLoaded) {
    const { initializePayloadSender } = await import("./payload_loader.js");
    initializePayloadSender(runtime.p, runtime.chain);
  }
}

run().catch(fail);