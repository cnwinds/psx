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

async function run() {
  // 打开页时不做主机侧端口探测（经公网访问会误用公网 IP）。
  // 存活检测改在破解/加载完成后，由 payload_loader 在 PS5 本机 connect 127.0.0.1。
  const btn = document.getElementById("btn-jailbreak");
  if (btn) btn.onclick = () => startJailbreak();
  const re = document.getElementById("btn-reexploit");
  if (re) re.onclick = () => startJailbreak();

  document.getElementById("jb-banner")?.classList.add("hidden");
  showStartPanel(true);
  setStartBusy(false);
  writeLog("点击「一键破解」开始（不会自动探测端口；加载完成后会检查 127.0.0.1）。", "info");
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