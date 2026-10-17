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

function showUnsupported(message) {
  const box = document.getElementById("jb-unsupported");
  const text = document.getElementById("jb-unsupported-text");
  if (text) text.textContent = message;
  if (box) box.classList.remove("hidden");
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
  const btn = document.getElementById("btn-jailbreak");
  if (btn) btn.onclick = () => startJailbreak();

  const rejection = window.firmware.rejection();
  if (rejection) {
    showStartPanel(false);
    showUnsupported(rejection);
    writeLog(rejection, "error");
    writeLog("当前环境无法使用本页破解。请使用固件 7.00–13.60 的 PS5 浏览器打开。", "info");
    return;
  }

  showStartPanel(true);
  setStartBusy(false);
  writeLog(`PS5 浏览器 FW ${window.fw_str}，支持破解。点击「一键破解」开始（不会自动开始）。`, "info");
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
