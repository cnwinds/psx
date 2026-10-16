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

// 打开页时的端口探测说明：
// 浏览器 fetch("http://127.0.0.1:2121") 不能可靠探测 FTP/elfldr——它们不是 HTTP，
// TCP 连上后 HTTP 立即失败，会被误判成「未存活」。电脑能连 2121 与此不矛盾。
// 正确做法：由主机对「打开本页的 PS5」做真实 TCP 探测（请求方局域网 IP，与电脑连 FTP 同一路径）。
// 公网来源会拒绝探测。加载完成后仍用 ROP connect 127.0.0.1（有原语后才准）。

async function probeVisitorServices() {
  let state;
  try {
    state = await (await fetch("/api/jbstate", { cache: "no-store" })).json();
  } catch (error) {
    writeLog(`端口探测失败（${error}）`, "error");
    return { elfldrAlive: false, anyAlive: false };
  }

  if (state.warning) {
    writeLog(state.warning, "error");
    writeLog("请用局域网地址打开本页（如 http://192.168.x.x/），勿用公网 IP/端口转发。", "info");
  }

  const target = state.ip || "（无效）";
  writeLog(`—— 服务存活检测（访问方 PS5 ${target}）——`, "info");

  const services = Array.isArray(state.services) ? state.services : [];
  for (const svc of services) {
    writeLog(
      (svc.alive ? "✓ " : "✗ ") + target + ":" + svc.port + "  " + svc.name + (svc.alive ? "  存活" : "  未存活"),
      svc.alive ? "success" : "error",
    );
  }

  const box = document.getElementById("jb-ports");
  if (box) {
    box.innerHTML =
      `<div style="color:#9ab;margin-bottom:4px">探测目标：${target}（打开本页的 PS5，主机 TCP 探测）</div>` +
      services.map((svc) => {
        const color = svc.alive ? "#81c784" : "#e57373";
        const mark = svc.alive ? "存活" : "未存活";
        return `<div style="color:${color}">${svc.alive ? "✓" : "✗"} :${svc.port}  ${svc.name}  — ${mark}</div>`;
      }).join("");
  }

  const elfldrAlive = !!(state.elfldr || (state.ports && state.ports["9021"]));
  const anyAlive = !!state.jailbroken;
  const title = document.getElementById("jb-banner-title");
  if (title) {
    title.textContent = anyAlive
      ? "服务存活检测（访问方 PS5）"
      : "服务存活检测 —— 全部未在线";
    title.style.color = anyAlive ? "#81c784" : "#e57373";
  }
  return { elfldrAlive, anyAlive, state };
}

async function run() {
  const btn = document.getElementById("btn-jailbreak");
  if (btn) btn.onclick = () => startJailbreak();
  const re = document.getElementById("btn-reexploit");
  if (re) re.onclick = () => startJailbreak();

  const rejection = window.firmware.rejection();
  if (rejection) {
    document.getElementById("jb-banner")?.classList.add("hidden");
    showStartPanel(true);
    setStartBusy(false);
    writeLog(rejection + " —— 跳过端口探测。", "info");
    return;
  }

  writeLog(`PS5 浏览器 FW ${window.fw_str}，探测打开本页的主机端口…`, "info");
  const { elfldrAlive, anyAlive } = await probeVisitorServices();

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