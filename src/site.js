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

async function run() {
  // 先问主机端：本机（PS5）的 elfldr(9021) 是否仍在线——在线则内核破解仍有效
  let state = null;
  try {
    state = await (await fetch("/api/jbstate", { cache: "no-store" })).json();
  } catch (error) {
    writeLog(`破解状态检测失败（${error}），按未破解处理`, "info");
  }
  if (state && state.jailbroken) {
    const open = Object.entries(state.ports).filter(([, v]) => v).map(([p]) => p);
    const elfldrAlive = !!state.ports["9021"];
    document.getElementById("jb-ports").textContent = open.join(" / ");
    document.getElementById("jb-banner").classList.remove("hidden");
    document.getElementById("btn-reexploit").onclick = () => {
      document.getElementById("jb-banner").classList.add("hidden");
      writeLog("手动触发：重新走完整破解流程");
      runExploit().catch(fail);
    };
    if (elfldrAlive) {
      writeLog(`检测到 elfldr(9021) 仍在监听（端口 ${open.join("、")}），跳过漏洞利用。` +
        "注意：页面内直发 payload 需要漏洞原语，已破解续传时请从电脑发送：nc <PS5的IP> 9021 < payloads/xxx.elf", "success");
    } else {
      writeLog(`检测到独立 FTP(2121) 在线但 elfldr(9021) 已不在监听。` +
        "传文件可继续用 /ftp.html；要再发 payload 须点「重新走完整破解流程」。", "success");
    }
    return;
  }
  writeLog("elfldr 未在监听（9021/2121 均无响应），开始漏洞利用");
  await runExploit();
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