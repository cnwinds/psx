// 首页编排：
// 1. PS5 且固件可用时显示「开始提权」。点击后的链路与 Relapse 的 run() 相同。
// 2. elfldr 就绪后显示「一键加载」，点击再按幕二勾选顺序加载 ELF。

import { loadPlan, savePlan, resetPlan, itemById, formatSize } from "./elfplan.js";
import { establishPrimitive } from "./webkit.js";
import { installWindowP } from "./utils/mem.js";

const $ = (id) => document.getElementById(id);

let plan = loadPlan();
let rowState = {};          // id -> "wait" | "sending" | "loaded" | "skip" | "fail"
let flowCollapsed = false;
let exploitHeadline = "WebKit → 内核 → :9021";
/** 幕二是否已解锁（提权成功）。 */
let payloadPanelReady = false;

function setPayloadPanelReady(ready) {
  payloadPanelReady = !!ready;
  const runBtn = $("btn-runplan");
  if (runBtn) {
    runBtn.hidden = !payloadPanelReady;
    runBtn.disabled = !payloadPanelReady;
  }
  const resetBtn = $("btn-resetplan");
  if (resetBtn) resetBtn.disabled = false;
  if ($("plan-mode")) {
    if (payloadPanelReady) {
      $("plan-mode").textContent = exploitRuntime ? "可加载 · 127.0.0.1:9021" : "可加载";
      if ($("plan-mode").classList) $("plan-mode").classList.add("ready");
    } else {
      $("plan-mode").textContent = "等待提权完成";
      if ($("plan-mode").classList) $("plan-mode").classList.remove("ready");
    }
  }
  renderPlan();
}

const STATE_TEXT = {
  wait: "待加载",
  sending: "发送中…",
  done: "已发送",
  loaded: "已在运行",
  skip: "跳过",
  fail: "失败",
  failed: "失败",
};

// ── 全局日志钩子，格式与 ntfargo/Relapse-Exploit src/site.js 一致 ──
let exploitRuntime = null;
let exploitBusy = false;

function writeLog(message, type = "log", replace = false) {
  const box = $("console");
  if (!box || typeof box.appendChild !== "function") return;
  let line = replace ? box.lastElementChild : null;
  if (!line) {
    line = document.createElement("div");
    box.appendChild(line);
  }
  let marker = "*";
  if (type === "error" || type === "e") marker = "-";
  if (type === "info" || type === "success" || type === "g") marker = "+";
  if (type === "error" || type === "e") {
    line.className = "e";
    const logDet = $("exploit-log");
    if (logDet) logDet.open = true;
  } else if (type === "success" || type === "g") {
    line.className = "g";
  } else if (line.className) {
    line.className = "";
  }
  line.textContent = `[${marker}] ${message}`;
  while (box.childElementCount > 400) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}

function writeEvent(name, detail, type) {
  writeLog(detail == null || detail === "" ? name : `${name}: ${detail}`,
    type || (name === "Failed" ? "error" : "log"));
}

if (typeof window !== "undefined") {
  window.writeLog = writeLog;
  window.jb = { mark: writeEvent };
}

// 折叠/展开单个幕模块
function setActFolded(actId, bodyId, btnId, folded) {
  const act = $(actId);
  const body = $(bodyId);
  const btn = $(btnId);
  if (body) body.hidden = !!folded;
  if (act && act.classList) act.classList.toggle("is-folded", !!folded);
  if (btn) {
    btn.textContent = folded ? "展开 ▾" : "收起 ▴";
    if (btn.setAttribute) btn.setAttribute("aria-expanded", folded ? "false" : "true");
  }
}

// 全部流程完成后收起 01 破解过程与 02 加载列表
function setFlowCollapsed(collapsed, reasonTitle, reasonDesc) {
  flowCollapsed = !!collapsed;
  if (typeof document !== "undefined" && document.body && document.body.classList) {
    document.body.classList.toggle("flow-done", flowCollapsed);
  }

  const banner = $("flow-complete-banner");
  if (banner) banner.hidden = false; // 一旦触发完成态，横幅始终保留以便随时切换

  if (reasonTitle && $("flow-banner-title")) {
    $("flow-banner-title").textContent = reasonTitle;
  }
  if (reasonDesc != null && $("flow-banner-desc")) {
    $("flow-banner-desc").textContent = reasonDesc;
  }

  setActFolded("act-exploit", "body-exploit", "btn-fold-exploit", flowCollapsed);
  setActFolded("act-payloads", "body-payloads", "btn-fold-payloads", flowCollapsed);

  const toggleBtn = $("btn-toggle-fold");
  if (toggleBtn) {
    toggleBtn.textContent = flowCollapsed ? "展开详情 ▾" : "收起详情 ▴";
  }

  // 更新折叠摘要提示
  const expSummary = $("exploit-fold-summary");
  if (expSummary) {
    expSummary.textContent = flowCollapsed
      ? exploitHeadline
      : "WebKit → 内核 → :9021";
  }
  const paySummary = $("payloads-fold-summary");
  if (paySummary) {
    const loadedNames = plan.order
      .filter((id) => rowState[id] === "loaded")
      .map((id) => {
        const it = itemById(id);
        return it ? it.name : id;
      });
    paySummary.textContent = flowCollapsed && loadedNames.length
      ? "已就绪：" + loadedNames.join(" / ")
      : "按勾选顺序加载";
  }
}

// 渲染幕二列表。每次顺序/勾选变化都整表重绘（只有 4 项，开销可忽略）。
function renderPlan() {
  const list = $("elf-rows");
  if (!list) return;
  list.innerHTML = "";
  const order = plan.order;
  order.forEach((id, idx) => {
    const it = itemById(id);
    if (!it) return;
    const on = !plan.off.has(id);
    const st = rowState[id] || (on ? "wait" : "skip");
    const canSend = payloadPanelReady;
    const li = document.createElement("li");
    li.className = "elf-row" + (on ? "" : " is-off");
    li.dataset.id = id;
    li.innerHTML =
      `<span class="ord">0${idx + 1}</span>` +
      `<input type="checkbox" class="chk" data-act="toggle" ${on ? "checked" : ""} aria-label="勾选 ${it.name}">` +
      `<div class="meta">` +
        `<div class="line1">` +
          `<b>${it.name}</b>` +
          (it.role ? `<span class="role-tag">${it.role}</span>` : "") +
          `<span class="desc-inline">${it.desc}</span>` +
        `</div>` +
      `</div>` +
      `<div class="ord-btns">` +
        `<button type="button" data-act="up" ${idx === 0 ? "disabled" : ""} title="上移" aria-label="上移 ${it.name}">↑</button>` +
        `<button type="button" data-act="down" ${idx === order.length - 1 ? "disabled" : ""} title="下移" aria-label="下移 ${it.name}">↓</button>` +
      `</div>` +
      `<span class="pill" data-st="${st}">${STATE_TEXT[st]}</span>` +
      `<button type="button" class="send-one ghost mini" data-act="send" data-file="${it.file}" ${canSend ? "" : "disabled"}>发送</button>`;
    list.appendChild(li);
  });
}

function wirePlanEvents() {
  const rows = $("elf-rows");
  if (rows) {
    rows.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-act]");
      if (!btn) return;
      const row = btn.closest(".elf-row");
      if (!row) return;
      const id = row.dataset.id;
      const act = btn.dataset.act;
      if (act === "send") return;
      const idx = plan.order.indexOf(id);
      if (act === "toggle") {
        if (btn.checked) plan.off.delete(id); else plan.off.add(id);
        savePlan(plan);
        renderPlan();
      } else if (act === "up" && idx > 0) {
        plan.order.splice(idx, 1);
        plan.order.splice(idx - 1, 0, id);
        savePlan(plan);
        renderPlan();
      } else if (act === "down" && idx >= 0 && idx < plan.order.length - 1) {
        plan.order.splice(idx, 1);
        plan.order.splice(idx + 1, 0, id);
        savePlan(plan);
        renderPlan();
      }
    });
  }

  const resetBtn = $("btn-resetplan");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      plan = resetPlan();
      renderPlan();
    });
  }

  const toggleFoldBtn = $("btn-toggle-fold");
  if (toggleFoldBtn) {
    toggleFoldBtn.addEventListener("click", () => {
      setFlowCollapsed(!flowCollapsed);
    });
  }

  const foldExploitBtn = $("btn-fold-exploit");
  if (foldExploitBtn) {
    foldExploitBtn.addEventListener("click", () => {
      const body = $("body-exploit");
      setActFolded("act-exploit", "body-exploit", "btn-fold-exploit", body ? !body.hidden : true);
    });
  }

  const foldPayloadsBtn = $("btn-fold-payloads");
  if (foldPayloadsBtn) {
    foldPayloadsBtn.addEventListener("click", () => {
      const body = $("body-payloads");
      setActFolded("act-payloads", "body-payloads", "btn-fold-payloads", body ? !body.hidden : true);
    });
  }

}

function setRowState(id, st, bytes) {
  rowState[id] = st;
  const pill = document.querySelector(`#elf-rows .elf-row[data-id="${id}"] .pill`);
  if (pill) {
    pill.dataset.st = st;
    pill.textContent = (STATE_TEXT[st] || st) + (bytes ? ` (${formatSize(bytes)})` : "");
  }
}

// 供 payload_loader.js 调用：读取当前勾选且保序的条目列表
window.getElfPlan = function () {
  return plan.order.filter((id) => !plan.off.has(id)).map(itemById).filter(Boolean);
};
window.setElfRowState = setRowState;

window.onFlowComplete = function () {
  exploitHeadline = "全部就绪";
  setStatus(
    "ok",
    "提权与组件加载已完成",
    "幕二勾选的 ELF 已交给 elfldr。"
  );
  setFlowCollapsed(true, "组件加载已完成", "");
};

// ── 幕一状态卡切换 ──
function setStatus(state, titleText, bodyText, actionsHtml) {
  const card = $("exploit-status");
  if (card && card.dataset) card.dataset.state = state;
  const badgeMap = {
    checking: "检测中",
    ok: "已就绪",
    ready: "待提权",
    running: "自动执行中",
    pc: "预览模式",
    fail: "异常",
  };
  if ($("status-badge")) $("status-badge").textContent = badgeMap[state] || state;
  if ($("status-title")) $("status-title").textContent = titleText;
  if ($("status-body")) $("status-body").innerHTML = bodyText;
  const act = $("status-actions");
  if (act) {
    if (actionsHtml) {
      act.innerHTML = actionsHtml;
      act.hidden = false;
    } else {
      act.innerHTML = "";
      act.hidden = true;
    }
  }
}

// ── 三阶段轨道状态与真实漏洞链编排 ──
function setStage(stage, state) {
  const el = $(`stage-${stage}`);
  if (el && el.dataset) el.dataset.st = state;
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

async function getPrimitive() {
  writeLog("Starting WebKit exploit");
  setStage("webkit", "run");
  const active = installWindowP(await establishPrimitive(writeEvent));
  if (!active || typeof active.read8 !== "function")
    throw new Error("Memory primitive unavailable");
  writeLog("ARW ready", "success");
  setStage("webkit", "ok");
  return active;
}

async function unlockSender() {
  setPayloadPanelReady(true);
  const payloads = $("act-payloads");
  if (payloads && typeof payloads.scrollIntoView === "function") {
    try { payloads.scrollIntoView({ behavior: "smooth", block: "start" }); } catch (error) {}
  }
  setActFolded("act-payloads", "body-payloads", "btn-fold-payloads", false);
  const { initializePayloadSender } = await import("./payload_loader.js");
  initializePayloadSender(exploitRuntime.p, exploitRuntime.chain);
}

async function runExploit() {
  if (exploitBusy) return;
  exploitBusy = true;
  if ($("rail")) $("rail").hidden = false;
  ["webkit", "kernel", "elfldr"].forEach((s) => setStage(s, "idle"));

  try {
    // 以下到 await main() 为止，与上游 src/site.js run() 相同。
    const rejection = window.firmware.rejection();
    if (rejection)
      throw new Error(rejection);
    writeLog("Credits: Sonic_Iso, Jordy, ntfargo, ufm42, Dr. Yenyen, TheFlow, SlidyBat, Flatz, cow, nhk, bollarz, Sleirsgoevy, EchoStretch, EarthOnion", "info");
    writeLog(`Agent: ${navigator.userAgent}`, "info");
    writeLog(`Firmware: ${window.fw_str}`, "info");
    const activePrimitive = await getPrimitive();
    writeLog(`WebKit base: 0x${getWebKitBase().toString(16)}`, "info");

    setStage("kernel", "run");
    await import("./relapse_exploit.js");
    const runtime = await main(activePrimitive);

    // 上游 main() 结束。只有 elfldr 已监听时，才做本站的 ELF 加载。
    exploitRuntime = runtime;
    setStage("kernel", "ok");
    if (!runtime || !runtime.payloadsLoaded) {
      setStage("elfldr", "fail");
      exploitHeadline = "内核已完成";
      setStatus("fail", "elfldr 未监听", "错误：:9021 没有起来。");
      return;
    }
    setStage("elfldr", "ok");
    exploitHeadline = "已破解";
    setStatus("ok", "提权完成", "elfldr 已就绪。");
    await unlockSender();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    writeLog(message, "error");
    ["webkit", "kernel", "elfldr"].forEach((s) => {
      const el = $(`stage-${s}`);
      if (el && el.dataset && el.dataset.st === "run") el.dataset.st = "fail";
    });
    exploitHeadline = "失败";
    setStatus("fail", "提权未完成", `错误：${message}。`);
  } finally {
    exploitBusy = false;
  }
}

function enterReady() {
  setFlowCollapsed(false);
  const banner = $("flow-complete-banner");
  if (banner) banner.hidden = true;
  setPayloadPanelReady(false);
  if ($("exploit-log")) $("exploit-log").open = true;
  if ($("plan-mode")) $("plan-mode").textContent = "等待提权完成";

  let rejection;
  try {
    rejection = window.firmware.rejection();
  } catch (error) {
    rejection = error instanceof Error ? error.message : String(error);
  }
  if (rejection) {
    exploitHeadline = "失败";
    setStatus("fail", "提权未完成", `错误：${rejection}。`);
    return;
  }

  exploitHeadline = "可以提权";
  setStatus(
    "ready",
    "可以提权",
    "",
    `<button type="button" id="jb-start" class="primary">开始提权</button>`
  );
  const start = $("jb-start");
  if (start) {
    start.onclick = () => {
      start.disabled = true;
      exploitHeadline = "执行中…";
      setStatus("running", "正在提权", "");
      runExploit();
    };
  }
}

function startMatrixRain() {
  try {
    if (typeof document === "undefined" || typeof document.querySelector !== "function") return;
    const canvas = document.querySelector(".matrix-rain");
    if (!canvas || typeof canvas.getContext !== "function") return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const glyphs = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789ABCDEF<>[]{}:=+-*/$#";
    const fontSize = 15;
    let cols = 0;
    let drops = [];

    const resize = () => {
      canvas.width = (typeof window !== "undefined" && window.innerWidth) || 1280;
      canvas.height = (typeof window !== "undefined" && window.innerHeight) || 800;
      cols = Math.max(1, Math.floor(canvas.width / fontSize));
      drops = Array.from({ length: cols }, () => Math.random() * -50);
    };
    resize();
    if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
      window.addEventListener("resize", resize);
    }

    const drawFrame = () => {
      ctx.fillStyle = "rgba(2, 5, 3, 0.08)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = fontSize + "px monospace";
      for (let i = 0; i < cols; i++) {
        const ch = glyphs.charAt(Math.floor(Math.random() * glyphs.length));
        const x = i * fontSize;
        const y = drops[i] * fontSize;
        ctx.fillStyle = Math.random() > 0.86 ? "#d8ffe4" : "#00ff41";
        ctx.fillText(ch, x, y);
        if (y > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i] += 0.65;
      }
    };

    const reduced = typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      for (let k = 0; k < 25; k++) drawFrame();
      return;
    }
    setInterval(drawFrame, 45);
  } catch (error) {}
}

function boot() {
  startMatrixRain();
  setPayloadPanelReady(false);
  renderPlan();
  wirePlanEvents();

  enterReady();
}

boot().catch((e) => {
  setStatus("fail", "前端脚本加载出错", `错误：${(e && e.message) || e}。`);
});
