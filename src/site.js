// 首页编排：
// 1. 提权与 ntfargo/Relapse-Exploit 相同：PS5 打开页面即跑 WebKit → 内核 → elfldr。
// 2. elfldr 就绪后，再按幕二勾选顺序从本站加载 ELF。

import { loadPlan, savePlan, resetPlan, itemById, formatSize } from "./elfplan.js";

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
  if (runBtn) runBtn.disabled = !payloadPanelReady;
  const resetBtn = $("btn-resetplan");
  if (resetBtn) resetBtn.disabled = !payloadPanelReady;
  const autoOpt = $("autorun-opt");
  if (autoOpt) autoOpt.disabled = !payloadPanelReady;
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

// ── 全局日志钩子（webkit.js / relapse_exploit.js / main.js / payload_loader.js 均依赖） ──
let primitive = null;
let exploitRuntime = null;
let exploitBusy = false;

function writeLog(message, cls) {
  const box = $("console");
  if (!box || typeof box.appendChild !== "function") return;
  if (cls === "error") cls = "e";
  else if (cls === "success") cls = "g";
  if (cls === "e") {
    const logDet = $("exploit-log");
    if (logDet) logDet.open = true;
  }
  const line = document.createElement("div");
  if (cls) line.className = cls;
  const now = new Date();
  const ts = now.toTimeString().slice(0, 8) + "." + String(now.getMilliseconds()).padStart(3, "0");
  line.textContent = `[${ts}] ${message}`;
  box.appendChild(line);
  while (box.childElementCount > 400) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}

function writeEvent(name, detail, type) {
  const text = detail == null || detail === "" ? String(name) : `${name}: ${detail}`;
  writeLog(text, type || (name === "Failed" ? "error" : "log"));
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
  if (reasonDesc && $("flow-banner-desc")) {
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
    const locked = !payloadPanelReady;
    const li = document.createElement("li");
    li.className = "elf-row" + (on ? "" : " is-off");
    li.dataset.id = id;
    li.innerHTML =
      `<span class="ord">0${idx + 1}</span>` +
      `<input type="checkbox" class="chk" data-act="toggle" ${on ? "checked" : ""} ${locked ? "disabled" : ""} aria-label="勾选 ${it.name}">` +
      `<div class="meta">` +
        `<div class="line1">` +
          `<b>${it.name}</b>` +
          (it.role ? `<span class="role-tag">${it.role}</span>` : "") +
          `<span class="desc-inline">${it.desc}</span>` +
        `</div>` +
      `</div>` +
      `<div class="ord-btns">` +
        `<button type="button" data-act="up" ${idx === 0 || locked ? "disabled" : ""} title="上移" aria-label="上移 ${it.name}">↑</button>` +
        `<button type="button" data-act="down" ${idx === order.length - 1 || locked ? "disabled" : ""} title="下移" aria-label="下移 ${it.name}">↓</button>` +
      `</div>` +
      `<span class="pill" data-st="${st}">${STATE_TEXT[st]}</span>` +
      `<button type="button" class="send-one ghost mini" data-act="send" data-file="${it.file}" ${locked ? "disabled" : ""}>发送</button>`;
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
      if (!payloadPanelReady && act !== "send") return;
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
  setFlowCollapsed(
    true,
    "组件加载已完成",
    "可展开详情查看日志与加载列表。"
  );
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

// 探测 UA 是否为 PS5 并发回固件字符串（仅用于顶部展示；真实偏移判断在 firmware.js）
function parsePs5Ua() {
  const ua = navigator.userAgent || "";
  const m = ua.match(/PlayStation 5\/([0-9]+\.[0-9]+)/) || ua.match(/PlayStation; PlayStation 5\/([0-9]+\.[0-9]+)/);
  if (m) return { isPs5: true, fw: m[1] };
  if (/PlayStation 5/i.test(ua)) return { isPs5: true, fw: "未知版本" };
  return { isPs5: false, fw: null };
}

// ── 三阶段轨道状态与真实漏洞链编排 ──
function setStage(stage, state) {
  const el = $(`stage-${stage}`);
  if (el && el.dataset) el.dataset.st = state;
}

async function getPrimitive() {
  if (primitive) return primitive;
  const [{ establishPrimitive }, { installWindowP }] = await Promise.all([
    import("./webkit.js"),
    import("./utils/mem.js"),
  ]);
  primitive = installWindowP(await establishPrimitive(writeEvent));
  if (!primitive || typeof primitive.read8 !== "function")
    throw new Error("Memory primitive unavailable");
  return primitive;
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

function failExploit(error) {
  const msg = error && error.stack ? error.stack : String(error);
  writeLog(`[!] 失败：${msg}`, "e");
  ["webkit", "kernel", "elfldr"].forEach((s) => {
    const el = $(`stage-${s}`);
    if (el && el.dataset && el.dataset.st === "run") el.dataset.st = "fail";
  });
  exploitHeadline = "失败";
  setStatus(
    "fail",
    "提权未完成",
    `错误：<code>${String((error && error.message) || error)}</code>`,
    `<button type="button" id="jb-retry" class="primary">重试</button>`
  );
  const retry = $("jb-retry");
  if (retry) retry.onclick = () => runExploit();
}

async function runExploit() {
  if (exploitBusy) return;
  exploitBusy = true;

  if ($("rail")) $("rail").hidden = false;
  ["webkit", "kernel", "elfldr"].forEach((s) => setStage(s, "idle"));
  setStatus("running", "正在执行 Relapse 提权…", "与上游相同：WebKit → 内核 → elfldr。成功后自动加载幕二勾选的 ELF。");
  exploitHeadline = "执行中…";

  try {
    const rejection = window.firmware && typeof window.firmware.rejection === "function"
      ? window.firmware.rejection()
      : null;
    if (rejection) throw new Error(rejection);

    writeLog("Starting WebKit exploit");
    setStage("webkit", "run");
    const activePrimitive = await getPrimitive();
    writeLog("ARW ready", "success");

    setStage("webkit", "ok");
    setStage("kernel", "run");
    writeLog(`Agent: ${navigator.userAgent}`, "info");
    writeLog(`Firmware: ${window.fw_str || ""}`, "info");
    await import("./relapse_exploit.js");
    const runtime = await main(activePrimitive);
    if (!runtime || !runtime.p || !runtime.chain) {
      throw new Error("内核阶段未返回有效 ROP 通道");
    }
    exploitRuntime = runtime;
    setStage("kernel", "ok");

    const loaded = !!runtime.payloadsLoaded;
    setStage("elfldr", loaded ? "ok" : "fail");
    if (!loaded) {
      writeLog("elfldr 未就绪，组件不会加载", "error");
      setStatus("fail", "elfldr 未就绪", "内核阶段已结束，但 :9021 没有起来。请重启主机后再打开本页。");
      return;
    }

    exploitHeadline = "已破解";
    setStatus(
      "ok",
      "提权完成 · elfldr (:9021) 就绪",
      "正在按幕二顺序加载 ELF。"
    );
    await unlockSender();
  } catch (error) {
    failExploit(error);
  } finally {
    exploitBusy = false;
  }
}

function enterFWBad(reason) {
  exploitHeadline = "固件不支持";
  setFlowCollapsed(false);
  setStatus(
    "fail",
    "固件不受支持",
    `${reason}（支持 FW <b>7.00 – 13.60</b>）。`
  );
}

function enterReady(ua) {
  setFlowCollapsed(false);
  const banner = $("flow-complete-banner");
  if (banner) banner.hidden = true;

  if (!ua.isPs5) {
    exploitHeadline = "非 PS5 浏览器";
    setStatus(
      "pc",
      "请用 PS5 浏览器打开",
      "提权只能在 PS5「设置 → 用户指南」里完成。"
    );
    return;
  }

  // 检查固件版本支持情况
  const rejection = typeof window !== "undefined" && window.firmware && typeof window.firmware.rejection === "function"
    ? window.firmware.rejection()
    : null;
  if (rejection) {
    enterFWBad(rejection);
    return;
  }

  // 真 PS5：展开三阶段轨道，拉起漏洞主流程
  exploitHeadline = "执行中…";
  if ($("rail")) $("rail").hidden = false;
  if ($("exploit-log")) $("exploit-log").open = true;
  if ($("plan-mode")) $("plan-mode").textContent = "等待提权完成";
  setStatus(
    "running",
    "正在执行 Relapse 提权…",
    "与上游相同，打开页面即开始。WebKit 失败可刷新重试；内核死机需重启主机。"
  );
  setPayloadPanelReady(false);
  runExploit();
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

  enterReady(parsePs5Ua());
}

boot().catch((e) => {
  setStatus("fail", "前端脚本加载出错", String((e && e.message) || e));
});
