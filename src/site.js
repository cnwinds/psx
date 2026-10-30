// 首页编排：
// 1. PS5 且固件可用时显示「开始提权」。点击后先做 WebKit 并探测 9021：
//    已在监听则直接可加载 ELF；否则到 await main() 里的内核链与 Relapse 的 run() 相同。
// 2. elfldr 就绪后显示「一键加载」，点击再按幕二勾选顺序加载 ELF。
// 3. 提权前就可以排序、勾选，并从目录查找 ELF。加入时先下载到本站。选择记在本地。

import { loadCatalog, savePayloadToHost, loadGithubRelease, saveReleaseAsset } from "./catalog.js";
import { loadPlan, savePlan, resetPlan, itemById, formatSize, addCatalogEntry, removeFromPlan, searchWithPinned, planVersionUpdates, commitVersionUpdates, listedReleaseItems, planReleaseUpdate } from "./elfplan.js";
import { establishPrimitive } from "./webkit.js";
import { installWindowP } from "./utils/mem.js";

const $ = (id) => document.getElementById(id);

let plan = loadPlan();
let catalogItems = [];
let searchHits = [];
let catalogState = "idle"; // idle | loading | ready | fail
let saving = false;
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

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

function payloadLine(item) {
  const name = esc(item.name);
  const ver = item.ver ? `<span class="ver-tag">${esc(item.ver)}</span>` : "";
  return `<span class="name-ver"><b>${name}</b>${ver}</span>` +
    `<span class="desc-inline">${esc(item.desc)}</span>`;
}

function planHasFile(file) {
  return plan.order.some((id) => {
    const it = itemById(id);
    return it && it.file === file;
  });
}

async function refreshLocalVersions() {
  if (saving) return;
  const btn = $("btn-updatever");
  const note = $("catalog-note");
  saving = true;
  if (btn) btn.disabled = true;
  if (note) {
    note.hidden = false;
    note.textContent = "正在更新";
  }
  const applied = [];
  let catalogOk = false;
  let checkingRelease = false;
  try {
    if (typeof loadCatalog !== "function" || typeof planVersionUpdates !== "function" || typeof commitVersionUpdates !== "function" || typeof savePayloadToHost !== "function") {
      throw new Error("目录不可用");
    }
    try {
      catalogItems = await loadCatalog();
      catalogState = "ready";
      catalogOk = true;
    } catch (error) {
      catalogItems = [];
      catalogState = "fail";
    }
    const planned = catalogOk ? planVersionUpdates(catalogItems) : [];
    if (typeof listedReleaseItems === "function" && typeof loadGithubRelease === "function" && typeof planReleaseUpdate === "function") {
      const specs = listedReleaseItems(plan.order);
      checkingRelease = specs.length > 0;
      for (const spec of specs) {
        const rel = await loadGithubRelease(spec.repo);
        const change = planReleaseUpdate(spec.id, rel);
        if (change && change.missing) throw new Error("无法保存到本站");
        if (change) planned.push(change);
      }
    }
    for (const change of planned) {
      if (!change.revert) {
        const saved = change.repo
          ? await saveReleaseAsset(change.repo, change.tag, change.asset, change.saveAs, true)
          : await savePayloadToHost(change.remoteFile, change.saveAs, true);
        if (!saved || saved.file !== "library/" + change.saveAs) throw new Error("无法保存到本站");
      }
      commitVersionUpdates([change]);
      applied.push(change);
    }
    renderPlan();
    renderHits();
    if (note) {
      note.hidden = false;
      if (!catalogOk && !applied.length && !checkingRelease) note.textContent = "目录不可用";
      else if (applied.length) note.textContent = "已更新 " + applied.map((change) => change.name + " " + change.to).join("、");
      else note.textContent = "已是最新";
    }
  } catch (error) {
    renderPlan();
    if (note) {
      note.hidden = false;
      if (checkingRelease && !applied.length) note.textContent = "无法保存到本站";
      else if (!catalogOk && !applied.length) note.textContent = "目录不可用";
      else if (applied.length) note.textContent = "已更新 " + applied.map((change) => change.name + " " + change.to).join("、") + "，其余无法保存";
      else note.textContent = "无法保存到本站";
    }
  } finally {
    saving = false;
    if (btn) btn.disabled = false;
  }
}

async function ensureCatalog() {
  if (catalogState === "ready" || catalogState === "loading") return;
  if (typeof loadCatalog !== "function") {
    catalogState = "fail";
    return;
  }
  catalogState = "loading";
  renderHits();
  try {
    catalogItems = await loadCatalog();
    catalogState = "ready";
  } catch (error) {
    catalogItems = [];
    catalogState = "fail";
  }
  renderHits();
}

function renderHits() {
  const input = $("catalog-q");
  const box = $("catalog-hits");
  const note = $("catalog-note");
  const clear = $("catalog-clear");
  if (clear) clear.hidden = !(input && input.value);
  if (!input || !box) return;
  const q = input.value.trim();
  if (!q) {
    searchHits = [];
    box.hidden = true;
    box.innerHTML = "";
    if (note && !saving) note.hidden = true;
    return;
  }
  if (catalogState === "loading") {
    box.hidden = true;
    if (note) {
      note.hidden = false;
      note.textContent = "正在读取目录";
    }
    return;
  }
  if (typeof searchWithPinned !== "function") {
    searchHits = [];
    box.hidden = true;
    box.innerHTML = "";
    if (note) {
      note.hidden = false;
      note.textContent = "目录不可用";
    }
    return;
  }
  const fw = (typeof window !== "undefined" && window.fw_str) || "";
  const source = catalogState === "ready" ? catalogItems : [];
  searchHits = searchWithPinned(source, q, fw);
  if (!searchHits.length) {
    box.hidden = true;
    box.innerHTML = "";
    if (note) {
      note.hidden = false;
      note.textContent = catalogState === "fail" ? "目录不可用" : "没有匹配";
    }
    return;
  }
  if (note && !saving) note.hidden = true;
  box.hidden = false;
  box.innerHTML = searchHits.map((hit) => {
    const added = planHasFile(hit.file);
    return `<li class="catalog-hit">` +
      `<div class="meta"><div class="line1">${payloadLine(hit)}</div></div>` +
      `<button type="button" class="ghost mini" data-act="add" data-file="${esc(hit.file)}">${added ? "已加入" : "加入"}</button>` +
      `</li>`;
  }).join("");
}

// 渲染幕二列表。每次顺序/勾选变化都整表重绘。
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
    const name = esc(it.name);
    li.innerHTML =
      `<span class="ord">${String(idx + 1).padStart(2, "0")}</span>` +
      `<input type="checkbox" class="chk" data-act="toggle" ${on ? "checked" : ""} aria-label="勾选 ${name}">` +
      `<div class="meta">` +
        `<div class="line1">${payloadLine(it)}</div>` +
      `</div>` +
      `<div class="ord-btns">` +
        `<button type="button" data-act="up" ${idx === 0 ? "disabled" : ""} title="上移" aria-label="上移 ${name}">↑</button>` +
        `<button type="button" data-act="down" ${idx === order.length - 1 ? "disabled" : ""} title="下移" aria-label="下移 ${name}">↓</button>` +
        `<button type="button" data-act="drop" title="移出列表" aria-label="移出 ${name}">移除</button>` +
      `</div>` +
      `<span class="pill" data-st="${st}">${STATE_TEXT[st]}</span>` +
      `<button type="button" class="send-one ghost mini" data-act="send" data-send="${esc(it.id)}" data-file="${esc(it.file)}" ${canSend ? "" : "disabled"}>发送</button>`;
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
      if (act === "drop") {
        if (typeof removeFromPlan === "function") removeFromPlan(plan, id);
        delete rowState[id];
        renderPlan();
        renderHits();
        return;
      }
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
      renderHits();
    });
  }

  const updateBtn = $("btn-updatever");
  if (updateBtn) {
    updateBtn.addEventListener("click", () => { refreshLocalVersions(); });
  }

  const catalogInput = $("catalog-q");
  if (catalogInput) {
    catalogInput.addEventListener("focus", () => {
      if (catalogState === "fail") catalogState = "idle";
      ensureCatalog();
    });
    catalogInput.addEventListener("input", () => {
      ensureCatalog();
      renderHits();
    });
  }
  const catalogClear = $("catalog-clear");
  if (catalogClear && catalogInput) {
    catalogClear.hidden = !catalogInput.value;
    catalogClear.addEventListener("click", () => {
      catalogInput.value = "";
      catalogInput.focus();
      renderHits();
    });
  }
  const catalogHits = $("catalog-hits");
  if (catalogHits) {
    catalogHits.addEventListener("click", async (e) => {
      const btn = e.target.closest("[data-act='add']");
      if (!btn || saving) return;
      const hit = searchHits.find((item) => item.file === btn.dataset.file);
      if (!hit || typeof addCatalogEntry !== "function") return;
      const note = $("catalog-note");
      if (hit.pinned) {
        const result = addCatalogEntry(plan, hit);
        if (!result) return;
        if (result.already) {
          if (note) {
            note.hidden = false;
            note.textContent = "已在列表";
          }
          return;
        }
        if (note) note.hidden = true;
        renderPlan();
        renderHits();
        return;
      }
      saving = true;
      if (note) {
        note.hidden = false;
        note.textContent = "正在保存";
      }
      try {
        if (typeof savePayloadToHost !== "function") throw new Error("无法保存到本站");
        const saved = await savePayloadToHost(hit.file, "", true);
        if (!saved || saved.file !== "library/" + hit.file) throw new Error("无法保存到本站");
        const result = addCatalogEntry(plan, Object.assign({}, hit, { library: true }));
        if (!result) throw new Error("无法保存到本站");
        if (result.already) {
          if (note) note.textContent = "已在列表";
          return;
        }
        if (note) note.hidden = true;
        renderPlan();
        renderHits();
      } catch (error) {
        if (note) {
          note.hidden = false;
          note.textContent = "无法保存到本站";
        }
      } finally {
        saving = false;
      }
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
