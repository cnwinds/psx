// 首页编排：
// 1. 渲染幕二 ELF 加载计划列表（勾选、上移/下移、恢复默认、持久化到 localStorage）。
// 2. 启动时查询 /api/jbstate 探测请求方（PS5）的端口：
//    - 9021 在线 → 跳过 WebKit+内核破解，幕一显示「已破解」，幕二切换为经主机转发模式；
//    - 仅 2120/8888/8080 在线 → 提示「部分服务已运行」，给强行重跑按钮；
//    - 全不在线 + 是 PS5 → 揭示三阶段轨道并拉起 main.js 执行漏洞链；
//    - 全不在线 + 非 PS5 → 显示「在电脑上查看」，提供离线下载与手机扫码服务预览。
// 3. 实时生成下方服务（websrv :8080、ZHTTP 网页文件管理 :8888）的手机扫码二维码。
// 4. 全部流程完成后（或主机服务已就绪时），自动折叠上方过程面板，置顶突出展示二维码供用户手机扫码访问。

import { loadPlan, savePlan, resetPlan, itemById, formatSize, renderQRSvg } from "./elfplan.js";

const $ = (id) => document.getElementById(id);

let plan = loadPlan();
let rowState = {};          // id -> "wait" | "sending" | "loaded" | "skip" | "fail"
let hostSendIp = null;      // 非 null 表示走 /api/elfsend 代发（跳过漏洞链模式）

// 服务二维码与流程折叠状态
let currentPs5Ip = "192.168.1.100";
let currentHostIp = "";
let currentHttpPort = 80;
let currentPorts = {};
let ps5Candidates = [];     // [{ip, source, label, ports, open_ports, online, score}]
let hostIpCandidates = [];  // ["192.168.30.182", ...]
let userManuallyPickedIp = false;
let flowCollapsed = false;  // 是否已折叠次要过程面板

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

function writeEvent(message) {
  writeLog(message);
}

if (typeof window !== "undefined") {
  window.writeLog = writeLog;
  window.jb = { mark: writeEvent };
}

function isIpv4(str) {
  return typeof str === "string" && /^\d{1,3}(\.\d{1,3}){3}$/.test(str.trim()) && str.trim() !== "127.0.0.1";
}

function subnetPrefix(ip) {
  if (!isIpv4(ip)) return "";
  return ip.trim().split(".").slice(0, 3).join(".") + ".";
}

function detectInitialPs5Ip() {
  try {
    const saved = localStorage.getItem("ps5ftp");
    if (isIpv4(saved)) return saved.trim();
  } catch (error) {}
  return "192.168.1.100";
}

currentPs5Ip = detectInitialPs5Ip();

// 当选定了 PS5 IP 时，若宿主机有多张网卡，自动优先对齐到与 PS5 同一 /24 子网的宿主机网卡
function alignHostIpToPs5Subnet(ps5Ip) {
  const pfx = subnetPrefix(ps5Ip);
  if (!pfx || !hostIpCandidates.length) return;
  const matched = hostIpCandidates.find((hip) => subnetPrefix(hip) === pfx);
  if (matched) currentHostIp = matched;
}

// 汇总后端多源发现的候选 IP 与本地历史记忆，智能选出最佳默认 IP 并渲染候选胶囊
function syncCandidatesFromState(state) {
  if (!state) return;

  if (Array.isArray(state.host_ips) && state.host_ips.length) {
    hostIpCandidates = state.host_ips.filter(isIpv4);
  } else if (isIpv4(state.host_ip) && hostIpCandidates.indexOf(state.host_ip) < 0) {
    hostIpCandidates = [state.host_ip];
  }
  if (isIpv4(state.host_ip) && !currentHostIp) {
    currentHostIp = state.host_ip;
  }

  const map = new Map();
  const addCand = (c) => {
    if (!c || !isIpv4(c.ip)) return;
    const ip = c.ip.trim();
    const prev = map.get(ip);
    if (!prev || (c.score || 0) >= (prev.score || 0)) {
      map.set(ip, {
        ip,
        source: c.source || (prev && prev.source) || "seen",
        label: c.label || (prev && prev.label) || "候选设备",
        ports: c.ports || (prev && prev.ports) || {},
        open_ports: c.open_ports || (prev && prev.open_ports) || [],
        online: !!(c.online || (prev && prev.online)),
        score: c.score != null ? c.score : (prev && prev.score) || 10,
      });
    }
  };

  if (Array.isArray(state.ps5_candidates)) {
    for (const c of state.ps5_candidates) addCand(c);
  }

  // 如果请求方本身是局域网非宿主机 IP（例如在 PS5 上直接打开），作为高优先级候选
  const isClientHost = isIpv4(state.ip) && hostIpCandidates.indexOf(state.ip) >= 0;
  if (isIpv4(state.ip) && !isClientHost) {
    const openPorts = state.ports ? Object.keys(state.ports).filter((p) => state.ports[p]) : [];
    addCand({
      ip: state.ip,
      source: "client",
      label: openPorts.length ? "当前设备 · 在线" : "当前访问设备",
      ports: state.ports || {},
      open_ports: openPorts,
      online: openPorts.length > 0,
      score: openPorts.length ? 150 : 90,
    });
  }

  // 并入 localStorage 历史记忆的 IP
  try {
    const saved = localStorage.getItem("ps5ftp");
    if (isIpv4(saved) && hostIpCandidates.indexOf(saved.trim()) < 0) {
      addCand({
        ip: saved.trim(),
        source: "saved",
        label: "上次使用",
        score: 35,
      });
    }
  } catch (error) {}

  ps5Candidates = Array.from(map.values()).sort((a, b) => (b.score || 0) - (a.score || 0));

  // 智能选择默认 PS5 IP（若用户尚未手动指定）
  if (!userManuallyPickedIp) {
    const bestOnline = ps5Candidates.find((c) => c.online);
    const bestConfirmed = ps5Candidates.find((c) => (c.score || 0) >= 35);
    if (bestOnline) {
      currentPs5Ip = bestOnline.ip;
      currentPorts = Object.assign({}, bestOnline.ports || {});
    } else if (bestConfirmed) {
      currentPs5Ip = bestConfirmed.ip;
      if (bestConfirmed.ports && Object.keys(bestConfirmed.ports).length) {
        currentPorts = Object.assign({}, bestConfirmed.ports);
      }
    } else if (currentPs5Ip === "192.168.1.100" && ps5Candidates.length) {
      currentPs5Ip = ps5Candidates[0].ip;
      if (ps5Candidates[0].ports) currentPorts = Object.assign({}, ps5Candidates[0].ports);
    } else if (currentPs5Ip === "192.168.1.100" && isIpv4(currentHostIp)) {
      // 没有任何候选设备时，至少把默认网段对齐到宿主机所在的 /24 网段（如 192.168.30.100）
      const pfx = subnetPrefix(currentHostIp);
      if (pfx) currentPs5Ip = pfx + "100";
    }
  }

  alignHostIpToPs5Subnet(currentPs5Ip);
  renderIpCandidateChips();
}

function renderIpCandidateChips() {
  const panel = $("qr-candidates-panel");
  const ps5Row = $("qr-ps5-candidates-row");
  const ps5Box = $("qr-ps5-chips");
  const hostRow = $("qr-host-candidates-row");
  const hostBox = $("qr-host-chips");
  if (!panel || !ps5Box || !hostBox) return;

  const hasPs5Chips = ps5Candidates.length > 0;
  const hasHostChips = hostIpCandidates.length > 1;
  panel.hidden = !hasPs5Chips && !hasHostChips;

  if (ps5Row) ps5Row.hidden = !hasPs5Chips;
  if (hasPs5Chips) {
    ps5Box.innerHTML = ps5Candidates.map((c) => {
      const active = c.ip === currentPs5Ip;
      const dotKind = c.online ? "online" : (c.score >= 35 ? "seen" : "arp");
      const portBadge = c.open_ports && c.open_ports.length
        ? ` · :${c.open_ports.join(" :")}`
        : "";
      return (
        `<button type="button" class="ip-chip${active ? " is-active" : ""}" data-select-ps5-ip="${c.ip}" role="radio" aria-checked="${active ? "true" : "false"}">` +
          `<span class="chip-dot" data-dot="${dotKind}"></span>` +
          `<b class="chip-ip">${c.ip}</b>` +
          `<span class="chip-meta">${c.label}${portBadge}</span>` +
        `</button>`
      );
    }).join("");
  }

  if (hostRow) hostRow.hidden = !hasHostChips;
  if (hasHostChips) {
    const ps5Pfx = subnetPrefix(currentPs5Ip);
    hostBox.innerHTML = hostIpCandidates.map((hip) => {
      const active = hip === currentHostIp;
      const sameSub = ps5Pfx && subnetPrefix(hip) === ps5Pfx;
      return (
        `<button type="button" class="ip-chip host-chip${active ? " is-active" : ""}" data-select-host-ip="${hip}" role="radio" aria-checked="${active ? "true" : "false"}">` +
          `<span class="chip-dot" data-dot="${active ? "online" : "arp"}"></span>` +
          `<b class="chip-ip">${hip}</b>` +
          `<span class="chip-meta">${sameSub ? "★ 与 PS5 同网段" : "备选网卡"}</span>` +
        `</button>`
      );
    }).join("");
  }

  // 更新输入框旁边的来源提示文案
  const hintEl = $("qr-ip-hint");
  if (hintEl) {
    const matched = ps5Candidates.find((c) => c.ip === currentPs5Ip);
    if (matched && matched.online) {
      hintEl.textContent = `● 在线`;
      if (hintEl.dataset) hintEl.dataset.tone = "ok";
    } else if (matched) {
      hintEl.textContent = matched.label;
      if (hintEl.dataset) hintEl.dataset.tone = "seen";
    } else {
      hintEl.textContent = "";
      if (hintEl.dataset) hintEl.dataset.tone = "";
    }
  }
}

async function selectPs5Ip(ip, probeNow) {
  if (!ip) return;
  userManuallyPickedIp = true;
  currentPs5Ip = ip.trim();
  try {
    if (isIpv4(currentPs5Ip)) localStorage.setItem("ps5ftp", currentPs5Ip);
  } catch (error) {}

  alignHostIpToPs5Subnet(currentPs5Ip);
  const cand = ps5Candidates.find((c) => c.ip === currentPs5Ip);
  if (cand && cand.ports && Object.keys(cand.ports).length) {
    currentPorts = Object.assign({}, cand.ports);
  }
  renderIpCandidateChips();
  updateServiceQRCodes();
  updatePcSendCmd();

  if (probeNow && isIpv4(currentPs5Ip)) {
    try {
      const res = await fetch("/api/jbstate?target=" + encodeURIComponent(currentPs5Ip), { cache: "no-store" });
      const st = await res.json();
      if (st && st.ports) {
        currentPorts = Object.assign({}, st.ports);
        syncCandidatesFromState(st);
        updateServiceQRCodes();
      }
    } catch (error) {}
  }
}

function getServiceDescriptor(key) {
  const ip = (currentPs5Ip || "192.168.1.100").trim() || "192.168.1.100";
  if (key === "websrv") {
    const url = "http://" + ip + ":8080";
    return {
      key: "websrv",
      title: "websrv 网页发送器 (:8080)",
      url,
      desc: "手机扫码向 PS5 追发任意 payload",
      up: !!currentPorts["8080"],
      port: "8080",
    };
  }
  const url = "http://" + ip + ":8888";
  return {
    key: "zhttp",
    title: "ZHTTP 网页文件管理 (:8888)",
    url,
    desc: "PS5 本机直连 · 免密访问",
    up: !!currentPorts["8888"],
    port: "8888",
  };
}

function safeRenderQR(text, opts) {
  if (typeof renderQRSvg === "function") {
    try {
      return renderQRSvg(text, opts);
    } catch (error) {}
  }
  return "";
}

function setBadgeState(el, up, port) {
  if (!el) return;
  const hasProbed = Object.keys(currentPorts).length > 0;
  if (!hasProbed) {
    if (el.dataset) el.dataset.up = "wait";
    el.textContent = "待检测 :" + port;
  } else if (up) {
    if (el.dataset) el.dataset.up = "on";
    el.textContent = "运行中 :" + port;
  } else {
    if (el.dataset) el.dataset.up = "off";
    el.textContent = "未监听 :" + port;
  }
}

function updateServiceQRCodes() {
  const ip = (currentPs5Ip || "192.168.1.100").trim() || "192.168.1.100";

  const ipInput = $("qr-ps5-ip");
  if (ipInput && document.activeElement !== ipInput && ipInput.value !== ip) {
    ipInput.value = ip;
  }

  const stIp = $("st-ip");
  if (stIp) {
    const openCount = ["9021", "2120", "8888", "8080"].filter((p) => currentPorts[p]).length;
    stIp.textContent = ip + (openCount ? " (" + openCount + " 在线)" : "");
    stIp.className = openCount ? "ok" : "";
  }

  // 1. websrv (:8080)
  const web = getServiceDescriptor("websrv");
  const qrWeb = $("qr-websrv");
  if (qrWeb) qrWeb.innerHTML = safeRenderQR(web.url);
  const urlWeb = $("url-websrv");
  if (urlWeb) urlWeb.textContent = web.url;
  const linkWeb = $("link-websrv");
  if (linkWeb) linkWeb.href = web.url;
  setBadgeState($("badge-websrv"), web.up, "8080");
  const cardWeb = $("service-websrv");
  if (cardWeb && cardWeb.dataset) cardWeb.dataset.online = web.up ? "1" : "0";

  // 2. ZHTTP (:8888)
  const zhttp = getServiceDescriptor("zhttp");
  const qrZhttp = $("qr-zhttp");
  if (qrZhttp) qrZhttp.innerHTML = safeRenderQR(zhttp.url);
  const urlZhttp = $("url-zhttp");
  if (urlZhttp) urlZhttp.textContent = zhttp.url;
  const linkZhttp = $("link-zhttp");
  if (linkZhttp) linkZhttp.href = zhttp.url;
  setBadgeState($("badge-zhttp"), zhttp.up, "8888");
  const cardZhttp = $("service-zhttp");
  if (cardZhttp && cardZhttp.dataset) cardZhttp.dataset.online = zhttp.up ? "1" : "0";
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

// 全部流程完成后的主折叠切换：收起顶部大横幅、01 破解过程、02 加载列表，将 03 手机扫码区置顶放大展示
function setFlowCollapsed(collapsed, reasonTitle, reasonDesc) {
  flowCollapsed = !!collapsed;
  if (typeof document !== "undefined" && document.body && document.body.classList) {
    document.body.classList.toggle("flow-done", flowCollapsed);
  }
  const hero = $("hero-intro");
  if (hero) hero.hidden = flowCollapsed;

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
  const manualBtn = $("btn-fold-manual");
  if (manualBtn) {
    manualBtn.textContent = flowCollapsed ? "展开流程" : "折叠流程";
  }

  // 更新折叠摘要提示
  const expSummary = $("exploit-fold-summary");
  if (expSummary) {
    const jbText = ($("st-jb") && $("st-jb").textContent) || "已完成";
    expSummary.textContent = flowCollapsed
      ? jbText
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
      : "间隔 5s · 自动跳过已运行项";
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
      `<button type="button" class="send-one ghost mini" data-act="send" data-file="${it.file}">发送</button>`;
    list.appendChild(li);
  });
  updatePcSendCmd();
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
      } else if (act === "send" && hostSendIp) {
        // 已破解模式下单独发送走后端代发；漏洞链模式下由 payload_loader.js 接管按钮
        sendOneViaHost(id);
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

  // 绑定二维码区交互
  const ipInput = $("qr-ps5-ip");
  if (ipInput) {
    ipInput.addEventListener("input", () => {
      const val = ipInput.value.trim();
      if (val) {
        userManuallyPickedIp = true;
        currentPs5Ip = val;
        try {
          if (isIpv4(val)) localStorage.setItem("ps5ftp", val);
        } catch (error) {}
        alignHostIpToPs5Subnet(val);
        renderIpCandidateChips();
        updateServiceQRCodes();
        updatePcSendCmd();
      }
    });
  }

  const scanLanBtn = $("btn-scan-lan");
  if (scanLanBtn) {
    scanLanBtn.addEventListener("click", async () => {
      scanLanBtn.disabled = true;
      scanLanBtn.textContent = "扫描中…";
      try {
        const res = await fetch("/api/jbstate?scan=1&target=" + encodeURIComponent(currentPs5Ip), { cache: "no-store" });
        const st = await res.json();
        if (st) {
          userManuallyPickedIp = false;
          syncCandidatesFromState(st);
          if (st.ports) applyElfState(st.ports, st);
        }
      } catch (error) {}
      scanLanBtn.disabled = false;
      scanLanBtn.textContent = "扫描局域网";
    });
  }

  const probeBtn = $("btn-probe-ports");
  if (probeBtn) {
    probeBtn.addEventListener("click", async () => {
      probeBtn.disabled = true;
      probeBtn.textContent = "刷新中…";
      try {
        const res = await fetch("/api/jbstate?target=" + encodeURIComponent(currentPs5Ip), { cache: "no-store" });
        const st = await res.json();
        if (st && st.ports) {
          syncCandidatesFromState(st);
          applyElfState(st.ports, st);
        }
      } catch (error) {}
      probeBtn.disabled = false;
      probeBtn.textContent = "刷新端口";
    });
  }

  const toggleFoldBtn = $("btn-toggle-fold");
  if (toggleFoldBtn) {
    toggleFoldBtn.addEventListener("click", () => {
      setFlowCollapsed(!flowCollapsed);
    });
  }

  const manualFoldBtn = $("btn-fold-manual");
  if (manualFoldBtn) {
    manualFoldBtn.addEventListener("click", () => {
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

  // 复制链接、切换候选 IP 胶囊与放大二维码事件委托
  if (typeof document !== "undefined" && document.addEventListener) {
    document.addEventListener("click", (e) => {
      if (!e.target || typeof e.target.closest !== "function") return;

      const ps5Chip = e.target.closest("[data-select-ps5-ip]");
      if (ps5Chip) {
        selectPs5Ip(ps5Chip.dataset.selectPs5Ip, true);
        return;
      }

      const hostChip = e.target.closest("[data-select-host-ip]");
      if (hostChip) {
        currentHostIp = hostChip.dataset.selectHostIp;
        renderIpCandidateChips();
        updateServiceQRCodes();
        return;
      }

      const copyBtn = e.target.closest("[data-copy-target]");
      if (copyBtn) {
        const targetEl = $(copyBtn.dataset.copyTarget);
        const text = targetEl ? targetEl.textContent : "";
        if (text && navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(() => {
            const orig = copyBtn.textContent;
            copyBtn.textContent = "已复制 ✓";
            setTimeout(() => { copyBtn.textContent = orig; }, 1500);
          }).catch(() => {});
        }
        return;
      }

      const zoomTrigger = e.target.closest("[data-zoom-qr]");
      if (zoomTrigger) {
        openQrModal(zoomTrigger.dataset.zoomQr);
        return;
      }

      const closeTrigger = e.target.closest("[data-close-modal]");
      if (closeTrigger) {
        closeQrModal();
      }
    });
  }
}

function openQrModal(serviceKey) {
  const modal = $("qr-modal");
  if (!modal) return;
  const desc = getServiceDescriptor(serviceKey);
  if ($("qr-modal-title")) $("qr-modal-title").textContent = desc.title;
  if ($("qr-modal-svg")) $("qr-modal-svg").innerHTML = safeRenderQR(desc.url, { margin: 2 });
  if ($("qr-modal-url")) $("qr-modal-url").textContent = desc.url;
  if ($("qr-modal-desc")) $("qr-modal-desc").textContent = desc.desc;
  if ($("qr-modal-open")) $("qr-modal-open").href = desc.url;
  modal.hidden = false;
}

function closeQrModal() {
  const modal = $("qr-modal");
  if (modal) modal.hidden = true;
}

function setRowState(id, st, bytes) {
  rowState[id] = st;
  const pill = document.querySelector(`#elf-rows .elf-row[data-id="${id}"] .pill`);
  if (pill) {
    pill.dataset.st = st;
    pill.textContent = (STATE_TEXT[st] || st) + (bytes ? ` (${formatSize(bytes)})` : "");
  }
  if (st === "done" || st === "loaded") {
    if (id === "zftpd") {
      currentPorts["2120"] = true;
      currentPorts["8888"] = true;
    } else if (id === "websrv") {
      currentPorts["8080"] = true;
    }
    updateServiceQRCodes();
  }
}

// 供 payload_loader.js 调用：读取当前勾选且保序的条目列表
window.getElfPlan = function () {
  return plan.order.filter((id) => !plan.off.has(id)).map(itemById).filter(Boolean);
};
window.setElfRowState = setRowState;

// 根据 /api/jbstate 的端口探测结果同步行状态胶囊与二维码状态
function applyElfState(ports, fullState) {
  if (!ports) return;
  currentPorts = Object.assign({}, currentPorts, ports);
  if (fullState) {
    if (isIpv4(fullState.ip)) {
      currentPs5Ip = fullState.ip;
      try { localStorage.setItem("ps5ftp", fullState.ip); } catch (error) {}
    }
    if (isIpv4(fullState.host_ip)) currentHostIp = fullState.host_ip;
    if (fullState.http_port) currentHttpPort = fullState.http_port;
  }
  if (ports["2120"] || ports["8888"]) setRowState("zftpd", "loaded");
  if (ports["8080"]) setRowState("websrv", "loaded");
  if (ports["9021"] && $("st-ldr")) {
    $("st-ldr").textContent = "在线 :9021";
    $("st-ldr").className = "ok";
  }
  updateServiceQRCodes();
}
window.applyElfState = applyElfState;

// 全部流程完成回调（由 payload_loader.js 在发送完所有勾选 ELF 并验证端口后触发）
window.onFlowComplete = function (finalState) {
  if (finalState && finalState.ports) {
    applyElfState(finalState.ports, finalState);
  }
  if ($("st-jb")) {
    $("st-jb").textContent = "全部就绪";
    $("st-jb").className = "ok";
  }
  setStatus(
    "ok",
    "提权与组件注入已完成",
    "请使用手机扫码访问下方服务。"
  );
  setFlowCollapsed(
    true,
    "服务已就绪 · 请用手机扫码访问",
    "手机与 PS5 连接同一 Wi-Fi 即可扫码直连。"
  );
  const servicesEl = $("act-services");
  if (servicesEl && typeof servicesEl.scrollIntoView === "function") {
    try { servicesEl.scrollIntoView({ behavior: "smooth", block: "start" }); } catch (error) {}
  }
};

// 生成电脑端一键按序发送的命令（Linux nc 与 PowerShell 双版本）
function updatePcSendCmd() {
  const box = $("pcsend");
  if (!box) return;
  const ip = hostSendIp || currentPs5Ip || "<PS5的IP>";
  const files = plan.order.filter((id) => !plan.off.has(id)).map((id) => "payloads/" + itemById(id).file);
  if (!files.length) {
    if ($("pcsend-cmd")) $("pcsend-cmd").textContent = "# 请先勾选至少一项 ELF";
    if ($("pcsend-ps")) $("pcsend-ps").textContent = "# 请先勾选至少一项 ELF";
    return;
  }
  if ($("pcsend-cmd")) {
    $("pcsend-cmd").textContent =
      `for f in ${files.join(" ")}; do nc -w 3 ${ip} 9021 < "$f" && sleep 5; done`;
  }
  if ($("pcsend-ps")) {
    const arr = files.map((f) => `"${f}"`).join(",");
    $("pcsend-ps").textContent =
      `(${arr}) | % { $c=New-Object Net.Sockets.TcpClient("${ip}",9021);` +
      `[IO.File]::OpenRead($_).CopyTo($c.GetStream());$c.Close();Start-Sleep 5 }`;
  }
}

// ── 经主机 /api/elfsend 代发模式（PS5 已破解、跳过浏览器漏洞链时使用）──
async function sendOneViaHost(id) {
  const it = itemById(id);
  if (!it) return false;
  const targetHost = hostSendIp || currentPs5Ip || "";
  // 发送前复查端口：zftpd / websrv 已在跑就直接标「已加载」不重发
  try {
    const st = await (await fetch("/api/jbstate?target=" + encodeURIComponent(targetHost), { cache: "no-store" })).json();
    if (st && st.ports) {
      applyElfState(st.ports, st);
      if ((id === "zftpd" && (st.ports["2120"] || st.ports["8888"])) ||
          (id === "websrv" && st.ports["8080"])) {
        return true;
      }
    }
  } catch (error) {}
  setRowState(id, "sending");
  try {
    const r = await fetch(`/api/elfsend?file=${encodeURIComponent(it.file)}&host=${encodeURIComponent(targetHost)}`, { method: "POST" });
    const j = await r.json();
    if (j && j.ok) {
      setRowState(id, "loaded", j.bytes);
      return true;
    }
    setRowState(id, "fail");
    return false;
  } catch (error) {
    setRowState(id, "fail");
    return false;
  }
}

async function runPlanViaHost() {
  const btn = $("btn-runplan");
  if (btn) btn.disabled = true;
  // 先探一轮，已加载的直接标绿并从本轮剔除
  let loaded = {};
  try {
    const st = await (await fetch("/api/jbstate", { cache: "no-store" })).json();
    if (st && st.ports) {
      applyElfState(st.ports, st);
      loaded = {
        zftpd: !!(st.ports["2120"] || st.ports["8888"]),
        websrv: !!st.ports["8080"],
      };
    }
  } catch (error) {}
  const ids = plan.order.filter((id) => !plan.off.has(id) && !loaded[id]);
  let allOk = true;
  for (let i = 0; i < ids.length; i++) {
    const ok = await sendOneViaHost(ids[i]);
    if (!ok) {
      allOk = false;
      break;
    }
    if (i < ids.length - 1) await new Promise((r) => setTimeout(r, 5000));
  }
  // 推送完成后再复查一次端口，刷新二维码在线徽章并自动折叠进入扫码视图
  try {
    const st2 = await (await fetch("/api/jbstate", { cache: "no-store" })).json();
    if (st2 && st2.ports) applyElfState(st2.ports, st2);
  } catch (error) {}
  if (btn) btn.disabled = false;
  if (allOk && typeof window.onFlowComplete === "function") {
    window.onFlowComplete();
  }
}

// ── 幕一状态卡切换 ──
function setStatus(state, titleText, bodyText, actionsHtml) {
  const card = $("exploit-status");
  if (card && card.dataset) card.dataset.state = state;
  const badgeMap = {
    checking: "检测中",
    ok: "已就绪",
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

function enterJailbroken(state, ua) {
  hostSendIp = state.ip;
  applyElfState(state.ports, state);
  if ($("st-jb")) {
    $("st-jb").textContent = "已破解";
    $("st-jb").className = "ok";
  }
  if ($("st-ldr")) {
    $("st-ldr").textContent = "在线 :9021";
    $("st-ldr").className = "ok";
  }

  const openList = [];
  if (state.ports["9021"]) openList.push("<code>9021</code> elfldr");
  if (state.ports["2120"]) openList.push("<code>2120</code> zftpd FTP");
  if (state.ports["8888"]) openList.push("<code>8888</code> ZHTTP 网页");
  if (state.ports["8080"]) openList.push("<code>8080</code> websrv");

  setStatus(
    "ok",
    `主机 ${state.ip} 已破解`,
    `在线端口：${openList.join(" · ")}。` +
    (state.ports["8888"]
      ? ` 可直接扫码或打开 <a href="http://${state.ip}:8888" target="_blank" rel="noreferrer">ZHTTP 文件管理</a>。`
      : ` 可展开「02 ELF 加载计划」补发组件。`),
    `<button type="button" id="btn-force-rerun" class="ghost">强制重跑</button>`
  );

  // 幕二切到「经主机代发」模式，立即可点
  if ($("plan-mode")) $("plan-mode").textContent = `经主机 → ${state.ip}:9021`;
  if ($("btn-runplan")) {
    $("btn-runplan").disabled = false;
    $("btn-runplan").onclick = runPlanViaHost;
  }
  if ($("pcsend")) $("pcsend").hidden = false;
  updatePcSendCmd();

  const rerun = $("btn-force-rerun");
  if (rerun) {
    rerun.onclick = () => {
      hostSendIp = null;
      startExploitFlow(ua);
    };
  }

  // 主机已破解时，默认自动折叠过程详情，直接主推下方服务二维码供用户扫码
  const hasAppService = !!(state.ports["2120"] || state.ports["8888"] || state.ports["8080"]);
  setFlowCollapsed(
    true,
    hasAppService
      ? `主机 ${state.ip} 已就绪 · 手机扫码访问`
      : `主机 ${state.ip} 已破解 (:9021 在线)`,
    hasAppService
      ? "后台服务运行中，手机连接同一 Wi-Fi 即可扫码直连。"
      : "如需启动文件管理或网页发送器，可展开「02 ELF 加载计划」一键发送。"
  );
}

function enterPartial(state, ua) {
  applyElfState(state.ports, state);
  if ($("st-jb")) {
    $("st-jb").textContent = "已破解（elfldr 已退出）";
    $("st-jb").className = "ok";
  }
  if ($("st-ldr")) {
    $("st-ldr").textContent = "离线";
    $("st-ldr").className = "warn";
  }
  const hasFtp = !!state.ports["2120"];
  const hasZhttp = !!state.ports["8888"];
  const hasWebsrv = !!state.ports["8080"];
  const running = [];
  if (hasFtp) running.push("zftpd FTP (<code>:2120</code>)");
  if (hasZhttp) running.push("ZHTTP (<code>:8888</code>)");
  if (hasWebsrv) running.push("websrv (<code>:8080</code>)");
  const guideParts = [];
  if (hasZhttp) guideParts.push(`打开 <a href="http://${state.ip}:8888" target="_blank" rel="noreferrer">ZHTTP 文件管理</a>`);
  if (hasWebsrv) guideParts.push(`访问 <code>http://${state.ip}:8080</code> 追发 payload`);
  const guideText = guideParts.length ? `可直接${guideParts.join("，或")}。` : "";
  setStatus(
    "ok",
    `${running.join(" / ")} 运行中`,
    `主机 <code>${state.ip}</code> 服务在线（<code>9021</code> 已退出）。${guideText}`,
    `<button type="button" id="btn-force-rerun" class="ghost">仍要重跑</button>`
  );
  const rerun = $("btn-force-rerun");
  if (rerun) rerun.onclick = () => enterReady(ua);

  // 服务已在运行时同样自动折叠上方过程面板，突出展示二维码
  setFlowCollapsed(
    true,
    `主机 ${state.ip} 服务运行中 · 手机扫码访问`,
    `已检测到 ${running.join(" / ").replace(/<\/?code>/g, "")} 在线。`
  );
}

function enterUnknown(state, ua) {
  setFlowCollapsed(false);
  const banner = $("flow-complete-banner");
  if (banner) banner.hidden = true;

  if ($("st-jb")) {
    $("st-jb").textContent = "待确认";
    $("st-jb").className = "warn";
  }
  if ($("st-ldr")) $("st-ldr").textContent = "未知";
  setStatus(
    "pc",
    "未能获取端口状态",
    "为防重复提权已暂停自动执行。若确认主机刚开机未破解，可手动启动；若已破解，直接在下方扫码。",
    `<button type="button" id="btn-manual-run" class="primary">手动启动提权</button>`
  );
  const runBtn = $("btn-manual-run");
  if (runBtn) runBtn.onclick = () => enterReady(ua);
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
  return primitive;
}

function getWebKitBase(activePrimitive) {
  const textarea = document.createElement("textarea");
  const webcoreTextarea = activePrimitive.read64(activePrimitive.addrof(textarea).add32(0x18));
  const vtable = activePrimitive.read64(webcoreTextarea);
  const firstEntry = activePrimitive.read64(vtable);
  return firstEntry.sub(window.firmware.offsets.WebKit_TextAreaVtableFirstEntryOffset);
}

async function unlockSender() {
  if (typeof document !== "undefined" && document.querySelectorAll) {
    document.querySelectorAll("#elf-rows [data-file]").forEach((btn) => { btn.disabled = false; });
  }
  if ($("btn-runplan")) $("btn-runplan").disabled = false;
  if ($("st-ldr")) {
    $("st-ldr").textContent = "在线 :9021";
    $("st-ldr").className = "ok";
  }
  currentPorts["9021"] = true;
  if ($("plan-mode")) {
    $("plan-mode").textContent = "浏览器直发 → 127.0.0.1:9021";
    $("plan-mode").className = "mode-tag ready";
  }
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
  if ($("st-jb")) {
    $("st-jb").textContent = "失败";
    $("st-jb").className = "err";
  }
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
  if ($("jb-button")) $("jb-button").disabled = true;

  if ($("rail")) $("rail").hidden = false;
  ["webkit", "kernel", "elfldr"].forEach((s) => setStage(s, "idle"));
  setStatus("running", "正在执行提权链路…", "请勿关闭页面，完成后将自动加载组件并展示二维码。");
  if ($("st-jb")) {
    $("st-jb").textContent = "执行中…";
    $("st-jb").className = "run";
  }

  try {
    const rejection = window.firmware && typeof window.firmware.rejection === "function"
      ? window.firmware.rejection()
      : null;
    if (rejection) throw new Error(rejection);

    setStage("webkit", "run");
    writeLog(`[*] 阶段 01：建立 WebKit 任意读写原语（固件 ${window.fw_str || "未知"}）`);
    const activePrimitive = await getPrimitive();
    const webkitBase = getWebKitBase(activePrimitive);
    writeLog(`[+] WebKit 原语就绪，libSceNKWebKit 基址 = ${webkitBase}`, "g");
    setStage("webkit", "ok");

    setStage("kernel", "run");
    setStage("elfldr", "idle");
    writeLog("[*] 阶段 02：触发 Relapse 内核漏洞并部署 elfldr…");
    await import("./relapse_exploit.js");
    const runtime = await main(activePrimitive);
    if (!runtime || !runtime.p || !runtime.chain) {
      throw new Error("内核阶段未返回有效 ROP 通道");
    }
    exploitRuntime = runtime;
    setStage("kernel", "ok");

    const loaded = runtime.elfldrResult && Number(runtime.elfldrResult.low) === 0;
    setStage("elfldr", loaded ? "ok" : "fail");
    if (loaded) {
      writeLog("[+] 阶段 03：elfldr 已注入并在 9021 端口监听", "g");
    } else {
      writeLog("[!] elfldr 返回码异常，但 ROP 通道可用，仍可尝试发送", "e");
    }

    if ($("st-jb")) {
      $("st-jb").textContent = "已破解";
      $("st-jb").className = "ok";
    }
    setStatus(
      "ok",
      "提权完成 · elfldr (:9021) 就绪",
      "正在按计划自动注入 ELF 组件…"
    );
    await unlockSender();
  } catch (error) {
    failExploit(error);
  } finally {
    exploitBusy = false;
  }
}

function enterFWBad(reason) {
  setFlowCollapsed(false);
  if ($("st-jb")) {
    $("st-jb").textContent = "固件不支持";
    $("st-jb").className = "err";
  }
  if ($("st-ldr")) $("st-ldr").textContent = "离线";
  setStatus(
    "fail",
    "固件不受支持",
    `${reason}（支持 FW <b>7.00 – 10.01</b>）。电脑访问请直接在下方扫码或打开 ZHTTP 文件管理（<code>:8888</code>）。`
  );
  if ($("pcsend")) $("pcsend").hidden = false;
  updatePcSendCmd();
}

function enterReady(ua) {
  setFlowCollapsed(false);
  const banner = $("flow-complete-banner");
  if (banner) banner.hidden = true;

  if (!ua.isPs5) {
    if ($("st-jb")) {
      $("st-jb").textContent = "非 PS5 浏览器";
      $("st-jb").className = "warn";
    }
    if ($("st-ldr")) $("st-ldr").textContent = "离线";
    setStatus(
      "pc",
      "非 PS5 浏览器（未检测到 :9021）",
      "请在 PS5「设置 → 用户指南」访问本页执行提权；若主机已在运行服务，直接在下方输入 IP 扫码即可。",
      `<button type="button" id="btn-pc-fold" class="ghost">专注扫码视图 ▾</button>`
    );
    const pcFoldBtn = $("btn-pc-fold");
    if (pcFoldBtn) {
      pcFoldBtn.onclick = () => {
        setFlowCollapsed(
          true,
          "手机扫码服务 · 输入 PS5 IP 生成二维码",
          "手机与 PS5 连接同一 Wi-Fi 即可扫码直连。"
        );
      };
    }
    if ($("pcsend")) $("pcsend").hidden = false;
    updatePcSendCmd();
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
  if ($("st-jb")) {
    $("st-jb").textContent = "待破解";
    $("st-jb").className = "warn";
  }
  if ($("st-ldr")) $("st-ldr").textContent = "等待阶段 3";
  setStatus(
    "running",
    "准备执行 WebKit + 内核提权",
    "依次完成 WebKit → 内核提权 → elfldr (:9021) → 组件加载，完成后自动切换扫码视图。",
    `<button type="button" id="jb-button" class="primary">开始提权</button>`
  );
  if ($("rail")) $("rail").hidden = false;
  if ($("exploit-log")) $("exploit-log").open = true;
  if ($("plan-mode")) $("plan-mode").textContent = "等待 elfldr :9021";

  const jbBtn = $("jb-button");
  if (jbBtn) jbBtn.onclick = () => runExploit();

  // 在真实浏览器环境（已加载 main.js）且开启自动执行时，进入页面即自动拉起漏洞链
  const autoOpt = $("autorun-opt");
  if (typeof main === "function" && (!autoOpt || autoOpt.checked !== false)) {
    runExploit();
  }
}

function startExploitFlow(ua) {
  return enterReady(ua);
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

async function boot() {
  startMatrixRain();
  renderPlan();
  wirePlanEvents();
  updateServiceQRCodes();

  const ua = parsePs5Ua();
  if ($("st-device")) {
    $("st-device").textContent = ua.isPs5 ? `PS5 · FW ${ua.fw}` : "电脑 / 手机浏览器";
    $("st-device").className = ua.isPs5 ? "ok" : "";
  }

  let state = null;
  try {
    const r = await fetch("/api/jbstate", { cache: "no-store" });
    state = await r.json();
  } catch (error) { /* 静态托管无后端时退化 */ }

  if (state) {
    if (isIpv4(state.ip)) {
      currentPs5Ip = state.ip;
      try { localStorage.setItem("ps5ftp", state.ip); } catch (error) {}
    }
    if (isIpv4(state.host_ip)) currentHostIp = state.host_ip;
    if (state.http_port) currentHttpPort = state.http_port;
    if (state.ports) currentPorts = Object.assign({}, state.ports);
    syncCandidatesFromState(state);
    updateServiceQRCodes();
  }

  // 支持 URL 参数 ?demo=done 方便直接进入「全部流程已完成 · 扫码主视图」并演示多源 IP 胶囊选择
  try {
    const qs = new URLSearchParams((typeof location !== "undefined" && location.search) || "");
    if (qs.get("demo") === "done" && typeof window.onFlowComplete === "function") {
      const pfx = subnetPrefix(currentHostIp) || "192.168.30.";
      const demoIp = pfx + "86";
      syncCandidatesFromState({
        ip: demoIp,
        host_ip: currentHostIp || (pfx + "182"),
        host_ips: [currentHostIp || (pfx + "182"), "192.168.1.50"],
        http_port: currentHttpPort,
        ports: { "9021": true, "2120": true, "8888": true, "8080": true },
        ps5_candidates: [
          {
            ip: demoIp,
            source: "ps5-ua",
            label: "PS5 用户指南 · 在线",
            ports: { "9021": true, "2120": true, "8888": true, "8080": true },
            open_ports: ["9021", "2120", "8888", "8080"],
            online: true,
            score: 140,
          },
          {
            ip: pfx + "105",
            source: "dns",
            label: "DNS 活跃记录",
            ports: { "9021": false, "2120": true, "8888": true, "8080": false },
            open_ports: ["2120", "8888"],
            online: true,
            score: 120,
          },
          {
            ip: pfx + "128",
            source: "arp",
            label: "局域网邻居",
            ports: { "9021": false, "2120": false, "8888": false, "8080": false },
            open_ports: [],
            online: false,
            score: 10,
          },
        ],
      });
      window.onFlowComplete({
        ip: demoIp,
        host_ip: currentHostIp || (pfx + "182"),
        http_port: currentHttpPort,
        ports: { "9021": true, "2120": true, "8888": true, "8080": true },
        jailbroken: true,
      });
      return;
    }
  } catch (error) {}

  const ports = state && state.ports && typeof state.ports === "object" ? state.ports : null;
  if (!ports) {
    enterUnknown(state, ua);
  } else if (ports["9021"]) {
    enterJailbroken(state, ua);
  } else if (state.jailbroken || ports["2120"] || ports["8888"] || ports["8080"]) {
    enterPartial(state, ua);
  } else {
    enterReady(ua);
  }
}

boot().catch((e) => {
  setStatus("fail", "前端脚本加载出错", String((e && e.message) || e));
});
