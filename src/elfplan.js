import { firmwareMatches } from "./catalog.js";

// ELF 加载计划：内置三项 + 用户从目录下载进本站的条目 + 顺序/勾选。
// 幕二的单一数据源：site.js 渲染，payload_loader.js 按此发送。
//
// 提权链路已经拉起 elfldr（监听 9021）。列表里是发给它的 ELF，
// 默认只有 kstuff、ftpsrv、panplay，并且都在一键链里（panplay 在队尾）。
// 这三项会混进目录搜索。删掉后可以再加回来，用的仍是本站文件。
//
// 从目录加入的其他 ELF 必须先由本站下载到 payloads/library/。
// 版本记录只留 {ver, library:true}，加载地址永远在本站。

export const ELF_ITEMS = [
  {
    id: "kstuff",
    file: "kstuff.elf",
    name: "kstuff-lite",
    ver: "1.11",
    role: "必选",
    desc: "FSELF / FPKG 内核补丁",
    src: "https://github.com/EchoStretch/kstuff-lite",
    size: 1737080,
    on: true,
  },
  {
    id: "ftpsrv",
    file: "ftpsrv.elf",
    name: "ftpsrv",
    ver: "0.21.1",
    role: ":2121",
    desc: "FTP 文件服务 (:2121)，FileZilla 等客户端可连",
    src: "https://github.com/ps5-payload-dev/ftpsrv",
    size: 191864,
    on: true,
  },
  {
    id: "panplay",
    file: "panplay.elf",
    name: "盘游 panplay",
    ver: "0.16.4",
    role: ":8734",
    desc: "百度网盘直装（:8734）；与 ShadowMountPlus 勿同时勾选",
    src: "https://github.com/cnwinds/pan-play",
    size: 6720416,
    on: true,
    // 目录里没有这个仓库。更新时向 GitHub latest 要 panplay-{tag}-ps5.elf。
    release: { repo: "cnwinds/pan-play", asset: "panplay-{tag}-ps5.elf" },
  },
];

const PLAN_KEY = "psx.elfplan.v1";
const EXTRA_KEY = "psx.elfextra.v1";
const UPDATE_KEY = "psx.elfupdate.v1";
const SEARCH_LIMIT = 8;
const FILE_NAME = /^[A-Za-z0-9._-]+\.(elf|bin)$/i;

function normalizeVer(ver) {
  return String(ver || "").trim().replace(/^[vV]/, "");
}

function repoOf(url) {
  const matched = String(url || "").match(/github\.com\/([^/]+\/[^/#?\s]+)/i);
  return matched ? matched[1].replace(/\.git$/i, "").toLowerCase() : "";
}

export function matchCatalogEntry(item, catalog) {
  const repo = repoOf(item && item.src);
  if (!repo) return null;
  const hits = [];
  for (const entry of catalog || []) {
    if (repoOf(entry.src) === repo) hits.push(entry);
  }
  if (!hits.length) return null;
  for (const entry of hits) if (entry.file === item.file) return entry;
  for (const entry of hits) if (/ps5/i.test(entry.file)) return entry;
  return hits[0];
}

function readUpdateRaw() {
  try {
    const raw = JSON.parse(localStorage.getItem(UPDATE_KEY) || "null");
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
    return raw;
  } catch (error) {
    return {};
  }
}

function loadVersionUpdates() {
  const raw = readUpdateRaw();
  const out = {};
  for (const item of ELF_ITEMS) {
    const upd = raw[item.id];
    if (!upd || typeof upd !== "object" || upd.library !== true) continue;
    const ver = normalizeVer(upd.ver);
    if (!ver || ver === normalizeVer(item.ver)) continue;
    out[item.id] = { ver, library: true };
  }
  return out;
}

function withVersion(item) {
  if (!item || item.extra) return item;
  const upd = loadVersionUpdates()[item.id];
  if (!upd) return item;
  return Object.assign({}, item, { ver: upd.ver, library: true });
}

/** 对照目录，算出要换版本的内置项。不写本地记录，也不下载。 */
export function planVersionUpdates(catalog) {
  const changes = [];
  for (const item of ELF_ITEMS) {
    if (item.release) continue;
    const hit = matchCatalogEntry(item, catalog);
    if (!hit || !FILE_NAME.test(hit.file || "")) continue;
    const remoteVer = normalizeVer(hit.ver);
    if (!remoteVer) continue;
    const current = withVersion(item);
    if (remoteVer === normalizeVer(current.ver)) continue;
    changes.push({
      id: item.id,
      name: item.name,
      from: current.ver,
      to: remoteVer,
      remoteFile: hit.file,
      saveAs: item.file,
      revert: remoteVer === normalizeVer(item.ver),
    });
  }
  return changes;
}

/** 仍在列表里、并且自己声明了 GitHub 发行版的内置项。 */
export function listedReleaseItems(order) {
  const ids = order || [];
  const out = [];
  for (const item of ELF_ITEMS) {
    if (!item.release || ids.indexOf(item.id) < 0) continue;
    out.push({ id: item.id, repo: item.release.repo, asset: item.release.asset });
  }
  return out;
}

/**
 * 对照一次 GitHub latest。版本相同返回 null。
 * 版本不同但附件对不上文件名时返回 {missing:true}，调用方不要下载。
 */
export function planReleaseUpdate(id, release) {
  const builtin = ELF_ITEMS.find((item) => item.id === id);
  if (!builtin || !builtin.release || !release) return null;
  const tag = String(release.tag || "");
  const version = normalizeVer(release.version || tag);
  if (!version || !/^v?[A-Za-z0-9._-]+$/.test(tag)) return null;
  const asset = String(builtin.release.asset || "").split("{tag}").join(tag);
  if (!FILE_NAME.test(asset)) return null;
  const current = withVersion(builtin);
  if (version === normalizeVer(current.ver)) return null;
  const names = [];
  for (const item of release.assets || []) {
    if (item && typeof item.name === "string") names.push(item.name);
  }
  if (names.indexOf(asset) < 0) return { id: builtin.id, name: builtin.name, missing: true };
  return {
    id: builtin.id,
    name: builtin.name,
    from: current.ver,
    to: version,
    repo: builtin.release.repo,
    tag,
    asset,
    saveAs: builtin.file,
    revert: version === normalizeVer(builtin.ver),
  };
}

/** 下载成功后才写入。版本回到随仓库发布的号时，清掉 library 标记。 */
export function commitVersionUpdates(applied) {
  const raw = readUpdateRaw();
  for (const change of applied || []) {
    const builtin = ELF_ITEMS.find((item) => item.id === change.id);
    if (!builtin) continue;
    const ver = normalizeVer(change.to);
    if (!ver || ver === normalizeVer(builtin.ver)) delete raw[change.id];
    else raw[change.id] = { ver, library: true };
  }
  try { localStorage.setItem(UPDATE_KEY, JSON.stringify(raw)); } catch (error) {}
}

function clip(value, max) {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
}

function normalizeExtra(raw) {
  const file = raw && typeof raw.file === "string" ? raw.file : "";
  if (!FILE_NAME.test(file)) return null;
  if (ELF_ITEMS.some((item) => item.file === file)) return null;
  return {
    id: "ext:" + file,
    file,
    name: clip(raw.name || file, 80),
    ver: clip(raw.ver || "", 32),
    role: "目录",
    desc: clip(raw.desc || "", 180),
    author: clip(raw.author || "", 80),
    extra: true,
    library: raw.library === true,
    on: true,
  };
}

export function loadExtras() {
  try {
    const raw = JSON.parse(localStorage.getItem(EXTRA_KEY) || "[]");
    if (!Array.isArray(raw)) return [];
    const seen = new Set();
    const out = [];
    for (const item of raw) {
      const next = normalizeExtra(item);
      if (!next || seen.has(next.id)) continue;
      seen.add(next.id);
      out.push(next);
    }
    return out;
  } catch (error) {
    return [];
  }
}

function saveExtras(items) {
  try {
    localStorage.setItem(EXTRA_KEY, JSON.stringify(items.map((item) => ({
      file: item.file,
      name: item.name,
      ver: item.ver,
      desc: item.desc,
      author: item.author,
      library: item.library === true,
    }))));
  } catch (error) { /* 无痕模式等存不进就算了 */ }
}

export function addExtra(plan, entry) {
  const item = normalizeExtra(entry);
  if (!item) return null;
  const extras = loadExtras();
  const idx = extras.findIndex((extra) => extra.id === item.id);
  if (idx < 0) extras.push(item);
  else extras[idx] = item;
  saveExtras(extras);
  if (plan.order.indexOf(item.id) < 0) plan.order.push(item.id);
  plan.off.delete(item.id);
  savePlan(plan);
  return item;
}

/** 和内置 ELF 同名时加回那一项。其他文件作为已下载到本站的条目。 */
export function addCatalogEntry(plan, entry) {
  const file = entry && typeof entry.file === "string" ? entry.file : "";
  const builtin = ELF_ITEMS.find((item) => item.file === file);
  if (builtin) {
    const already = plan.order.indexOf(builtin.id) >= 0;
    if (plan.gone) plan.gone.delete(builtin.id);
    if (!already) {
      plan.order.push(builtin.id);
      plan.off.delete(builtin.id);
      savePlan(plan);
    }
    return { item: itemById(builtin.id), already };
  }
  const existing = loadExtras().find((extra) => extra.file === file);
  if (existing && plan.order.indexOf(existing.id) >= 0) {
    return { item: itemById(existing.id), already: true };
  }
  const item = addExtra(plan, entry);
  return item ? { item, already: false } : null;
}

function textOf(item) {
  return [item.name, item.file, item.desc, item.ver, item.author, item.src].join(" ").toLowerCase();
}

/** 内置三项（不看固件）排在前面，同仓库或同文件名的目录条目去掉。 */
export function searchWithPinned(catalog, query, fw) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return [];
  const pinnedFiles = new Set();
  const pinnedRepos = new Set();
  const pinned = [];
  for (const item of ELF_ITEMS) {
    const shown = withVersion(item);
    pinnedFiles.add(item.file);
    const repo = repoOf(item.src);
    if (repo) pinnedRepos.add(repo);
    if (textOf(shown).indexOf(q) < 0) continue;
    pinned.push({
      file: shown.file,
      name: shown.name,
      desc: shown.desc,
      author: "",
      ver: shown.ver,
      src: shown.src,
      firmwares: [],
      pinned: true,
    });
  }
  const out = pinned.slice(0, SEARCH_LIMIT);
  for (const entry of catalog || []) {
    if (out.length >= SEARCH_LIMIT) break;
    if (!firmwareMatches(entry, fw)) continue;
    if (pinnedFiles.has(entry.file)) continue;
    const repo = repoOf(entry.src);
    if (repo && pinnedRepos.has(repo)) continue;
    const hay = [entry.name, entry.file, entry.author, entry.desc].join(" ").toLowerCase();
    if (hay.indexOf(q) < 0) continue;
    out.push(entry);
  }
  return out;
}

export function removeFromPlan(plan, id) {
  if (!id) return;
  if (String(id).indexOf("ext:") === 0) {
    saveExtras(loadExtras().filter((item) => item.id !== id));
  } else if (defaultPlan().indexOf(id) >= 0) {
    if (!plan.gone) plan.gone = new Set();
    plan.gone.add(id);
  } else {
    return;
  }
  plan.order = plan.order.filter((itemId) => itemId !== id);
  plan.off.delete(id);
  savePlan(plan);
}

/** 仅用于没有本地记录时的默认顺序：panplay 排在最后。 */
function ensurePanplayLast(order) {
  const i = order.indexOf("panplay");
  if (i < 0 || i === order.length - 1) return order;
  const next = order.slice();
  next.splice(i, 1);
  next.push("panplay");
  return next;
}

export function defaultPlan() {
  return ELF_ITEMS.map((item) => item.id);
}

export function itemById(id) {
  for (const item of ELF_ITEMS) if (item.id === id) return withVersion(item);
  for (const item of loadExtras()) if (item.id === id) return item;
  return null;
}

export function itemByFile(file) {
  for (const item of ELF_ITEMS) if (item.file === file) return withVersion(item);
  for (const item of loadExtras()) if (item.file === file) return item;
  return null;
}

export function loadPlan() {
  const extraIds = loadExtras().map((item) => item.id);
  const builtinIds = defaultPlan();
  let order = builtinIds.slice();
  const off = new Set();
  for (const item of ELF_ITEMS) {
    if (item.on === false) off.add(item.id);
  }
  let goneList = [];
  let saved = false;
  try {
    const raw = JSON.parse(localStorage.getItem(PLAN_KEY) || "null");
    if (raw && Array.isArray(raw.gone)) {
      goneList = raw.gone.filter((id) => builtinIds.indexOf(id) >= 0);
    }
    const visibleIds = builtinIds.filter((id) => goneList.indexOf(id) < 0);
    if (raw && Array.isArray(raw.order)) {
      saved = true;
      const known = visibleIds.concat(extraIds);
      const kept = raw.order.filter((id) => known.indexOf(id) >= 0);
      const appended = [];
      for (const id of known) {
        if (kept.indexOf(id) < 0) {
          kept.push(id);
          appended.push(id);
        }
      }
      order = kept;
      if (Array.isArray(raw.off)) {
        off.clear();
        for (const id of raw.off) if (known.indexOf(id) >= 0) off.add(id);
      }
      for (const id of appended) if (String(id).indexOf("ext:") === 0) off.add(id);
    }
  } catch (error) { /* 损坏则回落默认 */ }
  if (!saved) {
    order = ensurePanplayLast(order);
    for (const id of extraIds) {
      order.push(id);
      off.add(id);
    }
  }
  order = order.filter((id) => goneList.indexOf(id) < 0);
  return { order, off, gone: new Set(goneList) };
}

export function savePlan(plan) {
  try {
    const gone = plan.gone ? Array.from(plan.gone) : [];
    localStorage.setItem(PLAN_KEY, JSON.stringify({
      order: plan.order,
      off: Array.from(plan.off),
      gone,
    }));
  } catch (error) { /* 无痕模式等存不进就算了 */ }
}

export function resetPlan() {
  try { localStorage.removeItem(PLAN_KEY); } catch (error) {}
  return loadPlan();
}

export function formatSize(bytes) {
  if (!bytes) return "";
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + " MB";
  return Math.round(bytes / 1024) + " KB";
}
