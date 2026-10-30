// ELF 加载计划：注册表 + 顺序/勾选持久化。
// 幕二（加载 ELF）的单一数据源：site.js 渲染列表，payload_loader.js 按此发送。
// 新增 payload 只需在 ELF_ITEMS 里加一项（如 websrv.elf），UI 与发送链路自动生效。
//
// 默认一键链：kstuff → ftpsrv → panplay（panplay 固定队尾）；ShadowMountPlus / websrv 可选。

export { encodeQRMatrix, renderQRSvg } from "./qrcode.js";

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
    ports: ["2121"],
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
    ports: ["8734"],
    desc: "百度网盘直装（:8734）；与 ShadowMountPlus 勿同时勾选",
    src: "https://github.com/cnwinds/pan-play",
    size: 6720416,
    on: true,
  },
  {
    id: "smp",
    file: "shadowmountplus.elf",
    name: "ShadowMountPlus",
    ver: "1.7beta11",
    role: "挂载",
    desc: "自动扫描挂载 /data/homebrew 与 USB 游戏",
    src: "https://github.com/drakmor/ShadowMountPlus",
    size: 3614944,
    on: false,
  },
  {
    id: "websrv",
    file: "websrv.elf",
    name: "websrv",
    ver: "0.34",
    role: ":8080",
    ports: ["8080"],
    desc: "网页发送器 (:8080)，手机扫码追发任意 payload",
    src: "https://github.com/ps5-payload-dev/websrv",
    size: 1597864,
    on: false,
  },
];

/** 端口存活探测文案；payload_loader 验证日志的唯一来源（勿在别处重复维护端口表）。 */
const ELF_PORT_LABELS = {
  ftpsrv: {
    2121: { name: "ftpsrv FTP", hint: "在幕二勾选 ftpsrv 发送" },
  },
  panplay: {
    8734: { name: "panplay（盘游 / 百度网盘）", hint: "在幕二勾选 panplay 发送" },
  },
  websrv: {
    8080: { name: "websrv（网页发送器）", hint: "在幕二勾选 websrv 发送" },
  },
};

export function probePortInfo() {
  const out = {
    9021: { name: "elfldr（payload 通道）", hint: "已退出，需重启后重跑破解流程" },
  };
  for (const item of ELF_ITEMS) {
    const labels = ELF_PORT_LABELS[item.id];
    if (!labels || !item.ports) continue;
    for (const port of item.ports) {
      const key = String(port);
      const meta = labels[port];
      if (meta) out[key] = meta;
    }
  }
  return out;
}

const PLAN_KEY = "psx.elfplan.v1";

/** 一键加载链约定：panplay 始终排在最后（用户可上移，但默认与修复逻辑保证末尾）。 */
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
  for (const item of ELF_ITEMS) if (item.id === id) return item;
  return null;
}

export function itemByFile(file) {
  for (const item of ELF_ITEMS) if (item.file === file) return item;
  return null;
}

export function loadPlan() {
  // 返回 { order: [id...]（按顺序）, off: Set(id) }；本地存储损坏或缺少新条目时自动修复
  let order = defaultPlan();
  const off = new Set();
  for (const item of ELF_ITEMS) {
    if (item.on === false) off.add(item.id);
  }
  try {
    const raw = JSON.parse(localStorage.getItem(PLAN_KEY) || "null");
    if (raw && Array.isArray(raw.order)) {
      const known = order;
      const kept = raw.order.filter((id) => known.indexOf(id) >= 0);
      for (const id of known) if (kept.indexOf(id) < 0) kept.push(id); // 新增条目排到队尾
      order = kept;
      if (Array.isArray(raw.off)) {
        off.clear();
        for (const id of raw.off) off.add(id);
      }
    }
  } catch (error) { /* 损坏则回落默认 */ }
  order = ensurePanplayLast(order);
  return { order, off };
}

export function savePlan(plan) {
  try {
    localStorage.setItem(PLAN_KEY, JSON.stringify({ order: plan.order, off: Array.from(plan.off) }));
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
