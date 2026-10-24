// ELF 加载计划：注册表 + 顺序/勾选持久化。
// 幕二（加载 ELF）的单一数据源：site.js 渲染列表，payload_loader.js 按此发送。
// 新增 payload 只需在 ELF_ITEMS 里加一项（如 websrv.elf），UI 与发送链路自动生效。

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
    id: "smp",
    file: "shadowmountplus.elf",
    name: "ShadowMountPlus",
    ver: "1.7beta5-fix1",
    role: "挂载",
    desc: "自动扫描挂载 /data/homebrew 与 USB 游戏",
    src: "https://github.com/drakmor/ShadowMountPlus",
    size: 2498376,
    on: true,
  },
  {
    id: "zftpd",
    file: "zftpd.elf",
    name: "zftpd",
    ver: "1.6.0",
    role: ":2120 / :8888",
    ports: ["2120", "8888"],
    desc: "FTP (:2120) + ZHTTP 网页管理 (:8888)",
    src: "https://github.com/seregonwar/zftpd",
    size: 495456,
    on: true,
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
    on: true,
  },
];

const PLAN_KEY = "psx.elfplan.v1";

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
  try {
    const raw = JSON.parse(localStorage.getItem(PLAN_KEY) || "null");
    if (raw && Array.isArray(raw.order)) {
      const known = order;
      const kept = raw.order.filter((id) => known.indexOf(id) >= 0);
      for (const id of known) if (kept.indexOf(id) < 0) kept.push(id); // 新增条目排到队尾
      order = kept;
      if (Array.isArray(raw.off)) for (const id of raw.off) off.add(id);
    }
  } catch (error) { /* 损坏则回落默认 */ }
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
