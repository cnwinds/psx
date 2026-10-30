// 远端 ELF 目录。页面只读同源的 payloads/payload_map.js：
// 自建主机能联网时由服务端回源 http://45.56.67.85/payloads/payload_map.js，
// 失败或静态托管（GitHub Pages）时用仓库里的快照。不执行这份脚本。
// 加入或更新时由本站把 ELF 下载到 payloads/library。之后 elfldr 只向本站要文件。

export const CATALOG_HOST = "45.56.67.85";

const MAP_HREF = new URL("../payloads/payload_map.js", import.meta.url);
const FILE_OK = /^[A-Za-z0-9._-]+$/;

export function catalogPayloadUrl(file) {
  if (!FILE_OK.test(file) || !/\.(elf|bin)$/i.test(file)) throw new Error("非法 payload 文件名");
  return "http://" + CATALOG_HOST + "/payloads/payloads/" + encodeURIComponent(file);
}

function unquote(raw) {
  try { return JSON.parse('"' + raw + '"'); } catch (error) { return raw; }
}

function activeLines(block) {
  return block.split("\n").filter((line) => !/^\s*\/\//.test(line)).join("\n");
}

function readString(block, key) {
  const matched = block.match(new RegExp("\\b" + key + "\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\""));
  return matched ? unquote(matched[1]) : "";
}

function readStringList(block, key) {
  const matched = block.match(new RegExp("\\b" + key + "\\s*:\\s*\\[([\\s\\S]*?)\\]"));
  if (!matched) return [];
  const out = [];
  for (const item of matched[1].matchAll(/"((?:\\.|[^"\\])*)"/g)) out.push(unquote(item[1]));
  return out;
}

/** 从 payload_map.js 文本抽出可加载条目。注释掉的、没有文件名的、customAction 都丢掉。 */
export function parsePayloadMap(src) {
  const text = String(src || "").replace(/\r\n/g, "\n");
  const parts = text.split(/\n {4}\{/);
  const items = [];
  const seen = new Set();
  for (let i = 1; i < parts.length; i++) {
    const block = activeLines(parts[i]);
    if (/customAction\s*:/.test(block)) continue;
    const file = readString(block, "fileName");
    if (!FILE_OK.test(file) || !/\.(elf|bin)$/i.test(file) || seen.has(file)) continue;
    seen.add(file);
    items.push({
      file,
      name: readString(block, "displayTitle") || file,
      desc: readString(block, "description"),
      author: readString(block, "author"),
      ver: readString(block, "version"),
      src: readString(block, "projectSource"),
      firmwares: readStringList(block, "supportedFirmwares"),
    });
  }
  return items;
}

/** 空固件列表表示全部可用。fw 未知时不过滤，方便在电脑上查找。 */
export function firmwareMatches(item, fw) {
  const list = item && item.firmwares || [];
  const version = String(fw || "").trim();
  if (!list.length || !version) return true;
  return list.some((prefix) => version.startsWith(prefix));
}

export function searchCatalog(items, query, fw) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return [];
  const out = [];
  for (const item of items || []) {
    if (!firmwareMatches(item, fw)) continue;
    const hay = (item.name + " " + item.file + " " + item.author + " " + item.desc).toLowerCase();
    if (hay.indexOf(q) < 0) continue;
    out.push(item);
    if (out.length >= 8) break;
  }
  return out;
}

const STORE_NAME = /^[A-Za-z0-9._-]+\.(elf|bin)$/i;

/** 本站保存接口。save 仅用于把目录文件写成内置文件名（如 kstuff.elf）。 */
export function payloadStoreUrl(file, save, refresh, pageHref) {
  if (!STORE_NAME.test(file || "")) throw new Error("无法保存到本站");
  if (save && !STORE_NAME.test(save)) throw new Error("无法保存到本站");
  const href = pageHref || (typeof location !== "undefined" ? location.href : "http://127.0.0.1/");
  const page = new URL(href);
  if (!page.pathname.endsWith("/") && !/\.html?$/i.test(page.pathname)) page.pathname += "/";
  const url = new URL("api/payload/fetch", page);
  url.search = "";
  url.searchParams.set("file", file);
  if (save) url.searchParams.set("save", save);
  if (refresh) url.searchParams.set("refresh", "1");
  return url.href;
}

export async function savePayloadToHost(file, save, refresh, fetchImpl, pageHref) {
  const doFetch = fetchImpl || fetch;
  const res = await doFetch(payloadStoreUrl(file, save, refresh, pageHref), { cache: "no-store" });
  let data = null;
  try { data = await res.json(); } catch (error) { data = null; }
  const expect = "library/" + (save || file);
  if (!res.ok || !data || data.file !== expect) throw new Error("无法保存到本站");
  return data;
}

function storePage(pageHref) {
  const href = pageHref || (typeof location !== "undefined" ? location.href : "http://127.0.0.1/");
  const page = new URL(href);
  if (!page.pathname.endsWith("/") && !/\.html?$/i.test(page.pathname)) page.pathname += "/";
  return page;
}

export function githubReleaseUrl(repo, pageHref) {
  const url = new URL("api/payload/release", storePage(pageHref));
  url.search = "";
  url.searchParams.set("repo", repo);
  return url.href;
}

export async function loadGithubRelease(repo, fetchImpl, pageHref) {
  const doFetch = fetchImpl || fetch;
  const res = await doFetch(githubReleaseUrl(repo, pageHref), { cache: "no-store" });
  let data = null;
  try { data = await res.json(); } catch (error) { data = null; }
  if (!res.ok || !data || typeof data.tag !== "string" || typeof data.version !== "string" || !Array.isArray(data.assets)) {
    throw new Error("无法检查更新");
  }
  return data;
}

export async function saveReleaseAsset(repo, tag, file, save, refresh, fetchImpl, pageHref) {
  if (!STORE_NAME.test(file || "")) throw new Error("无法保存到本站");
  if (save && !STORE_NAME.test(save)) throw new Error("无法保存到本站");
  const url = new URL("api/payload/fetch", storePage(pageHref));
  url.search = "";
  url.searchParams.set("repo", repo);
  url.searchParams.set("tag", tag);
  url.searchParams.set("file", file);
  if (save) url.searchParams.set("save", save);
  if (refresh) url.searchParams.set("refresh", "1");
  const doFetch = fetchImpl || fetch;
  const res = await doFetch(url.href, { cache: "no-store" });
  let data = null;
  try { data = await res.json(); } catch (error) { data = null; }
  const expect = "library/" + (save || file);
  if (!res.ok || !data || data.file !== expect) throw new Error("无法保存到本站");
  return data;
}

export async function loadCatalog(fetchImpl) {
  const doFetch = fetchImpl || fetch;
  const res = await doFetch(MAP_HREF, { cache: "no-store" });
  if (!res.ok) throw new Error("目录不可用");
  const items = parsePayloadMap(await res.text());
  if (!items.length) throw new Error("目录为空");
  return items;
}
