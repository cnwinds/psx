#!/usr/bin/env python3
"""对照 GitHub Release 检查/同步 payloads/ 与 elfplan.js 版本（默认走 gh-proxy）。

  python scripts/sync_payloads.py --check
  python scripts/sync_payloads.py --sync
  python scripts/sync_payloads.py --sync smp websrv
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ELFPLAN_PATH = os.path.join(ROOT, "src", "elfplan.js")
PAYLOAD_DIR = os.path.join(ROOT, "payloads")
GITHUB_API = "https://api.github.com"
DEFAULT_GH_PROXY = "https://gh-proxy.com/"

# id 对应 elfplan.js；asset 为 release 文件名，{tag} 替换 tag_name
SPECS = [
    {
        "id": "kstuff",
        "repo": "EchoStretch/kstuff-lite",
        "file": "kstuff.elf",
        "asset": "kstuff.elf",
    },
    {
        "id": "ftpsrv",
        "repo": "ps5-payload-dev/ftpsrv",
        "file": "ftpsrv.elf",
        "asset": "ftpsrv-ps5.elf",
    },
    {
        "id": "panplay",
        "repo": "cnwinds/pan-play",
        "file": "panplay.elf",
        "asset": "panplay-{tag}-ps5.elf",
    },
    {
        "id": "smp",
        "repo": "drakmor/ShadowMountPlus",
        "file": "shadowmountplus.elf",
        "asset": "shadowmountplus.elf",
    },
    {
        "id": "websrv",
        "repo": "ps5-payload-dev/websrv",
        "file": "websrv.elf",
        "asset": "websrv-ps5.elf",
    },
]


def gh_proxy_prefix() -> str:
    raw = os.environ.get("GH_PROXY", DEFAULT_GH_PROXY).strip()
    if not raw:
        return ""
    return raw if raw.endswith("/") else raw + "/"


def mirror_urls(url: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    prefix = gh_proxy_prefix()
    if prefix:
        out.append(prefix + url)
    if not prefix or prefix != DEFAULT_GH_PROXY:
        out.append(DEFAULT_GH_PROXY + url)
    out.append(url)
    deduped: list[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


def _opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_json(url: str) -> dict:
    last: Exception | None = None
    for candidate in mirror_urls(url):
        req = urllib.request.Request(
            candidate,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "psx-sync-payloads"},
        )
        try:
            with _opener().open(req, timeout=90) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last = e
    raise urllib.error.URLError(last)  # type: ignore[arg-type]


def latest_release(repo: str) -> dict:
    return http_json(f"{GITHUB_API}/repos/{repo}/releases/latest")


def normalize_version(tag: str) -> str:
    return tag.lstrip("vV")


def read_elfplan_entry(entry_id: str) -> tuple[str, int] | None:
    with open(ELFPLAN_PATH, encoding="utf-8") as f:
        text = f.read()
    block = re.search(
        rf'id: "{re.escape(entry_id)}",.*?ver: "([^"]+)".*?size: (\d+)',
        text,
        re.DOTALL,
    )
    if not block:
        return None
    return block.group(1), int(block.group(2))


def patch_elfplan(entry_id: str, version: str, size: int) -> bool:
    with open(ELFPLAN_PATH, encoding="utf-8") as f:
        text = f.read()
    block = re.search(
        rf'(\{{\s*\n\s*id: "{re.escape(entry_id)}",.*?\n\s*\}},)',
        text,
        re.DOTALL,
    )
    if not block:
        return False
    chunk = block.group(1)
    chunk = re.sub(r'(\n\s*ver: ")[^"]+(")', rf"\g<1>{version}\2", chunk, count=1)
    chunk = re.sub(r"(\n\s*size: )\d+(,)", rf"\g<1>{size}\2", chunk, count=1)
    text = text[: block.start(1)] + chunk + text[block.end(1) :]
    with open(ELFPLAN_PATH, "w", encoding="utf-8") as f:
        f.write(text)
    return True


def asset_url(repo: str, tag: str, asset_template: str) -> str:
    name = asset_template.replace("{tag}", tag)
    return f"https://github.com/{repo}/releases/download/{tag}/{name}"


def find_asset(release: dict, asset_name: str) -> dict | None:
    for a in release.get("assets", []):
        if a.get("name") == asset_name:
            return a
    return None


def download(url: str, dest: str) -> int:
    last: Exception | None = None
    for candidate in mirror_urls(url):
        req = urllib.request.Request(candidate, headers={"User-Agent": "psx-sync-payloads"})
        try:
            with _opener().open(req, timeout=600) as resp:
                data = resp.read()
            if len(data) < 1024 or data[:4] != b"\x7fELF":
                raise ValueError(f"无效 ELF ({len(data)} B)")
            tmp = dest + ".part"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, dest)
            return len(data)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
            last = e
    raise urllib.error.URLError(last)  # type: ignore[arg-type]


def inspect_spec(spec: dict) -> dict:
    rel = latest_release(spec["repo"])
    tag = rel["tag_name"]
    asset_name = spec["asset"].replace("{tag}", tag)
    asset = find_asset(rel, asset_name)
    local_path = os.path.join(PAYLOAD_DIR, spec["file"])
    local_size = os.path.getsize(local_path) if os.path.isfile(local_path) else 0
    plan = read_elfplan_entry(spec["id"])
    plan_ver, plan_size = plan if plan else ("?", 0)
    remote_size = asset["size"] if asset else 0
    remote_ver = normalize_version(tag)
    file_ok = asset is not None and local_size == remote_size and local_size > 0
    if plan is None:
        up_to_date = file_ok
    else:
        up_to_date = file_ok and plan_ver == remote_ver and plan_size == remote_size
    return {
        "id": spec["id"],
        "repo": spec["repo"],
        "tag": tag,
        "asset_name": asset_name,
        "remote_size": remote_size,
        "local_size": local_size,
        "plan_ver": plan_ver,
        "plan_size": plan_size,
        "ok": up_to_date,
        "asset_meta": asset,
    }


def sync_spec(spec: dict, info: dict) -> None:
    asset = info.get("asset_meta")
    if not asset:
        print(f"  跳过 {spec['id']}：发行版无 {spec['asset']}")
        return
    dest = os.path.join(PAYLOAD_DIR, spec["file"])
    url = asset["browser_download_url"]
    print(f"  下载 {spec['id']} {info['tag']} …")
    size = download(url, dest)
    ver = normalize_version(info["tag"])
    if patch_elfplan(spec["id"], ver, size):
        print(f"  已更新 {spec['file']} ({size} B) → elfplan ver={ver}")
    else:
        print(f"  已更新 {spec['file']} ({size} B)")


def main() -> None:
    parser = argparse.ArgumentParser(description="检查/同步上游 payload 发行版")
    parser.add_argument("--check", action="store_true", help="只对照 latest release，不下载")
    parser.add_argument("--sync", action="store_true", help="将落后项更新到 latest")
    parser.add_argument("ids", nargs="*", help="仅处理这些 id（默认全部）")
    args = parser.parse_args()
    if not args.check and not args.sync:
        args.check = True

    wanted = {s["id"]: s for s in SPECS}
    ids = args.ids or list(wanted.keys())
    rows = []
    for pid in ids:
        if pid not in wanted:
            raise SystemExit(f"未知 id: {pid}")
        spec = wanted[pid]
        try:
            info = inspect_spec(spec)
        except urllib.error.URLError as e:
            print(f"{pid}: 无法查询上游 ({e})")
            continue
        status = "OK" if info["ok"] else "需更新"
        rows.append((spec, info, status))
        print(
            f"{pid:8} {status:4}  upstream={info['tag']} ({info['remote_size']} B)  "
            f"local={info['local_size']} B  elfplan={info['plan_ver']}/{info['plan_size']}"
        )
        if args.sync and not info["ok"]:
            sync_spec(spec, info)

    if args.check and not args.sync:
        stale = [r[0]["id"] for r in rows if r[2] != "OK"]
        if stale:
            print("\n落后项:", ", ".join(stale), "→ 运行: python scripts/sync_payloads.py --sync")


if __name__ == "__main__":
    main()
