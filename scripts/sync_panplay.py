#!/usr/bin/env python3
"""拉取 cnwinds/pan-play 发行包并更新 payloads/panplay.elf 与 elfplan.js 中的版本/大小。

示例:
  python scripts/sync_panplay.py
  python scripts/sync_panplay.py --tag v0.11.1
  python scripts/sync_panplay.py --url 'https://github.com/.../panplay-v0.11.2-ps5.elf' --version 0.11.2
  python scripts/sync_panplay.py --file /path/to/panplay.elf --version 0.11.2 --readme
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ELF_PATH = os.path.join(ROOT, "payloads", "panplay.elf")
ELFPLAN_PATH = os.path.join(ROOT, "src", "elfplan.js")
README_PATH = os.path.join(ROOT, "README.md")
REPO = "cnwinds/pan-play"
GITHUB_API = "https://api.github.com"
DEFAULT_GH_PROXY = "https://gh-proxy.com/"


def gh_proxy_prefix() -> str:
    raw = os.environ.get("GH_PROXY", DEFAULT_GH_PROXY).strip()
    if not raw:
        return ""
    return raw if raw.endswith("/") else raw + "/"


def mirror_urls(url: str) -> list[str]:
    """GitHub 直连不稳定时依次尝试 GH_PROXY 镜像与原始 URL。"""
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
            headers={"Accept": "application/vnd.github+json", "User-Agent": "psx-sync-panplay"},
        )
        try:
            with _opener().open(req, timeout=90) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last = e
            print(f"  API 失败: {candidate} ({e})")
    raise SystemExit(f"无法访问 GitHub API: {last}") from last


def download(url: str, dest: str) -> int:
    last: Exception | None = None
    for candidate in mirror_urls(url):
        print(f"  尝试 {candidate}")
        req = urllib.request.Request(candidate, headers={"User-Agent": "psx-sync-panplay"})
        try:
            with _opener().open(req, timeout=600) as resp:
                data = resp.read()
            if len(data) < 1024 or data[:4] != b"\x7fELF":
                raise ValueError(f"不是有效 ELF（{len(data)} 字节）")
            tmp = dest + ".part"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, dest)
            if candidate != url:
                print(f"  （经镜像下载成功）")
            return len(data)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
            last = e
            print(f"  失败: {e}")
    raise urllib.error.URLError(last)  # type: ignore[arg-type]


def normalize_version(tag: str) -> str:
    return tag.lstrip("vV")


def asset_name(tag_name: str) -> str:
    return f"panplay-{tag_name}-ps5.elf"


def release_url(tag_name: str) -> str:
    return f"https://github.com/{REPO}/releases/download/{tag_name}/{asset_name(tag_name)}"


def resolve_tag(tag: str) -> str:
    if tag not in ("", "latest"):
        return tag if tag.startswith("v") else f"v{tag}"
    try:
        rel = http_json(f"{GITHUB_API}/repos/{REPO}/releases/latest")
        return rel["tag_name"]
    except SystemExit:
        raise
    except (urllib.error.URLError, urllib.error.HTTPError):
        raise SystemExit("无法访问 GitHub API 获取 latest；请指定 --tag vX.Y.Z 或使用 --url / --file") from None


def patch_elfplan(version: str, size: int) -> None:
    with open(ELFPLAN_PATH, encoding="utf-8") as f:
        text = f.read()
    if 'id: "panplay"' not in text:
        raise SystemExit("elfplan.js 中未找到 panplay 条目，请先添加 ELF_ITEMS 配置")
    block = re.search(
        r'(\{\s*\n\s*id: "panplay",.*?\n\s*\},)',
        text,
        re.DOTALL,
    )
    if not block:
        raise SystemExit("无法解析 elfplan.js 中的 panplay 块")
    chunk = block.group(1)
    chunk = re.sub(r'(\n\s*ver: ")[^"]+(")', rf"\g<1>{version}\2", chunk, count=1)
    chunk = re.sub(r"(\n\s*size: )\d+(,)", rf"\g<1>{size}\2", chunk, count=1)
    text = text[: block.start(1)] + chunk + text[block.end(1) :]
    with open(ELFPLAN_PATH, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"elfplan.js: panplay ver={version} size={size}")


def update_readme(version: str) -> None:
    if not os.path.isfile(README_PATH):
        return
    with open(README_PATH, encoding="utf-8") as f:
        text = f.read()
    text = re.sub(
        r"(\[cnwinds/pan-play\]\([^)]+\)) v[\d.]+",
        rf"\1 v{version}",
        text,
        count=1,
    )
    with open(README_PATH, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"README: panplay 版本行 → v{version}")


def apply(version: str, size: int, touch_readme: bool) -> None:
    patch_elfplan(version, size)
    if touch_readme:
        update_readme(version)


def main() -> None:
    parser = argparse.ArgumentParser(description="同步 panplay PS5 ELF 与 elfplan 元数据")
    parser.add_argument("--tag", default="latest", help="GitHub release 标签，默认 latest")
    parser.add_argument("--url", metavar="URL", help="直链下载（需 --version）")
    parser.add_argument("--file", metavar="PATH", help="本地 ELF（需 --version）")
    parser.add_argument("--version", metavar="VER", help="--url / --file 时写入的版本号")
    parser.add_argument("--readme", action="store_true", help="同步 README 表格中的 panplay 版本")
    args = parser.parse_args()

    if args.file:
        if not args.version:
            raise SystemExit("--file 需要 --version")
        with open(args.file, "rb") as f:
            blob = f.read()
        tmp = ELF_PATH + ".part"
        with open(tmp, "wb") as f:
            f.write(blob)
        os.replace(tmp, ELF_PATH)
        apply(normalize_version(args.version), len(blob), args.readme)
        print(f"已写入 {ELF_PATH} ({len(blob)} 字节)")
        return

    if args.url:
        if not args.version:
            raise SystemExit("--url 需要 --version")
        print(f"下载 {args.url} …")
        size = download(args.url, ELF_PATH)
        apply(normalize_version(args.version), size, args.readme)
        print(f"已写入 {ELF_PATH} ({size} 字节)")
        return

    tag_name = resolve_tag(args.tag)
    url = release_url(tag_name)
    print(f"下载 {REPO} {tag_name} …")
    print(f"  {url}")
    try:
        size = download(url, ELF_PATH)
    except urllib.error.URLError as e:
        raise SystemExit(f"下载失败: {e}") from e
    version = normalize_version(tag_name)
    apply(version, size, args.readme)
    print(f"已写入 {ELF_PATH} ({size} 字节)")


if __name__ == "__main__":
    main()
