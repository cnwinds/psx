#!/usr/bin/env python3
"""把 ELF 存进本站 library 目录。

目录条目来自 http://45.56.67.85/payloads/payloads/<文件名>。
带 GitHub 发行版的条目（panplay）向 api.github.com 查 latest，再从
github.com 的 release 下载。原站失败时才走 GH_PROXY。
页面和 elfldr 都不访问这些站点：elfldr 只拿本站 /payloads/library/ 下的副本。
kstuff.elf / ftpsrv.elf / panplay.elf 这三个保存名要和 src/elfplan.js 一致。
"""

import argparse
import json
import os
import re
import sys
import tempfile
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

CATALOG_ELF_ROOT = "http://45.56.67.85/payloads/payloads/"
MAX_BYTES = 32 * 1024 * 1024
NAME = re.compile(r"^[A-Za-z0-9._-]+\.(elf|bin)$")
REPO_NAME = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
TAG_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
RESERVED = {
    "elfldr-ps5-1360.elf",
    "kexp_2026_05_25.bin",
    "payload_map.js",
}
PINNED = {"kstuff.elf", "ftpsrv.elf", "panplay.elf"}


def _proxy_prefix():
    raw = os.environ.get("GH_PROXY", "https://gh-proxy.com/").strip()
    if not raw:
        return ""
    return raw if raw.endswith("/") else raw + "/"


def github_open(url, timeout, headers):
    """先打开 GitHub 原站，失败再用 GH_PROXY。不走环境变量里的 HTTP 代理。"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    candidates = [url]
    prefix = _proxy_prefix()
    if prefix:
        candidates.append(prefix + url)
    last = None
    for candidate in candidates:
        req = urllib.request.Request(candidate, headers=headers)
        try:
            return opener.open(req, timeout=timeout)
        except Exception as error:
            last = error
    raise OSError(last)


def _local_target(remote_name, save_name):
    remote_name = str(remote_name or "")
    if not NAME.fullmatch(remote_name) or remote_name in RESERVED:
        raise ValueError("非法 payload 文件名")
    local_name = remote_name if not save_name else str(save_name)
    if not NAME.fullmatch(local_name) or local_name in RESERVED:
        raise ValueError("非法 payload 文件名")
    if local_name != remote_name and local_name not in PINNED:
        raise ValueError("非法 payload 文件名")
    return local_name


def _library_file(library_dir, local_name):
    library_real = os.path.realpath(library_dir)
    os.makedirs(library_real, exist_ok=True)
    final = os.path.join(library_real, local_name)
    if os.path.dirname(os.path.realpath(final)) != library_real or os.path.islink(final):
        raise ValueError("非法 payload 文件名")
    return library_real, final


def _store_response(library_dir, remote_name, save_name, refresh, open_response):
    local_name = _local_target(remote_name, save_name)
    library_real, final = _library_file(library_dir, local_name)
    if os.path.isfile(final) and not refresh:
        return local_name, os.path.getsize(final)
    fd, part = tempfile.mkstemp(prefix="." + local_name + ".", suffix=".part", dir=library_real)
    try:
        with os.fdopen(fd, "wb") as out:
            with open_response() as resp:
                if getattr(resp, "status", 200) != 200:
                    raise OSError("下载失败")
                total = 0
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_BYTES:
                        raise OSError("文件过大")
                    out.write(chunk)
        if total < 4:
            raise OSError("文件过小")
        with open(part, "rb") as fh:
            magic = fh.read(4)
        if local_name.lower().endswith(".elf") and magic != b"\x7fELF":
            raise OSError("不是 ELF")
        os.replace(part, final)
    except Exception:
        try:
            os.remove(part)
        except OSError:
            pass
        raise
    return local_name, os.path.getsize(final)


def save_catalog_payload(library_dir, remote_name, save_name=None, refresh=False):
    url = CATALOG_ELF_ROOT + quote(str(remote_name or ""))

    def open_response():
        req = urllib.request.Request(url, headers={"User-Agent": "psx-payload", "Accept": "*/*"})
        return urllib.request.urlopen(req, timeout=60)

    return _store_response(library_dir, remote_name, save_name, refresh, open_response)


def latest_release(repo):
    repo = str(repo or "")
    if not REPO_NAME.fullmatch(repo):
        raise ValueError("非法仓库")
    url = "https://api.github.com/repos/%s/releases/latest" % repo
    with github_open(url, 20, {
        "Accept": "application/vnd.github+json",
        "User-Agent": "psx-payload",
    }) as resp:
        if getattr(resp, "status", 200) != 200:
            raise OSError("无法检查更新")
        raw = resp.read(1024 * 1024)
    data = json.loads(raw.decode("utf-8"))
    tag = str(data.get("tag_name") or "")
    if not TAG_NAME.fullmatch(tag):
        raise OSError("没有发行版")
    assets = []
    for asset in data.get("assets") or []:
        name = str(asset.get("name") or "")
        if NAME.fullmatch(name) and name not in RESERVED:
            assets.append({"name": name, "size": int(asset.get("size") or 0)})
    version = tag[1:] if tag[:1] in ("v", "V") else tag
    return {"tag": tag, "version": version, "assets": assets}


def save_github_release(library_dir, repo, tag, asset, save_name=None, refresh=False):
    repo = str(repo or "")
    tag = str(tag or "")
    if not REPO_NAME.fullmatch(repo) or not TAG_NAME.fullmatch(tag):
        raise ValueError("非法 payload 文件名")
    url = "https://github.com/%s/releases/download/%s/%s" % (repo, quote(tag), quote(str(asset or "")))

    def open_response():
        return github_open(url, 90, {"User-Agent": "psx-payload", "Accept": "*/*"})

    return _store_response(library_dir, asset, save_name, refresh, open_response)


def serve(bind, library_dir):
    host, sep, port = bind.rpartition(":")
    if not sep or not port.isdigit():
        raise SystemExit("bind 需要 host:port")
    library_dir = os.path.abspath(library_dir)
    os.makedirs(library_dir, exist_ok=True)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlsplit(self.path)
            qs = parse_qs(parsed.query)
            if parsed.path == "/api/payload/release":
                try:
                    info = latest_release((qs.get("repo") or [""])[0])
                except ValueError as error:
                    self._json(400, {"error": str(error)})
                    return
                except Exception as error:
                    sys.stderr.write("payload release failed: %s\n" % error)
                    self._json(502, {"error": "无法检查更新"})
                    return
                self._json(200, info)
                return
            if parsed.path != "/api/payload/fetch":
                self._json(404, {"error": "未知接口"})
                return
            remote = (qs.get("file") or [""])[0]
            save = (qs.get("save") or [None])[0] or None
            refresh = (qs.get("refresh") or ["0"])[0] in ("1", "true", "yes")
            repo = (qs.get("repo") or [""])[0]
            tag = (qs.get("tag") or [""])[0]
            try:
                if repo:
                    name, size = save_github_release(library_dir, repo, tag, remote, save, refresh)
                else:
                    name, size = save_catalog_payload(library_dir, remote, save, refresh)
            except ValueError as error:
                self._json(400, {"error": str(error)})
                return
            except Exception as error:
                sys.stderr.write("payload save failed: %s\n" % error)
                self._json(502, {"error": "无法保存到本站"})
                return
            self._json(200, {"file": "library/" + name, "size": size})

        def _json(self, code, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            sys.stderr.write("payload-store: " + (fmt % args) + "\n")

    httpd = ThreadingHTTPServer((host, int(port)), Handler)
    sys.stderr.write("payload-store listening on %s root %s\n" % (bind, library_dir))
    httpd.serve_forever()


def self_test():
    import shutil

    original = urllib.request.urlopen
    directory = tempfile.mkdtemp()
    try:
        final = os.path.join(directory, "kstuff.elf")
        with open(final, "wb") as fh:
            fh.write(b"\x7fELF" + b"\0" * 8)

        def boom(*args, **kwargs):
            raise AssertionError("network")

        urllib.request.urlopen = boom
        name, size = save_catalog_payload(directory, "kstuff-lite.elf", "kstuff.elf", False)
        if (name, size) != ("kstuff.elf", 12):
            raise SystemExit("cache miss %s %s" % (name, size))
        bad = [
            ("../x.elf", None),
            ("payload_map.js", None),
            ("elfldr-ps5-1360.elf", None),
            ("kexp_2026_05_25.bin", None),
            ("a/b.elf", None),
            ("etaHEN.elf", "not-pinned.elf"),
            ("etaHEN.elf", "payload_map.js"),
        ]
        for remote, save in bad:
            try:
                save_catalog_payload(directory, remote, save, True)
            except ValueError:
                continue
            raise SystemExit("accepted %s %s" % (remote, save))
        try:
            save_catalog_payload(directory, "kstuff-lite.elf", "kstuff.elf", True)
        except AssertionError:
            pass
        else:
            raise SystemExit("refresh did not download")

        class Body:
            def __init__(self, data):
                self.data = data
                self.status = 200
                self.off = 0

            def read(self, n):
                chunk = self.data[self.off:self.off + n]
                self.off += len(chunk)
                return chunk

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        urllib.request.urlopen = lambda req, timeout=60: Body(b"NOPE" + b"\0" * 16)
        try:
            save_catalog_payload(directory, "kstuff-lite.elf", "kstuff.elf", True)
        except OSError:
            pass
        else:
            raise SystemExit("bad elf accepted")
        with open(final, "rb") as fh:
            if fh.read(4) != b"\x7fELF":
                raise SystemExit("original overwritten")
        if any(name.endswith(".part") for name in os.listdir(directory)):
            raise SystemExit("part file left behind")

        blob = b"\x7fELF" + b"\x01" * 20
        urllib.request.urlopen = lambda req, timeout=60: Body(blob)
        name, size = save_catalog_payload(directory, "kstuff-lite.elf", "kstuff.elf", True)
        if name != "kstuff.elf" or size != len(blob):
            raise SystemExit("refresh write failed")
        with open(final, "rb") as fh:
            if fh.read() != blob:
                raise SystemExit("bytes mismatch")
        name, size = save_catalog_payload(directory, "etaHEN.elf", None, True)
        if name != "etaHEN.elf" or not os.path.isfile(os.path.join(directory, "etaHEN.elf")):
            raise SystemExit("extra save failed")

        global github_open
        previous_open = github_open

        def fake_open(url, timeout, headers):
            if url.endswith("/releases/latest"):
                payload = json.dumps({
                    "tag_name": "v0.17.0",
                    "assets": [{"name": "panplay-v0.17.0-ps5.elf", "size": 24}],
                }).encode("utf-8")
                return Body(payload)
            if "/releases/download/" in url:
                return Body(b"\x7fELF" + b"\x02" * 20)
            raise AssertionError(url)

        github_open = fake_open
        try:
            try:
                latest_release("https://evil.example")
            except ValueError:
                pass
            else:
                raise SystemExit("bad repo accepted")
            info = latest_release("cnwinds/pan-play")
            if info["tag"] != "v0.17.0" or info["version"] != "0.17.0":
                raise SystemExit("release parse failed")
            if info["assets"][0]["name"] != "panplay-v0.17.0-ps5.elf":
                raise SystemExit("asset missing")
            name, size = save_github_release(
                directory, "cnwinds/pan-play", "v0.17.0",
                "panplay-v0.17.0-ps5.elf", "panplay.elf", True,
            )
            if name != "panplay.elf" or size != 24:
                raise SystemExit("github save failed")
            with open(os.path.join(directory, "panplay.elf"), "rb") as fh:
                if fh.read(4) != b"\x7fELF":
                    raise SystemExit("github bytes mismatch")
        finally:
            github_open = previous_open
        print("payload_store ok")
    finally:
        urllib.request.urlopen = original
        shutil.rmtree(directory)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--bind", default="127.0.0.1:8765")
    parser.add_argument("--root")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.root:
        parser.error("--root is required")
    serve(args.bind, args.root)


if __name__ == "__main__":
    main()
