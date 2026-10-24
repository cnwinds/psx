"""FTP 网页中转：浏览器 → 本机 serve.py → PS5 FTP（ftpsrv :2121 / zftpd :2120）。

仅当 serve.py 与 PS5 在同一局域网时可中转；公网部署请走 ftp.html 的「浏览器直连」模式。
"""

import ftplib
import io
import posixpath
import queue
import struct
import tempfile
import threading
import time
import zipfile
from urllib.parse import quote, unquote

FTP_PORT_DEFAULT = 2121
FTP_USER = "anonymous"
FTP_PASS = "anonymous"
FTP_POOL_SIZE = 16
FTP_SCHED_MIN = 2
FTP_SCHED_MAX = 16

_log = print
_ctx = {
    "ranked_lan_ips": lambda: [],
    "probe_tcp": lambda ip, port, timeout=0.5: False,
    "record_ps5_candidate": lambda *args, **kwargs: None,
    "is_valid_lan_ipv4": lambda ip: False,
}


def configure(log_fn, ranked_lan_ips, probe_tcp, record_ps5_candidate, is_valid_lan_ipv4):
    global _log
    _log = log_fn
    _ctx.update({
        "ranked_lan_ips": ranked_lan_ips,
        "probe_tcp": probe_tcp,
        "record_ps5_candidate": record_ps5_candidate,
        "is_valid_lan_ipv4": is_valid_lan_ipv4,
    })


class _FtpSlot:
    def __init__(self):
        self.lock = threading.Lock()
        self.ftp = None
        self.key = None


_ftp_slots = [_FtpSlot() for _ in range(FTP_POOL_SIZE)]
_ensured_lock = threading.Lock()
_ensured_dirs = set()
_ftp_pool_cv = threading.Condition()
_ftp_idle = list(_ftp_slots)


def _close_slot(slot):
    if slot.ftp is not None:
        try:
            slot.ftp.quit()
        except Exception:
            try:
                slot.ftp.close()
            except Exception:
                pass
    slot.ftp = None


def _ftp_connect(host, port):
    if not host:
        raise ValueError("PS5 地址为空")
    ftp = ftplib.FTP()
    ftp.encoding = "utf-8"
    try:
        ftp.connect(host, port, timeout=8)
        ftp.login(FTP_USER, FTP_PASS)
        ftp.sock.settimeout(30)
        ftp.timeout = 30
        ftp.voidcmd("TYPE I")
    except ftplib.error_perm:
        pass
    except OSError as error:
        raise ConnectionError(
            f"连不上 {host}:{port}（{error}）—— 确认 PS5 上 FTP 已启动，并核对 IP/端口"
        ) from error
    return ftp


def ftp_run(host, port, fn, retry=True):
    key = (host, port)
    with _ftp_pool_cv:
        while not _ftp_idle:
            _ftp_pool_cv.wait()
        slot = _ftp_idle.pop()
    slot.lock.acquire()
    try:
        if slot.ftp is None or slot.key != key:
            _close_slot(slot)
            slot.ftp, slot.key = _ftp_connect(host, port), key
        try:
            return fn(slot.ftp)
        except ftplib.all_errors + (OSError,):
            with _ensured_lock:
                _ensured_dirs.clear()
            _close_slot(slot)
            if not retry:
                raise
            slot.ftp = _ftp_connect(host, port)
            return fn(slot.ftp)
    finally:
        slot.lock.release()
        with _ftp_pool_cv:
            _ftp_idle.append(slot)
            _ftp_pool_cv.notify()


def ftp_size(ftp, path):
    try:
        ftp.voidcmd("TYPE I")
    except ftplib.error_perm:
        pass
    return int(ftp.size(path) or 0)


def ftp_mkd_p(ftp, path, cache_key=None):
    current = ""
    for part in [p for p in path.split("/") if p and p != "."]:
        current += "/" + part
        if cache_key and (cache_key[0], cache_key[1], current) in _ensured_dirs:
            continue
        try:
            ftp.mkd(current)
        except ftplib.error_perm:
            pass
        if cache_key:
            with _ensured_lock:
                _ensured_dirs.add((cache_key[0], cache_key[1], current))
    return current or "/"


def ftp_list(ftp, path):
    path = posixpath.normpath(path)
    if not path.startswith("/"):
        path = "/" + path
    ftp.cwd(path)
    entries = []
    try:
        for name, facts in ftp.mlsd():
            name = name.rstrip("/").rsplit("/", 1)[-1]
            if name in ("", ".", ".."):
                continue
            entries.append({
                "name": name,
                "dir": facts.get("type") == "dir",
                "size": int(facts.get("size") or 0),
                "mtime": facts.get("modify") or "",
            })
    except ftplib.error_perm:
        for name in ftp.nlst():
            name = name.rstrip("/").rsplit("/", 1)[-1]
            if name in ("", ".", ".."):
                continue
            is_dir = False
            try:
                ftp.cwd(name)
                is_dir = True
                ftp.cwd(path)
            except ftplib.error_perm:
                pass
            size = 0
            if not is_dir:
                try:
                    size = ftp_size(ftp, name)
                except Exception:
                    pass
            entries.append({"name": name, "dir": is_dir, "size": size, "mtime": ""})
    dirs = sorted((e for e in entries if e["dir"]), key=lambda e: e["name"].lower())
    files = [e for e in entries if not e["dir"]]
    files.sort(key=lambda e: e["name"].lower())
    files.sort(key=lambda e: e["mtime"], reverse=True)
    return dirs + files


def ftp_rmd_tree(ftp, path):
    for entry in ftp_list(ftp, path):
        full = posixpath.join(path, entry["name"])
        if entry["dir"]:
            ftp_rmd_tree(ftp, full)
        else:
            ftp.delete(full)
    ftp.rmd(path)


def ftp_walk_manifest(ftp, path, prefix, out):
    for entry in ftp_list(ftp, path):
        rel = prefix + entry["name"]
        if entry["dir"]:
            ftp_walk_manifest(ftp, posixpath.join(path, entry["name"]), rel + "/", out)
        else:
            out[rel] = entry["size"]


def ftp_walk_files(ftp, path, prefix, dirs, files):
    dirs.append(prefix)
    for entry in ftp_list(ftp, path):
        full = posixpath.join(path, entry["name"])
        rel = prefix + entry["name"]
        if entry["dir"]:
            ftp_walk_files(ftp, full, rel + "/", dirs, files)
        else:
            files.append((full, rel))


def ftp_remote_path(raw, base=None):
    path = unquote(raw or "/").replace("\\", "/")
    if base and not path.startswith("/"):
        path = posixpath.join(base, path)
    path = posixpath.normpath(path)
    if not path.startswith("/"):
        path = "/" + path
    return path


class _BodyReader:
    def __init__(self, rfile, length):
        self._rfile = rfile
        self.remaining = length

    def read(self, size=-1):
        if self.remaining <= 0:
            return b""
        if size < 0 or size > self.remaining:
            size = self.remaining
        chunk = self._rfile.read(size)
        self.remaining -= len(chunk)
        return chunk


class _UploadJob:
    __slots__ = ("host", "port", "path", "name", "data", "event", "result")

    def __init__(self, host, port, path, name, data):
        self.host, self.port, self.path = host, port, path
        self.name, self.data = name, data
        self.event = threading.Event()
        self.result = None


_sched_lock = threading.Lock()
_sched = {
    "queue": queue.Queue(),
    "workers": 0,
    "target": 6,
    "overhead": 0.2,
    "rate_now": 0.0,
    "rate_best": 0.0,
    "big_at": 0.0,
    "last_adj": 0.0,
}


def _mbps(rate):
    return f"{rate / 1048576:.1f} MB/s"


def _sched_note(size, seconds):
    with _sched_lock:
        s = _sched
        if size <= 65536:
            s["overhead"] = s["overhead"] * 0.7 + seconds * 0.3
        elif seconds - s["overhead"] > 0.05:
            rate = (size - 65536) / (seconds - s["overhead"])
            s["rate_now"] = s["rate_now"] * 0.6 + rate * 0.4 if s["rate_now"] else rate
            if s["rate_best"] == 0 or s["target"] <= 3:
                s["rate_best"] = max(s["rate_best"], s["rate_now"])
            s["big_at"] = time.monotonic()


def _sched_adjust():
    with _sched_lock:
        s = _sched
        now = time.monotonic()
        if now - s["last_adj"] < 1.5:
            return
        big_regime = now - s["big_at"] < 10 and s["rate_now"] > 0
        if big_regime:
            if s["rate_now"] < 0.7 * s["rate_best"]:
                target = max(FTP_SCHED_MIN, s["target"] // 2)
                if target != s["target"]:
                    s["target"], s["last_adj"] = target, now
                    _log(f"[ftp] 写入并发 ↓ {target} 路（单通道 {_mbps(s['rate_now'])} 被挤占）")
            elif s["rate_now"] >= 0.85 * s["rate_best"] and s["target"] < FTP_SCHED_MAX:
                s["target"] += 1
                s["last_adj"] = now
                _log(f"[ftp] 写入并发 ↑ {s['target']} 路")
        elif s["target"] < FTP_SCHED_MAX:
            s["target"] += 1
            s["last_adj"] = now
            _log(f"[ftp] 写入并发 ↑ {s['target']} 路（小文件事务开销约 {int(s['overhead'] * 1000)}ms/个）")


def _sched_ensure():
    with _sched_lock:
        while _sched["workers"] < _sched["target"]:
            _sched["workers"] += 1
            threading.Thread(target=_upload_worker, daemon=True).start()


def _upload_worker():
    while True:
        try:
            job = _sched["queue"].get(timeout=0.5)
        except queue.Empty:
            with _sched_lock:
                if _sched["workers"] > _sched["target"]:
                    _sched["workers"] -= 1
                    return
            continue
        start = time.monotonic()
        try:
            def _stor(ftp):
                parent = posixpath.dirname(job.name)
                if parent:
                    ftp_mkd_p(ftp, posixpath.join(job.path, parent), cache_key=(job.host, job.port))
                ftp.storbinary(
                    "STOR " + posixpath.join(job.path, job.name),
                    io.BytesIO(job.data),
                    blocksize=64 * 1024,
                )

            ftp_run(job.host, job.port, _stor)
            job.result = {"name": job.name, "ms": round((time.monotonic() - start) * 1000)}
        except Exception as error:
            job.result = {"name": job.name, "error": str(error)}
        finally:
            _sched_note(len(job.data), time.monotonic() - start)
            _sched_adjust()
            _sched_ensure()
            job.event.set()


def _sched_submit(host, port, path, files):
    _sched_ensure()
    jobs = [_UploadJob(host, port, path, name, data) for name, data in files]
    for job in jobs:
        _sched["queue"].put(job)
    for job in jobs:
        job.event.wait()
    with _sched_lock:
        lanes = _sched["target"]
    return [job.result for job in jobs], lanes


def shares_subnet(ip, server_ips):
    if not ip or not server_ips:
        return False
    prefix = ".".join(ip.split(".")[:3]) + "."
    return any(sip.startswith(prefix) for sip in server_ips)


def probe_relay(host, port, server_ips, probe_tcp_fn):
    """探测本机 serve.py 能否作为 FTP 中转连上 PS5。返回 (ok, reason, ps5_ports, ftp_port)。"""
    ps5_ports = {}
    if not host:
        return False, "请填写 PS5 的 IP", ps5_ports, port
    for p in (2120, 2121, 8888):
        ps5_ports[str(p)] = probe_tcp_fn(host, p, 0.45)
    ftp_port = pick_ftp_port(port, ps5_ports)
    if not server_ips:
        return False, "本服务器未检测到局域网网卡，无法中转内网 PS5", ps5_ports, ftp_port
    if not shares_subnet(host, server_ips):
        return (
            False,
            f"PS5（{host}）与服务器不在同一网段——公网站点无法访问你家内网 IP，请改用「浏览器直连」或 FileZilla",
            ps5_ports,
            ftp_port,
        )
    try:
        ftp_run(host, ftp_port, lambda ftp: ftp.pwd(), retry=False)
        return True, "", ps5_ports, ftp_port
    except Exception as error:
        hint = "确认 PS5 上 FTP 已启动"
        if ps5_ports.get("8888") and not ps5_ports.get(str(ftp_port)):
            hint = f"端口 {ftp_port} 未监听；检测到 ZHTTP :8888 在线，可改用「浏览器直连」"
        elif ps5_ports.get("2120") and ftp_port == 2121:
            hint = "检测到 zftpd :2120 在线，请把端口改为 2120"
        elif ps5_ports.get("2121") and ftp_port == 2120:
            hint = "检测到 ftpsrv :2121 在线，请把端口改为 2121"
        return False, f"{error}（{hint}）", ps5_ports, ftp_port


class RelayNotAllowed(PermissionError):
    """本服务器不允许向该 PS5 发起 FTP 中转。"""


def require_relay_allowed(host):
    """所有 /api/ftp/* 中转操作的前置校验（probe 除外）。"""
    if not _ctx["is_valid_lan_ipv4"](host):
        raise ValueError("PS5 IP 无效")
    server_ips = _ctx["ranked_lan_ips"]()
    if not server_ips:
        raise RelayNotAllowed("本服务器未检测到局域网网卡，无法中转内网 PS5")
    if not shares_subnet(host, server_ips):
        raise RelayNotAllowed(
            f"PS5（{host}）与服务器不在同一网段，无法中转——请改用浏览器直连或 FileZilla"
        )


def pick_ftp_port(requested_port, ps5_ports):
    """按 PS5 实际监听的 FTP 端口修正请求端口。"""
    if ps5_ports.get("2121") and not ps5_ports.get("2120"):
        return 2121
    if ps5_ports.get("2120") and not ps5_ports.get("2121"):
        return 2120
    return requested_port


def build_direct_options(host, ps5_ports):
    direct = {}
    if ps5_ports.get("8888"):
        direct["zhttp"] = f"http://{host}:8888"
    if ps5_ports.get("2121"):
        direct["ftp"] = {"host": host, "port": 2121, "kind": "ftpsrv"}
    elif ps5_ports.get("2120"):
        direct["ftp"] = {"host": host, "port": 2120, "kind": "zftpd"}
    return direct


class FtpRelayHandler:
    """混入 SiteHandler：处理 /api/ftp/* 路由。"""

    def _api_ftp_probe(self, query):
        host = (query.get("host") or [""])[0].strip()
        port = int((query.get("port") or [str(FTP_PORT_DEFAULT)])[0] or FTP_PORT_DEFAULT)
        server_ips = _ctx["ranked_lan_ips"]()
        site_host = (self.headers.get("Host") or "").split(":")[0]
        site_on_lan = _ctx["is_valid_lan_ipv4"](site_host) and site_host not in ("127.0.0.1",)
        if not _ctx["is_valid_lan_ipv4"](host):
            self._send_json(400, {"error": "PS5 IP 无效"})
            return
        relay_ok, relay_reason, ps5_ports, ftp_port = probe_relay(
            host, port, server_ips, _ctx["probe_tcp"]
        )
        if relay_ok:
            _ctx["record_ps5_candidate"](host, "ftp", "FTP 网页中转", {str(ftp_port): True})
        direct = build_direct_options(host, ps5_ports)
        if relay_ok:
            recommended = "relay"
        elif direct.get("zhttp"):
            recommended = "direct"
        else:
            recommended = "client"
        self._send_json(200, {
            "relay_ok": relay_ok,
            "relay_reason": relay_reason,
            "ftp_port": ftp_port,
            "server_lan_ips": server_ips,
            "site_on_lan": site_on_lan,
            "ps5_ports": ps5_ports,
            "direct": direct,
            "recommended_mode": recommended,
        })

    def _api_ftp_list(self, query):
        try:
            host = (query.get("host") or [""])[0].strip()
            port = int((query.get("port") or [str(FTP_PORT_DEFAULT)])[0] or FTP_PORT_DEFAULT)
            require_relay_allowed(host)
            path = ftp_remote_path((query.get("path") or ["/"])[0])
            offset = max(0, int((query.get("offset") or ["0"])[0] or 0))
            limit = min(1000, max(1, int((query.get("limit") or ["500"])[0] or 500)))
            entries = ftp_run(host, port, lambda ftp: ftp_list(ftp, path))
            self._send_json(200, {
                "path": path,
                "total": len(entries),
                "offset": offset,
                "entries": entries[offset:offset + limit],
            })
        except RelayNotAllowed as error:
            self._send_json(403, {"error": str(error)})
            _log(f"[ftp] 403 list：{error}")
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            _log(f"[ftp] 400 list：{error}")
        except Exception as error:
            self._send_json(502, {"error": str(error)})
            _log(f"[ftp] 502 list：{error}")

    def _api_ftp_put(self):
        host = self.headers.get("X-Ftp-Host", "").strip()
        port = int(self.headers.get("X-Ftp-Port") or FTP_PORT_DEFAULT)
        remote = ftp_remote_path(self.headers.get("X-Ftp-Path") or "")
        length = int(self.headers.get("Content-Length") or -1)
        if not host or remote == "/" or length < 0:
            raise ValueError(f"put 参数不完整：host={host!r} path={remote!r} length={length}")
        require_relay_allowed(host)
        ftp_run(host, port, lambda ftp: ftp.pwd())

        def _stor(ftp):
            parent = posixpath.dirname(remote)
            if parent not in ("", "/"):
                ftp_mkd_p(ftp, parent, cache_key=(host, port))
            ftp.storbinary("STOR " + remote, _BodyReader(self.rfile, length), blocksize=64 * 1024)

        ftp_run(host, port, _stor, retry=False)
        self._send_json(200, {"path": remote, "size": length})
        _log(f"[ftp] 上传 {remote}（{length} 字节）→ {host}:{port}")

    def _api_ftp_mkdir(self):
        data = self._read_json()
        host = str(data.get("host", "")).strip()
        port = int(data.get("port") or FTP_PORT_DEFAULT)
        path = ftp_remote_path(data.get("path") or "")
        if not host or path == "/":
            raise ValueError("缺少 PS5 地址 / 目录路径")
        require_relay_allowed(host)
        made = ftp_run(host, port, lambda ftp: ftp_mkd_p(ftp, path, cache_key=(host, port)))
        self._send_json(200, {"path": made})

    def _api_ftp_delete(self):
        data = self._read_json()
        host = str(data.get("host", "")).strip()
        port = int(data.get("port") or FTP_PORT_DEFAULT)
        path = ftp_remote_path(data.get("path") or "")
        if not host or path == "/":
            raise ValueError("缺少 PS5 地址 / 目标路径")
        require_relay_allowed(host)

        def _delete(ftp):
            if data.get("dir"):
                if data.get("recursive"):
                    ftp_rmd_tree(ftp, path)
                else:
                    ftp.rmd(path)
            else:
                ftp.delete(path)

        ftp_run(host, port, _delete)
        with _ensured_lock:
            _ensured_dirs.clear()
        self._send_json(200, {"path": path})
        _log(f"[ftp] 删除 {path}{'（递归）' if data.get('recursive') else ''}")

    def _api_ftp_rename(self):
        data = self._read_json()
        host = str(data.get("host", "")).strip()
        port = int(data.get("port") or FTP_PORT_DEFAULT)
        path = ftp_remote_path(data.get("path") or "")
        to = ftp_remote_path(str(data.get("to") or ""), base=posixpath.dirname(path))
        if not host or path == "/" or to == "/" or to == path:
            raise ValueError("缺少 PS5 地址 / 目标路径，或新旧路径相同")
        require_relay_allowed(host)

        def _rename(ftp):
            parent = posixpath.dirname(to)
            if parent not in ("", "/"):
                ftp_mkd_p(ftp, parent, cache_key=(host, port))
            ftp.rename(path, to)

        ftp_run(host, port, _rename)
        with _ensured_lock:
            _ensured_dirs.clear()
        self._send_json(200, {"path": to})
        _log(f"[ftp] 重命名/移动 {path} → {to}")

    def _api_ftp_check(self):
        data = self._read_json()
        host = str(data.get("host", "")).strip()
        port = int(data.get("port") or FTP_PORT_DEFAULT)
        path = ftp_remote_path(data.get("path") or "")
        manifest = data.get("files") or []
        if not host or path == "/" or not isinstance(manifest, list):
            raise ValueError("缺少 PS5 地址 / 目标目录 / 文件清单")
        require_relay_allowed(host)
        existing = {}
        ftp_run(host, port, lambda ftp: ftp_walk_manifest(ftp, path, "", existing))
        need = [m.get("name") for m in manifest if existing.get(m.get("name")) != m.get("size")]
        self._send_json(200, {
            "total": len(manifest),
            "need": need,
            "skip": len(manifest) - len(need),
        })
        _log(f"[ftp] 增量检查 {path}：清单 {len(manifest)}，待传 {len(need)}")

    def _api_ftp_putbatch(self):
        host = self.headers.get("X-Ftp-Host", "").strip()
        port = int(self.headers.get("X-Ftp-Port") or FTP_PORT_DEFAULT)
        target = ftp_remote_path(self.headers.get("X-Ftp-Dir") or "")
        length = int(self.headers.get("Content-Length") or -1)
        if not host or target == "/" or length < 0:
            raise ValueError(f"putbatch 参数不完整：host={host!r} dir={target!r} length={length}")
        require_relay_allowed(host)
        if length > 128 * 1024 * 1024:
            raise ValueError("批量请求过大（>128MB），请减小每批文件数")
        body = self.rfile.read(length)
        offset = 0

        def take(size):
            nonlocal offset
            if offset + size > len(body):
                raise ValueError("批量帧不完整")
            chunk = body[offset:offset + size]
            offset += size
            return chunk

        files = []
        (count,) = struct.unpack(">I", take(4))
        for _ in range(count):
            (name_len,) = struct.unpack(">I", take(4))
            name = take(name_len).decode("utf-8")
            (size,) = struct.unpack(">Q", take(8))
            segments = name.split("/")
            if (not name or name.startswith("/") or "\\" in name
                    or any(seg in ("", ".", "..") for seg in segments)):
                raise ValueError(f"批量帧含非法路径：{name!r}")
            files.append((name, bytes(take(size))))
        if offset != len(body):
            raise ValueError("批量帧有未消费的剩余字节")
        if not files:
            raise ValueError("批量帧为空")

        ftp_run(host, port, lambda ftp: ftp.pwd())
        ftp_run(host, port, lambda ftp: ftp_mkd_p(ftp, target, cache_key=(host, port)))
        results, lanes = _sched_submit(host, port, target, files)
        ok = [r for r in results if "error" not in r]
        failed = [r for r in results if "error" in r]
        self._send_json(200, {"ok": ok, "failed": failed, "lanes": lanes})
        _log(f"[ftp] 批量上传 {target}：成功 {len(ok)}，失败 {len(failed)} → {host}:{port}")

    def _api_ftp_get(self, query):
        try:
            host = (query.get("host") or [""])[0].strip()
            port = int((query.get("port") or [str(FTP_PORT_DEFAULT)])[0] or FTP_PORT_DEFAULT)
            path = ftp_remote_path((query.get("path") or [""])[0])
            if not host or path == "/":
                raise ValueError("缺少 PS5 地址 / 文件路径")
            require_relay_allowed(host)

            def _download(ftp):
                try:
                    size = ftp_size(ftp, path)
                except Exception as error:
                    raise ValueError("读不到文件大小（SIZE 命令失败），无法下载") from error
                name = posixpath.basename(path)
                self.send_response(200)
                if hasattr(self, "_ftp_cors_headers"):
                    self._ftp_cors_headers()
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(name))
                self.end_headers()
                ftp.retrbinary("RETR " + path, self.wfile.write, blocksize=64 * 1024)
                return size

            size = ftp_run(host, port, _download, retry=False)
            _log(f"[ftp] 下载 {path}（{size} 字节）→ {host}")
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            _log(f"[ftp] 400 get：{error}")
        except Exception as error:
            self._send_json(502, {"error": str(error)})
            _log(f"[ftp] 502 get：{error}")

    def _api_ftp_zip(self, query):
        try:
            host = (query.get("host") or [""])[0].strip()
            port = int((query.get("port") or [str(FTP_PORT_DEFAULT)])[0] or FTP_PORT_DEFAULT)
            path = ftp_remote_path((query.get("path") or [""])[0])
            if not host or path == "/":
                raise ValueError("缺少 PS5 地址 / 目录路径")
            require_relay_allowed(host)
            dirs, files = [], []
            ftp_run(host, port, lambda ftp: ftp_walk_files(
                ftp, path, posixpath.basename(path) + "/", dirs, files))

            def _pack(ftp):
                spool = tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024)
                with zipfile.ZipFile(spool, "w", zipfile.ZIP_STORED) as zf:
                    for rel in dirs:
                        zf.writestr(zipfile.ZipInfo(rel.rstrip("/") + "/"), b"")
                    for remote, rel in files:
                        size = ftp_size(ftp, remote)
                        info = zipfile.ZipInfo(rel)
                        info.file_size = size
                        with zf.open(info, "w") as dst:
                            ftp.retrbinary("RETR " + remote, dst.write, blocksize=64 * 1024)
                spool.seek(0, 2)
                total = spool.tell()
                spool.seek(0)
                name = posixpath.basename(path) + ".zip"
                self.send_response(200)
                if hasattr(self, "_ftp_cors_headers"):
                    self._ftp_cors_headers()
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(total))
                self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(name))
                self.end_headers()
                while True:
                    chunk = spool.read(64 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                return total

            total = ftp_run(host, port, _pack, retry=False)
            _log(f"[ftp] 打包下载 {path}（{total} 字节）→ {host}")
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            _log(f"[ftp] 400 zip：{error}")
        except Exception as error:
            self._send_json(502, {"error": str(error)})
            _log(f"[ftp] 502 zip：{error}")

    def handle_ftp_get(self, route, query):
        if route == "/api/ftp/probe":
            self._api_ftp_probe(query)
            return True
        if route == "/api/ftp/list":
            self._api_ftp_list(query)
            return True
        if route == "/api/ftp/get":
            self._api_ftp_get(query)
            return True
        if route == "/api/ftp/zip":
            self._api_ftp_zip(query)
            return True
        return False

    def handle_ftp_post(self, route):
        handlers = {
            "/api/ftp/put": self._api_ftp_put,
            "/api/ftp/mkdir": self._api_ftp_mkdir,
            "/api/ftp/delete": self._api_ftp_delete,
            "/api/ftp/rename": self._api_ftp_rename,
            "/api/ftp/check": self._api_ftp_check,
            "/api/ftp/putbatch": self._api_ftp_putbatch,
        }
        fn = handlers.get(route)
        if not fn:
            return False
        fn()
        return True
