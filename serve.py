#!/usr/bin/env python3
"""PS5 Relapse All-in-One Host — 纯 Python 一体化（Windows 双击 start-host.bat 即用）

一个进程包含全部功能：
  DNS  : udp/53   —— 索尼全系域名 NXDOMAIN 拦截 + manuals.playstation.net 劫持到本机
  HTTPS: tcp/443  —— 用户指南/健康与安全指南入口（自签证书 + /document 回首页）
  HTTP : tcp/80   —— 站点本体（PS5 浏览器手输 http://本机IP/ 也可进入）
  FTP  : 网页转发 —— /ftp.html 由本进程中转到 PS5 的 zftpd(2120)，电脑零客户端

PS5 侧设置：手动 DNS 首选填本机 IP，备用留空。
"""

import ftplib
import io
import json
import os
import posixpath
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import queue
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit

# ---------------- 可按需修改的配置 ----------------
HOST_IP = None            # 本机局域网 IP；None = 自动检测（多数情况不用改）
DNS_PORT = 53             # Windows 上通常无需管理员即可绑定
HTTP_PORT = 80
HTTPS_PORT = 443
UPSTREAMS = ["223.5.5.5", "119.29.29.29"]   # 放行域名的上游解析（阿里/腾讯）
TTL = 300
# 索尼域名全拦（NXDOMAIN）
BLOCKED_SUFFIXES = (
    "playstation.net",
    "playstation.com",
    "sonyentertainmentnetwork.com",
    "sony.com",
    "sony.net",
    "psn.com",
    "scea.com",
    "sonyinteractive.com",
)
GUIDE_DOMAIN = "manuals.playstation.net"    # 劫持到本机（用户指南入口）
FTP_PORT_DEFAULT = 2120     # zftpd（独立 FTP payload）的默认监听端口（v1.5.0 起 2120）
FTP_USER = "anonymous"      # zftpd 是开放服务器：任意账号密码均可登录
FTP_PASS = "anonymous"
ROOT = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(ROOT, "certs", "cert.pem")
KEY = os.path.join(ROOT, "certs", "key.pem")


def out(message):
    try:
        print(message, flush=True)
    except UnicodeEncodeError:
        print(message.encode("gbk", "replace").decode("gbk"), flush=True)


def ranked_lan_ips():
    """枚举本机 IPv4 并按“像真实局域网”排序：192.168 > 10 > 172.16。

    代理 TUN(Meta/Clash 198.18.x)、Tailscale(100.64-127.x)、链路本地、组播等
    地址对同一路由器下的 PS5 不可达，直接排除；Radmin(26.x) 之类垫底兜底。"""
    try:
        addrs = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        return []

    def rank(ip):
        try:
            first, second = (int(part) for part in ip.split(".")[:2])
        except ValueError:
            return None
        if first == 192 and second == 168:
            return 0
        if first == 10:
            return 1
        if first == 172 and 16 <= second <= 31:
            return 2
        if first in (0, 127, 169, 198, 224) or 100 <= first <= 127 or first >= 240:
            return None
        return 3

    ranked = [(rank(ip), ip) for ip in addrs]
    return [ip for score, ip in sorted(item for item in ranked if item[0] is not None)]


def detect_lan_ip():
    if HOST_IP:
        return HOST_IP
    ips = ranked_lan_ips()
    if ips:
        return ips[0]
    # 兜底：按默认路由取出口 IP（挂代理 TUN 时会拿到 198.18.x，需人工指定 HOST_IP）
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("223.5.5.5", 53))
        ip = probe.getsockname()[0]
        if not ip.startswith("127."):
            return ip
    except OSError:
        pass
    finally:
        probe.close()
    return "127.0.0.1"


def find_port_owner(port, proto):
    """Windows 下用 netstat+tasklist 查占用端口的进程，返回如 ["svchost.exe (PID 20372)"]。"""
    if sys.platform != "win32":
        return []

    def run_lenient(args):
        # 中文系统的 netstat/tasklist 输出是 GBK，按 bytes 取回宽松解码（字段本身是 ASCII）
        try:
            raw = subprocess.run(args, capture_output=True, timeout=15).stdout
        except (OSError, subprocess.SubprocessError):
            return ""
        return raw.decode(errors="replace")

    lines = run_lenient(["netstat", "-ano", "-p", proto]).splitlines()
    owners = []
    for line in lines:
        fields = line.split()
        if len(fields) < 4 or not fields[1].endswith(f":{port}") or not fields[-1].isdigit():
            continue
        pid = fields[-1]
        csv = run_lenient(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]).strip()
        name = csv.split('","')[0].strip('"') if csv.startswith('"') else f"PID {pid}"
        if f"{name} (PID {pid})" not in owners:
            owners.append(f"{name} (PID {pid})")
    return owners


# ---------------- DNS（53/udp）----------------

def read_qname_at(data, offset):
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            rest, _ = read_qname_at(data, pointer)
            if rest:
                labels.append(rest)
            offset += 2
            break
        labels.append(data[offset + 1:offset + 1 + length].decode("latin1"))
        offset += 1 + length
    return ".".join(labels), offset


def read_qname(data):
    name, _ = read_qname_at(data, 12)
    return name


def error_response(data, rcode):
    resp = bytearray(data)
    resp[2] |= 0x80                       # QR = 响应
    resp[3] = (resp[3] & 0xF0) | rcode    # RCODE
    resp[6:12] = b"\x00" * 6              # 清空 AN/NS/AR 计数
    return bytes(resp)


def a_response(data, ip):
    resp = bytearray(data)
    resp[2] |= 0x80                       # QR = 响应
    resp[6:8] = b"\x00\x01"               # ANCOUNT = 1
    resp[8:12] = b"\x00\x00\x00\x00"      # NS/AR = 0
    resp += b"\xc0\x0c"                   # 指回问题区的域名
    resp += struct.pack(">HHIH", 1, 1, TTL, 4)
    resp += bytes(int(part) for part in ip.split("."))
    return bytes(resp)


def forward_upstream(data):
    for upstream in UPSTREAMS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(3)
            sock.sendto(data, (upstream, 53))
            response, _ = sock.recvfrom(4096)
            return response
        except OSError:
            continue
        finally:
            sock.close()
    return None


def handle_query(sock, data, addr, host_ip):
    try:
        if len(data) < 12:
            return
        name = read_qname(data).lower()
        if not name:
            return
        if name == GUIDE_DOMAIN or name.endswith("." + GUIDE_DOMAIN):
            sock.sendto(a_response(data, host_ip), addr)
            out(f"[dns] {name} -> {host_ip}  (指南入口，来自 {addr[0]})")
        elif any(name == s or name.endswith("." + s) for s in BLOCKED_SUFFIXES):
            sock.sendto(error_response(data, 3), addr)   # NXDOMAIN（高频请求，不打印日志）
        else:
            response = forward_upstream(data)
            if response:
                sock.sendto(response, addr)
            else:
                sock.sendto(error_response(data, 2), addr)   # SERVFAIL
    except OSError:
        pass


def dns_loop(host_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", DNS_PORT))
    except OSError as error:
        out(f"[!] DNS {DNS_PORT}/udp 绑定失败：{error}")
        owners = find_port_owner(DNS_PORT, "udp")
        if owners:
            out(f"    占用者：{'、'.join(owners)}")
        out("    常见原因：Windows ICS/移动热点（svchost，管理员执行 net stop sharedaccess 释放）、")
        out("    代理客户端 DNS 监听（Clash/mihomo 等，关闭其 DNS 服务或退出）。")
        out("    PS5 的 DNS 指向本机将不可用；站点功能不受影响。")
        return
    out(f"[dns] 监听 {DNS_PORT}/udp —— 索尼域名拦截 + 指南入口已激活")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            break
        threading.Thread(
            target=handle_query, args=(sock, data, addr, host_ip), daemon=True
        ).start()


# ---------------- FTP 转发（网页 → PS5 zftpd:2120）----------------

FTP_POOL_SIZE = 16         # zftpd 每连接一线程：多条控制连接并行收发。
                           # 槽位惰性建连（用到才连），空槽零开销。
                           # 浏览器同源并发上限约 6，更大的池主要服务小文件批量接口的内部并行


class _FtpSlot:
    """一条缓存的 FTP 控制连接 + 它自己的锁。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.ftp = None
        self.key = None


_ftp_slots = [_FtpSlot() for _ in range(FTP_POOL_SIZE)]
_ensured_lock = threading.Lock()
_ensured_dirs = set()      # 已确认存在的远端目录 (host, port, path)：免去逐文件重复 MKD


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
    """新建一条到 PS5 FTP 的控制连接。"""
    if not host:
        raise ValueError("PS5 地址为空")
    ftp = ftplib.FTP()
    ftp.encoding = "utf-8"          # 远端文件名按 UTF-8 收发（中文 ROM 名）
    try:
        ftp.connect(host, port, timeout=8)
        ftp.login(FTP_USER, FTP_PASS)
        ftp.sock.settimeout(30)     # 万级条目的大目录，列表传输远慢于建连
        ftp.timeout = 30            # PASV 数据连接同样用这个超时
        ftp.voidcmd("TYPE I")       # 二进制模式：部分 FTP 实现 ASCII 模式下拒绝 SIZE
    except ftplib.error_perm:
        pass                        # 登录失败也先留着：zftpd 任意账号放行，别的服务器可能只警告
    except OSError as error:
        raise ConnectionError(
            f"连不上 {host}:{port}（{error}）—— 先在破解页发送「zftpd」payload，并核对 IP/端口（默认 2120）"
        ) from error
    return ftp


_ftp_pool_cv = threading.Condition()
_ftp_idle = list(_ftp_slots)            # 空闲槽队列：16 槽高并发下公平排队


def ftp_run(host, port, fn, retry=True):
    """在连接池的一个槽里执行 fn(ftp)。空闲连接可能已被远端断开
    （PS5 侧重启过 zftpd 属常态），失败时换新连接把 fn 再跑一次。"""
    key = (host, port)
    with _ftp_pool_cv:
        while not _ftp_idle:
            _ftp_pool_cv.wait()
        slot = _ftp_idle.pop()
    slot.lock.acquire()                    # 占住槽的锁（对 await 语义友好：拿槽即持锁）
    try:
        if slot.ftp is None or slot.key != key:
            _close_slot(slot)
            slot.ftp, slot.key = _ftp_connect(host, port), key
        try:
            return fn(slot.ftp)
        except ftplib.all_errors + (OSError,):
            with _ensured_lock:             # 连接状态未知：目录缓存一并作废
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
    """取远端文件大小。SIZE 前强制 TYPE I：部分服务器（pyftpdlib/zftpd 类）
    在列表等操作后会把会话切回 ASCII 模式并拒绝 SIZE。"""
    try:
        ftp.voidcmd("TYPE I")
    except ftplib.error_perm:
        pass
    return int(ftp.size(path) or 0)


def ftp_mkd_p(ftp, path, cache_key=None):
    """逐级建目录，已存在的层级跳过；cache_key 命中缓存时一次往返都不发。"""
    current = ""
    for part in [p for p in path.split("/") if p and p != "."]:
        current += "/" + part
        if cache_key and (cache_key[0], cache_key[1], current) in _ensured_dirs:
            continue
        try:
            ftp.mkd(current)
        except ftplib.error_perm:
            pass                    # 已存在
        if cache_key:
            with _ensured_lock:
                _ensured_dirs.add((cache_key[0], cache_key[1], current))
    return current or "/"


def ftp_list(ftp, path):
    """列目录。必须先 CWD 再用无参数 MLSD/NLST：部分实现的 MLSD 会忽略路径参数、
    只列服务器自己的当前目录（cmd.c: opendir(env->cwd)），带路径调用永远返回
    根目录的列表——表现为"点任何目录内容都不变"。"""
    path = posixpath.normpath(path)
    if not path.startswith("/"):
        path = "/" + path
    ftp.cwd(path)
    entries = []
    try:
        for name, facts in ftp.mlsd():
            name = name.rstrip("/").rsplit("/", 1)[-1]   # 防御：个别服务器返回带路径的名字
            if name in ("", ".", ".."):
                continue
            entries.append({
                "name": name,
                "dir": facts.get("type") == "dir",
                "size": int(facts.get("size") or 0),
                "mtime": facts.get("modify") or "",      # YYYYmmddHHMMSS，无则空
            })
    except ftplib.error_perm:
        # 服务器不支持 MLSD：NLST 只给名字，逐个用 CWD 探测是不是目录
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
    # 目录置顶按名字排；文件按修改时间倒序（最近的在最前，同类时间按名字）
    dirs = sorted((e for e in entries if e["dir"]), key=lambda e: e["name"].lower())
    files = [e for e in entries if not e["dir"]]
    files.sort(key=lambda e: e["name"].lower())
    files.sort(key=lambda e: e["mtime"], reverse=True)
    return dirs + files


def ftp_rmd_tree(ftp, path):
    """递归删除远端目录：先删深层文件，再自底向上删空目录。"""
    for entry in ftp_list(ftp, path):
        full = posixpath.join(path, entry["name"])
        if entry["dir"]:
            ftp_rmd_tree(ftp, full)
        else:
            ftp.delete(full)
    ftp.rmd(path)


def ftp_walk_manifest(ftp, path, prefix, out):
    """递归收集目录树到 out：{相对路径: 大小}。大小直接取自 MLSD facts，
    整棵树每个目录只花一次 CWD+MLSD，不做逐文件 SIZE。"""
    for entry in ftp_list(ftp, path):
        rel = prefix + entry["name"]
        if entry["dir"]:
            ftp_walk_manifest(ftp, posixpath.join(path, entry["name"]), rel + "/", out)
        else:
            out[rel] = entry["size"]


def ftp_walk_files(ftp, path, prefix, dirs, files):
    """收集目录树：dirs 收相对目录名，files 收 (远端完整路径, zip 内相对名)。"""
    dirs.append(prefix)
    for entry in ftp_list(ftp, path):
        full = posixpath.join(path, entry["name"])
        rel = prefix + entry["name"]
        if entry["dir"]:
            ftp_walk_files(ftp, full, rel + "/", dirs, files)
        else:
            files.append((full, rel))


def ftp_remote_path(raw, base=None):
    """清洗前端传来的远端路径：归一化、去 ..，可相对 base。"""
    path = unquote(raw or "/").replace("\\", "/")
    if base and not path.startswith("/"):
        path = posixpath.join(base, path)
    path = posixpath.normpath(path)
    if not path.startswith("/"):
        path = "/" + path
    return path


class _BodyReader:
    """把 HTTP 请求体包装成 storbinary 要的 file-like，边收边转发、不落盘。"""

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


# ---------------- 上传调度器（FTP 写入并发统一在服务端自适应）----------------
# 设计：浏览器只负责把小文件打成大批量（约 5 个并发 HTTP 就能喂满）；所有批量
# 文件进入这一个全局队列，由 M 个常驻写入工人在连接池上消费。M 按"每文件耗时"
# 自适应——小文件(≤64KB)耗时≈事务固定开销，大文件有效速率=(大小-64KB)/(耗时-开销)；
# 开销主导则加路摊薄、单通道速率被挤占则减半，M ∈ [FTP_SCHED_MIN, FTP_SCHED_MAX]。
# 批量数据完整在内存中，STOR 失败可安全重试（流式单发不可倒带，不走这里）。

FTP_SCHED_MIN = 2
FTP_SCHED_MAX = 16          # 不超过连接池


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
    "overhead": 0.2,        # s：小文件事务固定开销的滑动估计
    "rate_now": 0.0,        # B/s：单通道有效载荷速率
    "rate_best": 0.0,
    "big_at": 0.0,          # 最后一次大文件样本（monotonic）
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
                    out(f"[ftp] 写入并发 ↓ {target} 路（单通道 {_mbps(s['rate_now'])} 被挤占，带宽到顶）")
            elif s["rate_now"] >= 0.85 * s["rate_best"] and s["target"] < FTP_SCHED_MAX:
                s["target"] += 1
                s["last_adj"] = now
                out(f"[ftp] 写入并发 ↑ {s['target']} 路（单通道 {_mbps(s['rate_now'])} 仍有余量）")
        elif s["target"] < FTP_SCHED_MAX:
            s["target"] += 1
            s["last_adj"] = now
            out(f"[ftp] 写入并发 ↑ {s['target']} 路（小文件事务开销约 {int(s['overhead'] * 1000)}ms/个，加路摊薄）")


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
            with _sched_lock:                     # 空闲时才允许降档收工，绝不丢任务
                if _sched["workers"] > _sched["target"]:
                    _sched["workers"] -= 1
                    return
            continue
        start = time.monotonic()
        try:
            def _stor(ftp):
                parent = posixpath.dirname(job.name)
                if parent:      # 相对子路径：先逐级建父目录（有缓存，一批只建一次）
                    ftp_mkd_p(ftp, posixpath.join(job.path, parent),
                              cache_key=(job.host, job.port))
                ftp.storbinary("STOR " + posixpath.join(job.path, job.name),
                               io.BytesIO(job.data), blocksize=64 * 1024)
            ftp_run(job.host, job.port, _stor)    # 数据在内存：连接坏了也能安全重试
            job.result = {"name": job.name, "ms": round((time.monotonic() - start) * 1000)}
        except Exception as error:
            job.result = {"name": job.name, "error": str(error)}
        finally:
            _sched_note(len(job.data), time.monotonic() - start)
            _sched_adjust()
            _sched_ensure()
            job.event.set()


def _sched_submit(host, port, path, files):
    """files: [(name, bytes)]，全部入队并等完成，返回逐文件结果。"""
    _sched_ensure()
    jobs = [_UploadJob(host, port, path, name, data) for name, data in files]
    for job in jobs:
        _sched["queue"].put(job)
    for job in jobs:
        job.event.wait()
    with _sched_lock:
        lanes = _sched["target"]
    return [job.result for job in jobs], lanes


# ---------------- 已破解检测（探测请求方即 PS5 本机的破解端口）----------------

JB_PROBE_PORTS = (9021, 2120, 8888, 8734)   # elfldr / zftpd FTP / zftpd ZHTTP / panplay
JB_PROBE_TIMEOUT = 0.6


def probe_tcp(ip, port, timeout=JB_PROBE_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


# ---------------- HTTP/HTTPS（80 / 443）----------------

class SiteHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    # ---- 基础应答 ----
    def _send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    # ---- 路由 ----
    def do_GET(self):
        route = urlsplit(self.path)
        if route.path == "/document" or route.path.startswith("/document/"):
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if route.path == "/api/ftp/list":
            self._api_list(parse_qs(route.query))
            return
        if route.path == "/api/jbstate":
            self._api_jbstate()
            return
        if route.path == "/api/ftp/get":
            self._api_get(parse_qs(route.query))
            return
        if route.path == "/api/ftp/zip":
            self._api_zip(parse_qs(route.query))
            return
        super().do_GET()

    def do_POST(self):
        route = urlsplit(self.path).path
        try:
            if route == "/api/ftp/put":
                self._api_put()
            elif route == "/api/ftp/mkdir":
                self._api_mkdir()
            elif route == "/api/ftp/delete":
                self._api_delete()
            elif route == "/api/ftp/rename":
                self._api_rename()
            elif route == "/api/ftp/check":
                self._api_check()
            elif route == "/api/ftp/putbatch":
                self._api_putbatch()
            else:
                self._send_json(404, {"error": "未知接口"})
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            out(f"[ftp] 400 {route}：{error}")
        except Exception as error:
            self._send_json(502, {"error": str(error)})
            out(f"[ftp] 502 {route}：{error}")

    # ---- /api/ftp/* ----
    def _api_jbstate(self):
        """探测发起请求的设备（就是 PS5）的破解相关端口：elfldr 在线则首页跳过漏洞利用。"""
        ip = self.client_address[0]
        results = {}
        threads = []
        for port in JB_PROBE_PORTS:
            thread = threading.Thread(
                target=lambda p=port: results.update({p: probe_tcp(ip, p)})
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        open_ports = [p for p in JB_PROBE_PORTS if results.get(p)]
        self._send_json(200, {
            "ip": ip,
            "ports": {str(p): results.get(p, False) for p in JB_PROBE_PORTS},
            "jailbroken": bool(open_ports),
        })
        if open_ports:
            out(f"[jb] {ip} elfldr 仍在线（端口 {open_ports}），页面跳过漏洞利用")

    def _api_list(self, query):
        try:
            host = (query.get("host") or [""])[0].strip()
            port = int((query.get("port") or [str(FTP_PORT_DEFAULT)])[0] or FTP_PORT_DEFAULT)
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
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            out(f"[ftp] 400 list：{error}")
        except Exception as error:
            self._send_json(502, {"error": str(error)})
            out(f"[ftp] 502 list：{error}")

    def _api_put(self):
        host = self.headers.get("X-Ftp-Host", "").strip()
        port = int(self.headers.get("X-Ftp-Port") or FTP_PORT_DEFAULT)
        remote = ftp_remote_path(self.headers.get("X-Ftp-Path") or "")
        length = int(self.headers.get("Content-Length") or -1)
        if not host or remote == "/" or length < 0:
            raise ValueError(f"put 参数不完整：host={host!r} path={remote!r} length={length}")
        ftp_run(host, port, lambda ftp: ftp.pwd())     # 先探活（坏线在此重连）
        def _stor(ftp):
            parent = posixpath.dirname(remote)
            if parent not in ("", "/"):
                ftp_mkd_p(ftp, parent, cache_key=(host, port))
            ftp.storbinary(
                "STOR " + remote, _BodyReader(self.rfile, length), blocksize=64 * 1024
            )
        ftp_run(host, port, _stor, retry=False)         # 请求体是流：不可重试
        self._send_json(200, {"path": remote, "size": length})
        out(f"[ftp] 上传 {remote}（{length} 字节）→ {host}:{port}")

    def _api_mkdir(self):
        data = self._read_json()
        host = str(data.get("host", "")).strip()
        port = int(data.get("port") or FTP_PORT_DEFAULT)
        path = ftp_remote_path(data.get("path") or "")
        if not host or path == "/":
            raise ValueError("缺少 PS5 地址 / 目录路径")
        made = ftp_run(host, port, lambda ftp: ftp_mkd_p(ftp, path, cache_key=(host, port)))
        self._send_json(200, {"path": made})

    def _api_delete(self):
        data = self._read_json()
        host = str(data.get("host", "")).strip()
        port = int(data.get("port") or FTP_PORT_DEFAULT)
        path = ftp_remote_path(data.get("path") or "")
        if not host or path == "/":
            raise ValueError("缺少 PS5 地址 / 目标路径")
        def _delete(ftp):
            if data.get("dir"):
                if data.get("recursive"):
                    ftp_rmd_tree(ftp, path)      # 整个文件夹连内容一起删
                else:
                    ftp.rmd(path)                # 只删空目录
            else:
                ftp.delete(path)
        ftp_run(host, port, _delete)
        with _ensured_lock:                 # 目录结构变了：MKD 缓存一并作废
            _ensured_dirs.clear()
        self._send_json(200, {"path": path})
        out(f"[ftp] 删除 {path}{'（递归）' if data.get('recursive') else ''}")

    def _api_rename(self):
        data = self._read_json()
        host = str(data.get("host", "")).strip()
        port = int(data.get("port") or FTP_PORT_DEFAULT)
        path = ftp_remote_path(data.get("path") or "")
        to = ftp_remote_path(str(data.get("to") or ""), base=posixpath.dirname(path))
        if not host or path == "/" or to == "/" or to == path:
            raise ValueError("缺少 PS5 地址 / 目标路径，或新旧路径相同")
        def _rename(ftp):
            parent = posixpath.dirname(to)
            if parent not in ("", "/"):
                ftp_mkd_p(ftp, parent, cache_key=(host, port))   # 移动目标层级不存在时先建
            ftp.rename(path, to)
        ftp_run(host, port, _rename)
        with _ensured_lock:
            _ensured_dirs.clear()
        self._send_json(200, {"path": to})
        out(f"[ftp] 重命名/移动 {path} → {to}")

    def _api_check(self):
        """增量续传：拿前端清单（相对路径+大小）对比 PS5 现状，返回需要上传的子集。"""
        data = self._read_json()
        host = str(data.get("host", "")).strip()
        port = int(data.get("port") or FTP_PORT_DEFAULT)
        path = ftp_remote_path(data.get("path") or "")
        manifest = data.get("files") or []
        if not host or path == "/" or not isinstance(manifest, list):
            raise ValueError("缺少 PS5 地址 / 目标目录 / 文件清单")
        existing = {}
        ftp_run(host, port, lambda ftp: ftp_walk_manifest(ftp, path, "", existing))
        need = [m.get("name") for m in manifest
                if existing.get(m.get("name")) != m.get("size")]
        self._send_json(200, {
            "total": len(manifest),
            "need": need,
            "skip": len(manifest) - len(need),
        })
        out(f"[ftp] 增量检查 {path}：清单 {len(manifest)}，跳过 {len(manifest) - len(need)}，待传 {len(need)}")

    def _api_putbatch(self):
        """小文件批量上传：一个 HTTP 请求带多个文件，绕开浏览器同源并发(≈6)限制，
        服务端在连接池内并行落地。帧格式（大端）：
        [4B 文件数] × [4B 名长][名字 UTF-8][8B 大小][内容字节]"""
        host = self.headers.get("X-Ftp-Host", "").strip()
        port = int(self.headers.get("X-Ftp-Port") or FTP_PORT_DEFAULT)
        target = ftp_remote_path(self.headers.get("X-Ftp-Dir") or "")
        length = int(self.headers.get("Content-Length") or -1)
        if not host or target == "/" or length < 0:
            raise ValueError(f"putbatch 参数不完整：host={host!r} dir={target!r} length={length}")
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

        ftp_run(host, port, lambda ftp: ftp.pwd())          # 探活
        ftp_run(host, port, lambda ftp: ftp_mkd_p(ftp, target, cache_key=(host, port)))
        results, lanes = _sched_submit(host, port, target, files)
        ok = [r for r in results if "error" not in r]
        failed = [r for r in results if "error" in r]
        self._send_json(200, {"ok": ok, "failed": failed, "lanes": lanes})
        out(f"[ftp] 批量上传 {target}：成功 {len(ok)}，失败 {len(failed)} → {host}:{port}")

    def _api_get(self, query):
        try:
            host = (query.get("host") or [""])[0].strip()
            port = int((query.get("port") or [str(FTP_PORT_DEFAULT)])[0] or FTP_PORT_DEFAULT)
            path = ftp_remote_path((query.get("path") or [""])[0])
            if not host or path == "/":
                raise ValueError("缺少 PS5 地址 / 文件路径")
            def _download(ftp):
                try:
                    size = ftp_size(ftp, path)
                except Exception as error:
                    raise ValueError("读不到文件大小（SIZE 命令失败），无法下载") from error
                name = posixpath.basename(path)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                self.send_header(
                    "Content-Disposition",
                    "attachment; filename*=UTF-8''" + quote(name),
                )
                self.end_headers()
                ftp.retrbinary("RETR " + path, self.wfile.write, blocksize=64 * 1024)
                return size
            size = ftp_run(host, port, _download, retry=False)   # 头发出后中途失败只能断开
            out(f"[ftp] 下载 {path}（{size} 字节）→ {host}")
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            out(f"[ftp] 400 get：{error}")
        except Exception as error:
            self._send_json(502, {"error": str(error)})
            out(f"[ftp] 502 get：{error}")

    def _api_zip(self, query):
        try:
            host = (query.get("host") or [""])[0].strip()
            port = int((query.get("port") or [str(FTP_PORT_DEFAULT)])[0] or FTP_PORT_DEFAULT)
            path = ftp_remote_path((query.get("path") or [""])[0])
            if not host or path == "/":
                raise ValueError("缺少 PS5 地址 / 目录路径")
            dirs, files = [], []
            ftp_run(host, port, lambda ftp: ftp_walk_files(
                ftp, path, posixpath.basename(path) + "/", dirs, files))

            def _pack(ftp):
                spool = tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024)
                with zipfile.ZipFile(spool, "w", zipfile.ZIP_STORED) as zf:
                    for rel in dirs:            # 空目录也保留结构
                        zf.writestr(zipfile.ZipInfo(rel.rstrip("/") + "/"), b"")
                    for remote, rel in files:
                        try:
                            size = ftp_size(ftp, remote)
                        except Exception as error:
                            raise ValueError(f"读不到 {remote} 的大小，无法打包") from error
                        info = zipfile.ZipInfo(rel)
                        info.file_size = size   # STORED 模式要求写前给出精确大小
                        with zf.open(info, "w") as dst:
                            ftp.retrbinary(
                                "RETR " + remote, dst.write, blocksize=64 * 1024
                            )
                spool.seek(0, 2)
                total = spool.tell()
                spool.seek(0)
                name = posixpath.basename(path) + ".zip"
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(total))
                self.send_header(
                    "Content-Disposition",
                    "attachment; filename*=UTF-8''" + quote(name),
                )
                self.end_headers()
                while True:                     # spool 可能溢出到磁盘，分块发
                    chunk = spool.read(64 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                return total

            total = ftp_run(host, port, _pack, retry=False)
            out(f"[ftp] 打包下载 {path}（{len(dirs)} 目录 {len(files)} 文件，{total} 字节）→ {host}")
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            out(f"[ftp] 400 zip：{error}")
        except Exception as error:
            self._send_json(502, {"error": str(error)})
            out(f"[ftp] 502 zip：{error}")

    def log_message(self, fmt, *args):
        out(f"[web] {self.address_string()}  {fmt % args}")


def start_server(port, use_tls):
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT, KEY)
        # PS5 打开「用户指南」入口时会反复拒绝自签证书（unknown ca），
        # 默认行为是每个线程打一整段 traceback 刷屏：这里压成单行并去重。
        tls_quiet = {}
        tls_quiet_lock = threading.Lock()

        class TLSServer(ThreadingHTTPServer):
            def finish_request(self, request, client_address):
                try:
                    request = context.wrap_socket(request, server_side=True)
                except (ssl.SSLError, OSError) as error:
                    try:
                        request.close()
                    except OSError:
                        pass
                    reason = getattr(error, "reason", None) or type(error).__name__
                    key = (client_address[0], reason)
                    with tls_quiet_lock:
                        tls_quiet[key] = tls_quiet.get(key, 0) + 1
                        count = tls_quiet[key]
                    if count == 1:
                        out(f"[web] TLS 握手被 {client_address[0]} 拒绝（{reason}，"
                            f"自签证书警告未确认，属预期现象，不阻塞站点）")
                    elif count % 20 == 0:
                        out(f"[web] TLS 握手拒绝（{client_address[0]}，{reason}）已累计 {count} 次")
                    return
                super().finish_request(request, client_address)

        server = TLSServer(("0.0.0.0", port), SiteHandler)
    else:
        server = ThreadingHTTPServer(("0.0.0.0", port), SiteHandler)
    scheme = "https" if use_tls else "http"
    out(f"[web] 监听 {scheme}://0.0.0.0:{port}")
    # 必须在持有引用的线程里 serve_forever：线程返回会让 server 被 GC 关掉端口
    server.serve_forever()


def main():
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass

    if not os.path.exists(os.path.join(ROOT, "index.html")):
        out("[!] 未找到 index.html —— 请在本仓库目录下运行本脚本。")
        sys.exit(1)

    host_ip = detect_lan_ip()
    out("=" * 54)
    out("  PS5 Relapse All-in-One Host")
    out("-" * 54)
    out(f"  本机 IP     : {host_ip}")
    others = [ip for ip in ranked_lan_ips() if ip != host_ip]
    if others:
        out(f"  备选 IP     : {', '.join(others[:3])}（选错就改脚本顶部 HOST_IP）")
    out(f"  PS5 浏览器  : http://{host_ip}/")
    out(f"  传文件到 PS5 : http://{host_ip}/ftp.html （先在破解页发送 zftpd，端口 2120）")
    out(f"  PS5 手动 DNS: 首选 {host_ip}   备用留空")
    out("  指南入口    : 设置 → 用户指南（证书警告点继续）")
    out("-" * 54)
    out("  拦截范围    : playstation.net/.com、sony*.com/.net、")
    out("                psn.com、scea.com 等 → NXDOMAIN")
    out("  关闭窗口即停止服务；破解期间勿让电脑休眠")
    out("=" * 54)

    if not os.path.exists(CERT) or not os.path.exists(KEY):
        out(f"[!] 缺少证书文件 {CERT} —— 用户指南(443)入口将不可用。")

    # 端口预检：绑定失败给出明确指引，而不是中途崩
    for name, port, kind in (("DNS", DNS_PORT, socket.SOCK_DGRAM),
                             ("HTTP", HTTP_PORT, socket.SOCK_STREAM),
                             ("HTTPS", HTTPS_PORT, socket.SOCK_STREAM)):
        probe = socket.socket(socket.AF_INET, kind)
        try:
            probe.bind(("0.0.0.0", port))
        except OSError as error:
            out(f"[!] {name} 端口 {port} 被占用：{error}")
            if name == "DNS":
                out("    PS5 DNS 指向本机将不可用；PS5 端 DNS 固定走 53，只能释放本机端口。")
            elif name == "HTTPS":
                out("    用户指南入口不可用；站点功能不受影响。")
            else:
                out("    改脚本顶部 HTTP_PORT（如 8080），访问地址同步带端口号。")
                out("    按回车退出。")
                input()
                sys.exit(1)
        finally:
            probe.close()

    threading.Thread(target=dns_loop, args=(host_ip,), daemon=True).start()
    threading.Thread(target=start_server, args=(HTTPS_PORT, True), daemon=True).start()

    try:
        start_server(HTTP_PORT, False)
    except OSError as error:
        out(f"[!] HTTP {HTTP_PORT} 绑定失败：{error}")
        input()
        sys.exit(1)


if __name__ == "__main__":
    main()
