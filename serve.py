#!/usr/bin/env python3
"""PS5 Relapse All-in-One Host — 纯 Python 一体化（Windows 双击 start-host.bat 即用）

一个进程包含全部功能：
  DNS  : udp/53   —— 索尼全系域名 NXDOMAIN 拦截（store/image.api 例外放行）+ manuals 劫持到本机
  HTTPS: tcp/443  —— 用户指南/健康与安全指南入口（自签证书 + /document 回首页）
  HTTP : tcp/80   —— 站点本体（PS5 浏览器手输 http://本机IP/ 也可进入）
  FTP  : /ftp.html —— 局域网加速中转（批量小文件）；公网部署走「浏览器直连 PS5」

PS5 侧设置：手动 DNS 首选填本机 IP，备用留空。
"""

import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import queue
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from ftp_relay import FtpRelayHandler, RelayNotAllowed, configure as configure_ftp_relay

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
# 商店元数据抓取例外（store_meta）：优先于上面的全拦，走上游正常解析
#   store.playstation.com      商店页：中文名/简介/发行商/发售日
#   image.api.playstation.com  封面 CDN（?w=440，存 covers/）
ALLOWED_DOMAINS = (
    "store.playstation.com",
    "image.api.playstation.com",
)
GUIDE_DOMAIN = "manuals.playstation.net"    # 劫持到本机（用户指南入口）
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
        allowed = any(name == d or name.endswith("." + d) for d in ALLOWED_DOMAINS)
        if name == GUIDE_DOMAIN or name.endswith("." + GUIDE_DOMAIN):
            record_ps5_candidate(addr[0], "dns", "DNS 指南入口活跃")
            sock.sendto(a_response(data, host_ip), addr)
            out(f"[dns] {name} -> {host_ip}  (指南入口，来自 {addr[0]})")
        elif not allowed and any(name == s or name.endswith("." + s) for s in BLOCKED_SUFFIXES):
            record_ps5_candidate(addr[0], "dns", "PS5 DNS 活跃")
            sock.sendto(error_response(data, 3), addr)   # NXDOMAIN（高频请求，不打印日志）
        else:
            # 放行例外（store_meta 商店元数据/封面）与其余域名一起走上游
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


# ---------------- 已破解检测（探测请求方即 PS5 本机的破解端口）----------------

JB_PROBE_PORTS = (9021, 2120, 2121, 8888, 8080)   # elfldr / zftpd / ftpsrv / ZHTTP / websrv
JB_PROBE_TIMEOUT = 0.6

_seen_devices_lock = threading.Lock()
_seen_devices = {}   # ip -> {"ip": str, "source": str, "label": str, "ts": float, "ports": dict}


def _is_valid_lan_ipv4(ip):
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    if nums[0] in (0, 127) or nums[0] >= 224 or nums[3] in (0, 255):
        return False
    return True


def record_ps5_candidate(ip, source="seen", label="局域网设备", ports=None):
    """记录发现的疑似/确认 PS5 设备 IP（来自 DNS 拦截、PS5 UA 或端口扫描）。"""
    if not _is_valid_lan_ipv4(ip):
        return
    host_ips = set(ranked_lan_ips())
    # 排除宿主机自身 IP（除非确实在本机开了 PS5 模拟端口）
    if ip in host_ips and not (ports and any(ports.values())):
        return
    with _seen_devices_lock:
        prev = _seen_devices.get(ip, {})
        # 高优先级来源不被低优先级覆盖
        priority = {"ps5-ua": 4, "port-scan": 3, "ftp": 3, "dns": 2, "arp": 1}
        old_p = priority.get(prev.get("source"), 0)
        new_p = priority.get(source, 1)
        chosen_source = source if new_p >= old_p else prev.get("source", source)
        chosen_label = label if new_p >= old_p else prev.get("label", label)
        merged_ports = dict(prev.get("ports") or {})
        if ports:
            merged_ports.update({str(k): bool(v) for k, v in ports.items()})
        _seen_devices[ip] = {
            "ip": ip,
            "source": chosen_source,
            "label": chosen_label,
            "ts": time.time(),
            "ports": merged_ports,
        }


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


def probe_ports_map(ip, timeout=JB_PROBE_TIMEOUT):
    results = {}
    threads = []
    for port in JB_PROBE_PORTS:
        thread = threading.Thread(
            target=lambda p=port: results.update({str(p): probe_tcp(ip, p, timeout)})
        )
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    return {str(p): results.get(str(p), False) for p in JB_PROBE_PORTS}


def read_arp_neighbors():
    """读取本机 ARP 缓存表，筛选与宿主机同 /24 网段的活跃邻居 IP（排除 .1 网关与自身）。"""
    host_ips = ranked_lan_ips()
    prefixes = {".".join(ip.split(".")[:3]) + "." for ip in host_ips if _is_valid_lan_ipv4(ip)}
    if not prefixes:
        return []
    try:
        raw = subprocess.run(["arp", "-a"], capture_output=True, timeout=2).stdout.decode(errors="replace")
    except (OSError, subprocess.SubprocessError):
        return []
    neighbors = []
    host_set = set(host_ips)
    for token in raw.replace("(", " ").replace(")", " ").split():
        if not any(token.startswith(pfx) for pfx in prefixes):
            continue
        if not _is_valid_lan_ipv4(token) or token in host_set:
            continue
        last_octet = int(token.split(".")[3])
        if last_octet in (1, 254, 255):
            continue
        if token not in neighbors:
            neighbors.append(token)
    return neighbors[:16]


def discover_ps5_candidates(client_ip=None, scan_subnet=False):
    """汇总并探测局域网内的候选 PS5 IP，按可信度排序返回。"""
    host_ips = set(ranked_lan_ips())
    if _is_valid_lan_ipv4(client_ip) and client_ip not in host_ips:
        record_ps5_candidate(client_ip, "client", "当前访问设备")

    arp_ips = read_arp_neighbors()
    with _seen_devices_lock:
        seen_Snapshot = dict(_seen_devices)

    to_probe = []
    for ip in seen_Snapshot:
        if ip not in to_probe:
            to_probe.append(ip)
    for ip in arp_ips:
        if ip not in to_probe:
            to_probe.append(ip)

    # 若用户点击了「局域网全网段扫描」，额外快扫主网卡 /24 网段的 9021 / 2120 端口
    if scan_subnet:
        primary = detect_lan_ip()
        if _is_valid_lan_ipv4(primary):
            prefix = ".".join(primary.split(".")[:3]) + "."
            q = queue.Queue()
            for last in range(2, 254):
                cand = prefix + str(last)
                if cand not in host_ips and cand not in to_probe:
                    q.put(cand)
            found_from_scan = []
            found_lock = threading.Lock()

            def _scan_worker():
                while True:
                    try:
                        cand = q.get_nowait()
                    except queue.Empty:
                        return
                    if (probe_tcp(cand, 2120, 0.14) or probe_tcp(cand, 2121, 0.14)
                            or probe_tcp(cand, 9021, 0.14) or probe_tcp(cand, 8888, 0.14)):
                        with found_lock:
                            found_from_scan.append(cand)

            workers = [threading.Thread(target=_scan_worker, daemon=True) for _ in range(32)]
            for w in workers:
                w.start()
            for w in workers:
                w.join(timeout=2.5)
            for cand in found_from_scan:
                if cand not in to_probe:
                    to_probe.append(cand)

    # 并发探测所有候选 IP 的 4 个服务端口（超时 0.22s，整体耗时约 220ms）
    probed_ports = {}
    probe_threads = []
    for ip in to_probe[:24]:
        t = threading.Thread(
            target=lambda target=ip: probed_ports.update({target: probe_ports_map(target, 0.22)}),
            daemon=True,
        )
        t.start()
        probe_threads.append(t)
    for t in probe_threads:
        t.join(timeout=1.0)

    candidates = []
    for ip in to_probe[:24]:
        ports = probed_ports.get(ip) or {
            "9021": False, "2120": False, "2121": False, "8888": False, "8080": False,
        }
        open_ports = [p for p, up in ports.items() if up]
        meta = seen_Snapshot.get(ip, {})
        source = meta.get("source") or ("port-scan" if open_ports else "arp")
        label = meta.get("label") or ("端口在线" if open_ports else "局域网邻居")
        if open_ports:
            record_ps5_candidate(ip, "port-scan", label if source != "arp" else "端口扫描发现", ports)
            score = 100 + len(open_ports) * 10
        elif source in ("ps5-ua", "dns", "ftp"):
            score = 60
        elif ip == client_ip and client_ip not in host_ips:
            score = 40
        else:
            score = 10
        candidates.append({
            "ip": ip,
            "source": source,
            "label": label,
            "ports": ports,
            "open_ports": open_ports,
            "online": bool(open_ports),
            "score": score,
        })

    candidates.sort(key=lambda item: (-item["score"], item["ip"]))
    # 优先返回所有确认在线或有 PS5 痕迹的设备；若全无，则最多附带前 4 个同网段邻居供手动点选
    confirmed = [c for c in candidates if c["score"] >= 40]
    fallback_arp = [c for c in candidates if c["score"] < 40][:4]
    return confirmed + (fallback_arp if len(confirmed) < 3 else [])


# ---------------- HTTP/HTTPS（80 / 443）----------------

class SiteHandler(FtpRelayHandler, SimpleHTTPRequestHandler):
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
        ua = self.headers.get("User-Agent") or ""
        if "PlayStation 5" in ua:
            record_ps5_candidate(self.client_address[0], "ps5-ua", "PS5 浏览器访问")
        if route.path == "/document" or route.path.startswith("/document/"):
            record_ps5_candidate(self.client_address[0], "ps5-ua", "PS5 用户指南入口")
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if route.path == "/api/jbstate":
            self._api_jbstate(parse_qs(route.query))
            return
        if self.handle_ftp_get(route.path, parse_qs(route.query)):
            return
        super().do_GET()

    def do_POST(self):
        parsed = urlsplit(self.path)
        route = parsed.path
        try:
            if route == "/api/elfsend":
                self._api_elfsend(parse_qs(parsed.query))
            elif self.handle_ftp_post(route):
                pass
            else:
                self._send_json(404, {"error": "未知接口"})
        except RelayNotAllowed as error:
            self._send_json(403, {"error": str(error)})
            out(f"[api] 403 {route}：{error}")
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            out(f"[api] 400 {route}：{error}")
        except Exception as error:
            self._send_json(502, {"error": str(error)})
            out(f"[api] 502 {route}：{error}")

    def _api_elfsend(self, query=None):
        """通过宿主机向已开启 9021 端口的 PS5 直接推送 payloads/ 目录下的 ELF 载荷。"""
        query = query or {}
        raw_file = (query.get("file") or [""])[0].strip()
        target_host = (query.get("host") or [""])[0].strip() or self.client_address[0]
        if not raw_file or "/" in raw_file or "\\" in raw_file or ".." in raw_file or not raw_file.endswith(".elf"):
            raise ValueError("非法 ELF 文件名")
        elf_path = os.path.join(ROOT, "payloads", os.path.basename(raw_file))
        if not os.path.isfile(elf_path):
            raise ValueError(f"载荷文件不存在：{raw_file}")
        with open(elf_path, "rb") as fp:
            payload_bytes = fp.read()
        with socket.create_connection((target_host, 9021), timeout=10.0) as sock:
            sock.sendall(payload_bytes)
        out(f"[elf] 已向 {target_host}:9021 推送 {raw_file}（{len(payload_bytes)} 字节）")
        self._send_json(200, {"ok": True, "file": raw_file, "host": target_host, "bytes": len(payload_bytes)})

    def _api_jbstate(self, query=None):
        """探测发起请求的设备（或指定 target）的破解相关端口，并返回多源发现的候选 IP 列表。"""
        query = query or {}
        ip = self.client_address[0]
        target = (query.get("target") or [""])[0].strip()
        scan_subnet = (query.get("scan") or ["0"])[0] in ("1", "true", "yes")

        probe_ip = target if _is_valid_lan_ipv4(target) else ip
        ports_map = probe_ports_map(probe_ip, JB_PROBE_TIMEOUT)
        open_ports = [int(p) for p, up in ports_map.items() if up]
        if open_ports and _is_valid_lan_ipv4(probe_ip):
            record_ps5_candidate(probe_ip, "port-scan", "端口在线", ports_map)

        candidates = discover_ps5_candidates(client_ip=ip, scan_subnet=scan_subnet)
        host_ips = ranked_lan_ips()
        primary_host_ip = detect_lan_ip()
        if primary_host_ip and primary_host_ip not in host_ips:
            host_ips.insert(0, primary_host_ip)

        self._send_json(200, {
            "ip": probe_ip,
            "client_ip": ip,
            "host_ip": primary_host_ip,
            "host_ips": host_ips,
            "http_port": HTTP_PORT,
            "ports": ports_map,
            "jailbroken": bool(open_ports),
            "ps5_candidates": candidates,
        })
        if open_ports:
            out(f"[jb] {probe_ip} 破解服务仍在线（端口 {open_ports}），页面跳过漏洞利用")

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
    configure_ftp_relay(out, ranked_lan_ips, probe_tcp, record_ps5_candidate, _is_valid_lan_ipv4)
    out("=" * 54)
    out("  PS5 Relapse All-in-One Host")
    out("-" * 54)
    out(f"  本机 IP     : {host_ip}")
    others = [ip for ip in ranked_lan_ips() if ip != host_ip]
    if others:
        out(f"  备选 IP     : {', '.join(others[:3])}（选错就改脚本顶部 HOST_IP）")
    out(f"  PS5 浏览器  : http://{host_ip}/")
    out(f"  传文件到 PS5 : http://{host_ip}/ftp.html（局域网批量中转 + 浏览器直连）")
    out(f"  PS5 手动 DNS: 首选 {host_ip}   备用留空")
    out("  指南入口    : 设置 → 用户指南（证书警告点继续）")
    out("-" * 54)
    out("  拦截范围    : playstation.net/.com、sony*.com/.net、")
    out("                psn.com、scea.com 等 → NXDOMAIN")
    out("  放行例外    : store.playstation.com、image.api.playstation.com")
    out("                （商店元数据/封面抓取走上游正常解析）")
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
