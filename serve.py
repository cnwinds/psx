#!/usr/bin/env python3
"""PS5 Relapse All-in-One Host — 纯 Python 一体化（Windows 双击 start-host.bat 即用）

一个进程包含全部功能：
  DNS  : udp/53   —— 索尼全系域名 NXDOMAIN 拦截 + manuals.playstation.net 劫持到本机
  HTTPS: tcp/443  —— 用户指南/健康与安全指南入口（自签证书 + /document 回首页）
  HTTP : tcp/80   —— 站点本体（PS5 浏览器手输 http://本机IP/ 也可进入）

PS5 侧设置：手动 DNS 首选填本机 IP，备用留空。
"""

import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

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


# ---------------- HTTP/HTTPS（80 / 443）----------------

class SiteHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/document" or path.startswith("/document/"):
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, fmt, *args):
        out(f"[web] {self.address_string()}  {fmt % args}")


def start_server(port, use_tls):
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT, KEY)

        class TLSServer(ThreadingHTTPServer):
            def finish_request(self, request, client_address):
                request = context.wrap_socket(request, server_side=True)
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
