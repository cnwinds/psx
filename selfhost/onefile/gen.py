#!/usr/bin/env python3
"""Generate selfhost/onefile/docker-compose.yml — a single-file, zero-mount
QNAP Container Station deployment.

Embeds the repo's all-in-one front-end files (index.html, src/site.js,
src/main.js, src/payload_loader.js) into the compose command block so the
container needs no files on the NAS. The exploit chain itself and the payload
binaries are downloaded at first boot from public GitHub sources.

Run from this directory:  python gen.py
"""

from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

FILES = {
    "HTML_EOF": (REPO / "index.html", "/srv/www/index.html"),
    "SITE_EOF": (REPO / "src" / "site.js", "/srv/www/src/site.js"),
    "MAIN_EOF": (REPO / "src" / "main.js", "/srv/www/src/main.js"),
    "LOADR_EOF": (REPO / "src" / "payload_loader.js", "/srv/www/src/payload_loader.js"),
}

# heredoc 定界符不能出现在文件内容里；结尾换行自动补齐。
for marker, (path, _) in FILES.items():
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.strip() == marker:
            raise SystemExit(f"{path} contains heredoc delimiter {marker}!")

overlays = []
for marker, (path, dest) in FILES.items():
    body = path.read_text(encoding="utf-8")
    # 去掉每行行首可能的缩进差异，heredoc 定界符顶格
    lines = "\n".join(ln.rstrip() for ln in body.splitlines())
    overlays.append(f"cat > {dest} <<'{marker}'\n{lines}\n{marker}")
OVERLAY = "\n".join(overlays)

SCRIPT = f"""set -e
# ---------- PS5 all-in-one host（单文件版，无需 NAS 上的任何本地文件） ----------
apk add -U dnsmasq nginx openssl curl >/dev/null

LAN_IP=$(ip -4 addr show dev eth0 | awk '/inet /{{split($2,a,"/"); print a[1]; exit}}')
echo "ps5-host: container IP = $LAN_IP (PS5 首选 DNS 填这个，备用留空)"

# ---------- 站点内容：首次启动从公共源下载，命名卷持久化 ----------
if [ ! -f /srv/www/.site-ready ]; then
    echo "ps5-host: downloading exploit site (first boot)..."
    mkdir -p /srv/www
    # 漏洞链基础（公共 fork；如不可达可换 ntfargo/Relapse-Exploit）
    curl -fsSL https://github.com/cnwinds/Relapse-Exploit/archive/refs/heads/main.tar.gz \\
        | tar -xz -C /srv/www --strip-components=1
    # 三个 payload（官方 release，与仓库 payloads/ 同版本）
    cd /srv/www/payloads
    [ -s kstuff.elf ]          || curl -fL -o kstuff.elf          https://github.com/EchoStretch/kstuff-lite/releases/download/v1.11/kstuff.elf
    [ -s etaHEN-2.5B.bin ]     || curl -fL -o etaHEN-2.5B.bin     https://github.com/etaHEN/etaHEN/releases/download/2.5B/etaHEN-2.5B.bin
    [ -s shadowmountplus.elf ] || curl -fL -o shadowmountplus.elf https://github.com/drakmor/ShadowMountPlus/releases/download/1.7beta3/shadowmountplus.elf
    cd /
    touch /srv/www/.site-ready
    echo "ps5-host: site ready"
fi

# ---------- 覆盖为 all-in-one 页面（每次启动都重写，保持与仓库一致） ----------
{OVERLAY}

# ---------- 自签证书（SAN 必须有；剩余不足 7 天才重建） ----------
mkdir -p /srv/certs
if [ ! -s /srv/certs/cert.pem ] || [ ! -s /srv/certs/key.pem ] || \\
   ! openssl x509 -checkend 604800 -noout -in /srv/certs/cert.pem >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \\
        -keyout /srv/certs/key.pem -out /srv/certs/cert.pem \\
        -subj '/CN=manuals.playstation.net' \\
        -addext 'subjectAltName=DNS:manuals.playstation.net'
    echo "ps5-host: generated new certificate (365 days)"
fi

# ---------- DNS：接管用户指南入口 + NXDOMAIN 屏蔽更新 ----------
cat > /etc/ps5-dnsmasq.conf <<DNS_EOF
no-resolv
server=223.5.5.5
server=119.29.29.29
domain-needed
cache-size=1000
local=/manuals.playstation.net/
address=/manuals.playstation.net/$LAN_IP
address=/ps5.update.playstation.net/
address=/ps4.update.playstation.net/
address=/feu01.ps4.update.playstation.net/
DNS_EOF

# ---------- HTTP/HTTPS：静态站 + 用户指南 /document 路径回首页 ----------
cat > /etc/nginx/http.d/default.conf <<'NGINX_EOF'
server {{
    listen 80 default_server;
    location /document {{ return 302 /; }}
    location / {{ root /srv/www; index index.html; try_files $uri $uri/ /index.html; }}
}}
server {{
    listen 443 ssl default_server;
    ssl_certificate     /srv/certs/cert.pem;
    ssl_certificate_key /srv/certs/key.pem;
    location /document {{ return 302 /; }}
    location / {{ root /srv/www; index index.html; try_files $uri $uri/ /index.html; }}
}}
NGINX_EOF

dnsmasq --test -C /etc/ps5-dnsmasq.conf
dnsmasq --no-daemon -C /etc/ps5-dnsmasq.conf &
echo "ps5-host: all services up — DNS 53 / HTTP 80 / HTTPS 443"
exec nginx -g "daemon off;"
"""

COMPOSE = """\
# PS5 Relapse All-in-One — 单文件部署（QNAP Container Station 直接粘贴即可，无需 SSH）
# 使用方法见 selfhost/onefile/README.md。
#
# >>> 只需修改下面 4 处网络参数 <<<
#   1. parent:  QTS 开了虚拟交换机填 ovs_eth0，没开填 eth0
#   2. subnet:  你的网段
#   3. gateway: 你的网关
#   4. ipv4_address: 给容器的固定 IP（与网段一致，避开已占用地址）
services:
  ps5-host:
    image: alpine:3.20
    container_name: ps5-host
    restart: unless-stopped
    command:
      - sh
      - -c
      - |
""" + "\n".join("        " + ln if ln else "" for ln in SCRIPT.splitlines()) + """
    networks:
      lan:
        ipv4_address: 192.168.1.250
    volumes:
      - ps5-certs:/srv/certs
      - ps5-www:/srv/www

networks:
  lan:
    driver: macvlan
    driver_opts:
      parent: ovs_eth0
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: 192.168.1.1

volumes:
  ps5-certs:
  ps5-www:
"""

out = HERE / "docker-compose.yml"
out.write_text(COMPOSE, encoding="utf-8", newline="\n")
print(f"wrote {out} ({len(COMPOSE)} bytes)")
