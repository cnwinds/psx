#!/bin/sh
# PS5 host 容器入口：dnsmasq（DNS 劫持 + 更新屏蔽） + nginx（HTTP/HTTPS 静态站）
# 幂等：证书不存在或 7 天内到期才重建，其余重启不改变状态。
set -e

apk add -U dnsmasq nginx openssl python3 >/dev/null

# --- 自签证书（必须带 SAN：PS5 WebKit 校验 SAN 而非 CN） ---
mkdir -p /srv/certs
if [ ! -s /srv/certs/cert.pem ] || [ ! -s /srv/certs/key.pem ] || \
   ! openssl x509 -checkend 604800 -noout -in /srv/certs/cert.pem >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout /srv/certs/key.pem -out /srv/certs/cert.pem \
        -subj '/CN=manuals.playstation.net' \
        -addext 'subjectAltName=DNS:manuals.playstation.net'
    echo "ps5-host: generated new certificate (365 days)"
fi

# --- nginx：80/443 静态站 + 用户指南路径回首页 ---
# PS5 用户指南打开的是 https://manuals.playstation.net/document/...，
# 必须 302 回 / 才能落到 exploit 页面（参照 flex36ty 的 serve_https.py 行为）。
# payload_map.js 能连上目录站就回源，失败则用仓库快照。页面只请求同源地址。
# 加入的 ELF 写到 /srv/payload-library，经 /payloads/library/ 给 elfldr 下载。
cat > /etc/nginx/psx-site.conf <<'EOF'
location = /api/payload/release {
    proxy_pass http://127.0.0.1:8765;
    proxy_connect_timeout 5s;
    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
}
location = /api/payload/fetch {
    proxy_pass http://127.0.0.1:8765;
    proxy_connect_timeout 5s;
    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
}
location /payloads/library/ {
    alias /srv/payload-library/;
    default_type application/octet-stream;
    add_header Cache-Control no-store;
}
location = /payloads/payload_map.js {
    proxy_pass http://45.56.67.85/payloads/payload_map.js;
    proxy_set_header Host 45.56.67.85;
    proxy_connect_timeout 2s;
    proxy_read_timeout 3s;
    proxy_send_timeout 3s;
    proxy_intercept_errors on;
    error_page 500 502 503 504 = @catalog_snapshot;
}
location @catalog_snapshot {
    root /srv/www;
    try_files /payloads/payload_map.js =404;
}
location /document { return 302 /; }
location / { root /srv/www; index index.html; try_files $uri $uri/ /index.html; }
EOF
cat > /etc/nginx/http.d/default.conf <<'EOF'
server {
    listen 80 default_server;
    include /etc/nginx/psx-site.conf;
}
server {
    listen 443 ssl default_server;
    ssl_certificate     /srv/certs/cert.pem;
    ssl_certificate_key /srv/certs/key.pem;
    include /etc/nginx/psx-site.conf;
}
EOF

mkdir -p /srv/payload-library
if [ -f /srv/www/scripts/payload_store.py ]; then
    python3 /srv/www/scripts/payload_store.py --bind 127.0.0.1:8765 --root /srv/payload-library &
    echo "ps5-host: payload library on 127.0.0.1:8765"
fi

dnsmasq --test -C /etc/ps5-dnsmasq.conf

dnsmasq --no-daemon -C /etc/ps5-dnsmasq.conf &
echo "ps5-host: dnsmasq up (53/udp), nginx starting (80/443)"
exec nginx -g "daemon off;"
