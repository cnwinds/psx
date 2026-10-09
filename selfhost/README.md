# NAS 自托管：DNS 劫持 + HTTPS Host（QNAP Container Station）

把本仓库变成一套完全离线可控的 PS5 exploit host：**DNS 接管用户指南入口 + 更新屏蔽 + HTTPS 静态站**，不依赖任何第三方公共服务。参照了 [flex36ty/ps5-relapse-selfhost](https://github.com/flex36ty/ps5-relapse-selfhost)（其自述不含更新屏蔽）与 [Al-Azif](https://github.com/Al-Azif/chukei-dns) 的屏蔽思路，并用容器（alpine + dnsmasq + nginx）实现，适配 QNAP Container Station / 任何能跑 Docker Compose 的 NAS。

## 两种部署方式选一

- **[onefile/ 单文件版](onefile/README.md)** —— NAS 不方便 SSH 的选这个：一个 compose YAML 粘贴进 Container Station 即可，站点全部内容（页面+漏洞链+payload）首启时从公共的 [cnwinds/psx](https://github.com/cnwinds/psx) 仓库下载，只需改 4 行网络参数。
- **本目录完整版（下文）** —— 可以 SSH 的选这个：挂载仓库本体，内容与仓库完全同步，改起来最直接。

## 为什么全套自建

| 方案 | 依赖第三方 | 防手滑升级 | 说明 |
|---|---|---|---|
| 公共 DNS 45.56.67.85 | ✅ 全靠它 | 部分 | 对方关站/限流就失效（备用 62.210.38.117） |
| 只跑 serve.py | ✅ 仍需公共 DNS | ❌ | 8000 端口纯静态，不含 DNS/443，没解决问题 |
| **本方案（NAS 全套）** | ❌ | ✅ | DNS + HTTPS 一体，顺带把索尼更新域名沉掉 |

第三列是关键增益：DNS 接管 `manuals.playstation.net`（用户指南入口）的同时，把 `ps5.update.playstation.net` 等域名指向 NXDOMAIN——**主机想自动升级也解析不了**，直接消除越狱后最大的翻车点。

## 与原始手稿方案的三处修正

1. **NXDOMAIN 语法**：`address=/域名/#` 中的 `#` 非标准写法，正确写法是地址留空 `address=/域名/`（dnsmasq 官方 man page 确认返回 NXDOMAIN）。
2. **证书必须带 SAN**：PS5 的 WebKit 校验 `subjectAltName` 而非 CN，只有 CN 的自签证书可能直接连接失败（flex36ty 的脚本同样加了 SAN）。`start.sh` 已用 `-addext 'subjectAltName=DNS:manuals.playstation.net'`。
3. **用户指南路径重定向**：PS5 用户指南打开的是 `https://manuals.playstation.net/document/...` 具体路径，不重定向会 404。nginx 已配置 `location /document { return 302 /; }`（行为对齐 flex36ty 的 serve_https.py）。

## 部署步骤

**① 拿文件**：把本仓库放到 NAS，例如：

```bash
ssh admin@nas
cd /share/Containers
git clone https://github.com/cnwinds/psx.git
cd psx/selfhost
```

**② 改三处 IP/网卡**（都在 `docker-compose.yml` + `ps5-dnsmasq.conf`）：

- `ipv4_address: 192.168.1.250` → 给容器的固定内网 IP（两处文件保持一致）
- `subnet` / `gateway` → 你网段的实际值
- `parent: ovs_eth0` → QTS 开了虚拟交换机是 `ovs_eth0`，没开是 `eth0`（`ip addr` 确认）

**③ 启动**（Container Station 支持 compose，或 SSH 里）：

```bash
docker compose up -d
docker compose logs -f ps5-host   # 看到 dnsmasq up / nginx starting 即成功
```

**④ 验证**（同网段任一机器）：

```bash
nslookup manuals.playstation.net 192.168.1.250     # 应返回 192.168.1.250
nslookup ps5.update.playstation.net 192.168.1.250  # 应返回 NXDOMAIN
curl -k https://192.168.1.250/ | head              # 应返回 exploit 页面 HTML
```

**⑤ PS5 侧**：设置 → 网络 → 手动 DNS，**首选填 `192.168.1.250`，备用留空**（填了公共 DNS 会被轮询绕过劫持）→ 打开 设置 → 用户指南 → 弹证书警告**选择继续**（自签证书的正常现象）→ 落到 all-in-one 页面，照常跑漏洞链；elfldr 就绪后页面自动发送 kstuff → etaHEN → ShadowMountPlus，全程无需 PC。

## 三条红线

1. **绝不暴露公网**：53/80/443 只能内网可达。路由器端口转发、QNAP 反向代理里都别碰这几个端口——DNS 一旦暴露等于替全网做解析，HTTP 也会被人蹭站。
2. **证书一年到期**：`start.sh` 幂等（剩余不足 7 天自动重建），但容器若常年不重启，证书过期前手动 `rm -rf certs/ && docker compose restart` 一次即可。
3. **NAS 停机 = PS5 断网**：DNS 全托管后，NAS 不在 PS5 解析不了任何域名——副作用是连升级都做不了，安全上反而可接受。想恢复上网把 DNS 改回自动；改回期间注意别让它自动装了新固件。

## 备选：LXD 一键路线

Container Station 若支持 LXD，可建 Ubuntu 容器直接跑 flex36ty 的 `setup-ps5.sh <容器IP>`（它依赖 systemd，所以 Docker 容器里跑不了）。但它没有更新屏蔽，且只含官方 Relapse 文件（无本仓库的三个 payload 与页面自动发送）——想要完整体验仍推荐上面的 compose 方案。

## 文件说明

| 文件 | 作用 |
|---|---|
| `docker-compose.yml` | macvlan 给容器独立内网 IP（避开 QTS 自占的 80/443），挂仓库根为站点目录 |
| `ps5-dnsmasq.conf` | DNS：接管 `manuals.playstation.net`，屏蔽 PS5/PS4 更新域名，上游国内 DNS |
| `start.sh` | 容器入口：装依赖 → 自签证书（SAN，幂等）→ 起 dnsmasq + nginx（含 `/document` 302） |

仅供教育与研究用途，仅限自有设备；屏蔽更新、修改 DNS 均有风险，见主 README 免责声明。
