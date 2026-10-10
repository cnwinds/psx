# 单文件部署（无 SSH · QNAP Container Station 直接粘贴）

为不方便 SSH 登录 NAS 的情况准备的方案：**一个 compose YAML 包含全部内容**，不挂载 NAS 上的任何本地文件，Container Station 的 YAML 界面粘贴即可部署。

| 需要的东西 | 来源 | 时机 |
|---|---|---|
| 全部站点内容（all-in-one 页面 + 漏洞链 + 三个 payload） | 公共仓库 [cnwinds/psx](https://github.com/cnwinds/psx) 的 tarball | 容器首次启动下载（约 9 MB） |
| DNS 更新屏蔽 + HTTP 服务 | dnsmasq + nginx（apk 安装） | 每次启动 |

站点内容放在 docker **命名卷**（`ps5-www`）里，重启不重复下载；删除容器+卷则全部重来。

## 两个版本怎么选

| | [`docker-compose.yml`](docker-compose.yml)（**主推**） | [`docker-compose-macvlan.yml`](docker-compose-macvlan.yml) |
|---|---|---|
| 网络模式 | 普通桥接 + 端口映射（NAS 的 53/UDP 和 8010） | macvlan 独立内网 IP |
| PS5 入口 | 浏览器手动输 `http://<NAS的IP>:8010/` | 设置 → 用户指南（DNS 劫持直达） |
| DNS 更新屏蔽 | ✅（PS5 DNS 指向 NAS IP） | ✅（PS5 DNS 指向容器 IP） |
| 前提条件 | NAS 的 53/UDP（可关）、8010 端口空闲 | NAS 网卡可作 macvlan parent（见下方排错） |
| 已知坑 | 几乎没有 | QNAP 上常见 `failed to create the macvlan port: device or resource busy`（eth0 被 QTS 网络栈占用）；报 `invalid subinterface vlan name` 则是网卡名不存在 |

先用主推版跑通，想要「用户指南」入口的便利再折腾 macvlan 版。

## 部署步骤（主推 Bridge 版）

**① Container Station → 应用程序 → 创建 → 粘贴 YAML**：贴入 [`docker-compose.yml`](docker-compose.yml) 全文。

**② 需要改的只有一处**：如果 NAS 的 8010 被占用，改 `ports:` 里的 `"8010:80"` 左半边为其他端口（QTS 管理页默认占 8080，避开即可）。

**③ 部署**，容器日志依次出现即成功：

```
ps5-host: downloading all-in-one site (first boot)...
ps5-host: site ready (page + exploit + payloads)
ps5-host: all services up — DNS 53 (update-blocked) / HTTP 8010
```

**④ 验证**（同网段电脑）：

```bash
nslookup ps5.update.playstation.net <NAS的IP>   # 应返回 NXDOMAIN
nslookup www.baidu.com <NAS的IP>                # 应正常解析（DNS 转发工作正常）
浏览器打开 http://<NAS的IP>:8010/               # 应显示 all-in-one 页面
```

**⑤ PS5 侧**：浏览器打开 `http://<NAS的IP>:8010/` → all-in-one 页面自动跑完漏洞链并自动发送三个 payload。

**⑥ 更新屏蔽（默认已启用，UDP 53）**：把 PS5 手动 DNS 首选填 **NAS 的 IP**、备用留空即生效；电脑上 `nslookup ps5.update.playstation.net <NAS的IP>` 应返回 NXDOMAIN。若部署报 53 端口被占（见下方排错），注释掉 YAML 里 `- "53:53/udp"` 重新部署即关闭屏蔽、站点不受影响。

## 用户指南入口（GUIDE_IP，可选）

填了 `environment:` 里的 `GUIDE_IP=<电脑局域网IP>` 并保持 `443:443` 映射后，PS5（DNS 指向这台电脑）打开 **设置 → 用户指南** 或主页的 **健康与安全指南**，会自动落到破解页——和公共破解 DNS 体验一致，全程在自家局域网。打开时弹的证书警告选"继续"即可（自签证书的正常现象）。

不填 `GUIDE_IP` 时该功能关闭，索尼域名照常全拦，纯手输地址用法不受影响。

## Windows Docker Desktop 也能跑这套 YAML

bridge 版没有 macvlan，天然兼容 Docker Desktop（Windows/macOS）——适合"破解日临时在电脑上开一下"的用法：

1. 安装 Docker Desktop → 保存本目录 `docker-compose.yml` 为本地文件 → PowerShell 里 `docker compose up -d`
2. `ipconfig` 查 PC 局域网 IPv4 → 管理员 PowerShell 放行防火墙：
   `New-NetFirewallRule -DisplayName "PS5-Host" -Direction Inbound -LocalPort 8010,53 -Action Allow`
3. PS5 浏览器开 `http://<PC的IP>:8010`；破解期间把 PC 电源计划设为"从不睡眠"
4. 8010/53 映射若被占改 `ports:` 左半边即可；不用 DNS 时可整行删掉 `53` 映射

## 常见问题（按报错对号入座）

- **`The "xxx" variable is not set` 警告**：旧版问题已修复（shell 的 `$` 全部写成 `$$`）。手工编辑脚本时注意保留 `$$`。
- **`failed to pull image ... registry-1.docker.io`（拉镜像超时）**：镜像默认 `docker.m.daocloud.io`（NAS 实测可拉）；拉取失败换 `docker.xuanyuan.me` 或 `docker.1ms.run`（daocloud 对部分网络/IP 会返回 denied）。
- **`curl: (XX) ...` 下载站点失败（卡在 downloading）**：GitHub 直连不通。把 `environment:` 里 `GH_PROXY=` 填上加速前缀（以 `/` 结尾），如 `https://gh-proxy.com/`（加速站时效性强，失效换一个），删掉 `ps5-www` 卷后重新部署。
- **端口 53 冲突**（`bind: address already in use`，53 映射已默认注释）：NAS 上已有 DNS 服务。三类处理：
  1. **是 AdGuard Home / Pi-hole 等容器**（Container Station → 容器 页可看到）→ 不用本容器的 DNS，直接在它的管理界面加屏蔽规则：`ps5.update.playstation.net`、`ps4.update.playstation.net`、`feu01.ps4.update.playstation.net` 全部拒绝解析，PS5 的 DNS 指向它即可，效果等同；
  2. **是 QTS 虚拟交换机自带的 dnsmasq**（「网络与虚拟交换机 → 虚拟交换机」显示已启用）→ 若你不需要虚拟交换机（无 VM/直连容器依赖），停用后取消 53 注释；需要保留则走方案 1 或 3；
  3. **暂时用社区公共屏蔽 DNS**：PS5 手动 DNS 填 `45.56.67.85`（备用留空）——它本身屏蔽索尼更新（代价：依赖第三方，解析全走它）。
- **`failed to create the macvlan port: device or resource busy`**（macvlan 版）：QTS 网络栈占用了 eth0（虚拟交换机/网桥模式）。查「网络与虚拟交换机 → 接口」确认网卡名：把 parent 换成实际存在的空闲物理口（eth1 等）；若所有口都被 QTS 管理，请用主推 Bridge 版。
- **`invalid subinterface vlan name XXX`**（macvlan 版）：parent 写的接口名不存在，换成实际网卡名。
- **PS5 打开页面空白/证书错误**：Bridge 版走 HTTP，不应有证书问题；确认浏览器输的是 `http://`（不是 https）。

## 注意事项

- **仓库必须保持 public**：站点全部内容来自 `cnwinds/psx` 的 tarball，仓库转私有后新部署的容器将无法下载（已下载的命名卷不受影响）。
- **首次启动需要外网**（GitHub 可达或配好 GH_PROXY，下载约 9 MB）；之后离线也能起。
- **绝不暴露公网**：53 和 8010 不要在路由器做端口转发。
- NAS 停机 = PS5 解析不了任何域名（含更新检查）；恢复上网把 PS5 DNS 改回自动，改回期间别让它自动升级。
- **更新站点内容**（改了页面或升级 payload 后）：更新 GitHub 仓库 → 删除 `ps5-www` 卷 → 重新部署。
