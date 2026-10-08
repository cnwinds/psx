# 单文件部署（无 SSH · QNAP Container Station 直接粘贴）

为不方便 SSH 登录 NAS 的情况准备的方案：**一个 `docker-compose.yml` 包含全部内容**，不挂载 NAS 上的任何本地文件，Container Station 的 YAML 界面粘贴即可部署。

| 需要的东西 | 来源 | 时机 |
|---|---|---|
| 全部站点内容（all-in-one 页面 + 漏洞链 + 三个 payload） | 公共仓库 [cnwinds/psx](https://github.com/cnwinds/psx) 的 tarball | 容器首次启动下载（约 9 MB） |
| DNS 劫持 + 更新屏蔽 + 自签证书 | dnsmasq + nginx + openssl（apk 安装） | 每次启动 |

站点内容和证书放在 docker **命名卷**里（`ps5-www` / `ps5-certs`），重启不重复下载；删除容器+卷则全部重来。

## 部署步骤

**① 打开 Container Station → 应用程序（Application）→ 创建 → 粘贴 YAML**：把本目录 [`docker-compose.yml`](docker-compose.yml) 的内容整份贴进去。

**② 只改 4 处网络参数**（都在文件里，有 `>>>` 注释标出）：

```yaml
    networks:
      lan:
        ipv4_address: 192.168.1.250   # ← 给容器的固定 IP
...
    driver_opts:
      parent: ovs_eth0                # ← 虚拟交换机开=ovs_eth0，没开=eth0
    ipam:
      config:
        - subnet: 192.168.1.0/24      # ← 你的网段
          gateway: 192.168.1.1        # ← 你的网关
```

DNS 劫持地址**不用改**——脚本启动时自动读取容器自身 IP 写入 dnsmasq 配置。

**③ 点创建/部署**，在容器日志里确认依次出现：

```
ps5-host: container IP = 192.168.1.250 (PS5 首选 DNS 填这个，备用留空)
ps5-host: downloading all-in-one site (first boot)...
ps5-host: site ready (page + exploit + payloads)
ps5-host: all services up — DNS 53 / HTTP 80 / HTTPS 443
```

**④ 验证**（同网段任一电脑，无需登录 NAS）：

```bash
nslookup manuals.playstation.net 192.168.1.250     # 应返回 192.168.1.250
nslookup ps5.update.playstation.net 192.168.1.250  # 应返回 NXDOMAIN（服务器找不到域名）
curl -k https://192.168.1.250/ | head              # 应返回 all-in-one 页面 HTML
```

**⑤ PS5 侧**：设置 → 网络 → 手动 DNS，首选 `192.168.1.250`，**备用留空** → 打开 设置 → 用户指南 → 证书警告选**继续** → all-in-one 页面自动跑完漏洞链并自动发送三个 payload。

## 常见问题（按报错对号入座）

- **`failed to create network ... invalid subinterface vlan name ovs_eth0`**
  NAS 上没有这个网卡名。默认已改为 `eth0`；仍报错就换 `eth1`（双网卡机器）或 `ovs_eth0`（开了虚拟交换机）。网卡名可在 QTS「网络与虚拟交换机 → 接口」里看到（eth0 / eth1 / …）。
- **`The "xxx" variable is not set` 警告**
  旧版问题，已修复（脚本里 shell 的 `$` 全部写成 `$$`）。若你手工编辑过脚本，注意保留 `$$`。
- **`failed to pull image ... registry-1.docker.io`（拉镜像超时）**
  国内访问 Docker Hub 不稳。镜像已默认用国内源 `docker.m.daocloud.io`；仍失败可换 `docker.1ms.run/library/alpine:3.20` 等，或在 Container Station 首选项里配置 Registry 镜像。
- **`curl: (XX) ...` 下载站点失败（首次启动卡在 downloading）**
  GitHub 直连不通。把 `environment:` 里的 `GH_PROXY=` 填上加速前缀（以 `/` 结尾），例如 `https://gh-proxy.com/`（加速站时效性强，失效就换一个），删掉 `ps5-www` 卷后重新部署。
- **NAS 自己的浏览器打不开容器 IP**
  macvlan 的已知隔离特性：宿主机（NAS 本机）访问不了容器，**其他设备（电脑/PS5）可以**。验证请从电脑访问。
- **PS5 打开用户指南是白屏/证书错误无法继续**
  先从电脑 `curl -k https://<容器IP>/` 确认站点正常；证书警告页面选「继续」是正常流程。

## 注意事项

- **仓库必须保持 public**：站点全部内容来自 `github.com/cnwinds/psx` 的 tarball，仓库转私有后新部署的容器将无法下载（已下载的命名卷不受影响）。
- **首次启动需要外网**（GitHub 可达，下载约 9 MB）；之后离线也能起。
- **macvlan 是必须的，不是可选项**：用户指南入口访问的是 `manuals.playstation.net` 的标准 80/443 端口，桥接模式做端口映射会撞上 QTS 自己占用的 443——所以必须让容器拥有独立内网 IP。
- **绝不暴露公网**：53/80/443 不要在路由器做端口转发。
- 证书一年有效期，剩余不足 7 天时重启容器自动重建（Container Station 里重启即可）。
- NAS 停机 = PS5 解析不了任何域名（含更新检查）；恢复上网把 PS5 DNS 改回自动，改回期间别让它自动升级。
- **更新站点内容**（改了页面或升级 payload 后）：更新 GitHub 仓库 → 删除 `ps5-www` 卷 → 重新部署（或用 [selfhost/](../README.md) 完整版直接挂载仓库）。
