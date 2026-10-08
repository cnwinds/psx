# 单文件部署（无 SSH · QNAP Container Station 直接粘贴）

为不方便 SSH 登录 NAS 的情况准备的方案：**一个 `docker-compose.yml` 包含全部内容**，不挂载 NAS 上的任何本地文件，Container Station 的 YAML 界面粘贴即可部署。

| 需要的东西 | 来源 | 时机 |
|---|---|---|
| 漏洞链（offsets/src/elfldr/kexp） | 公共仓库 [cnwinds/Relapse-Exploit](https://github.com/cnwinds/Relapse-Exploit) | 容器首次启动下载 |
| kstuff.elf / etaHEN / shadowmountplus | 官方 GitHub Releases（与本仓库 payloads/ 同版本） | 容器首次启动下载 |
| all-in-one 页面（index.html 等 4 个文件） | **直接内嵌在 YAML 里** | 每次启动重写 |
| DNS 劫持 + 更新屏蔽 + 自签证书 | dnsmasq + nginx + openssl（apk 安装） | 每次启动 |

站点内容和证书放在 docker **命名卷**里（`ps5-www` / `ps5-certs`），重启不重复下载；删除容器+卷则全部重来。

## 部署步骤

**① 打开 Container Station → 应用程序（Application）→ 创建 → 粘贴 YAML**：把本目录 [`docker-compose.yml`](docker-compose.yml) 的内容整份贴进去。

**② 只改 4 处网络参数**（都在文件末尾，有 `>>>` 注释标出）：

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
ps5-host: downloading exploit site (first boot)...
ps5-host: site ready
ps5-host: all services up — DNS 53 / HTTP 80 / HTTPS 443
```

**④ 验证**（同网段任一电脑，无需登录 NAS）：

```bash
nslookup manuals.playstation.net 192.168.1.250     # 应返回 192.168.1.250
nslookup ps5.update.playstation.net 192.168.1.250  # 应返回 NXDOMAIN（服务器找不到域名）
curl -k https://192.168.1.250/ | head              # 应返回 all-in-one 页面 HTML
```

**⑤ PS5 侧**：设置 → 网络 → 手动 DNS，首选 `192.168.1.250`，**备用留空** → 打开 设置 → 用户指南 → 证书警告选**继续** → all-in-one 页面自动跑完漏洞链并自动发送三个 payload。

## 注意事项

- **首次启动需要外网**（下载漏洞链和 payload，约 11 MB）；之后离线也能起。
- **macvlan 是必须的，不是可选项**：用户指南入口访问的是 `manuals.playstation.net` 的标准 80/443 端口，桥接模式做端口映射会撞上 QTS 自己占用的 443——所以必须让容器拥有独立内网 IP。
- **绝不暴露公网**：53/80/443 不要在路由器做端口转发。
- 证书一年有效期，剩余不足 7 天时重启容器自动重建（`docker compose restart`，或 Container Station 里重启容器）。
- NAS 停机 = PS5 解析不了任何域名（含更新检查）；恢复上网把 PS5 DNS 改回自动，改回期间别让它自动升级。
- 想升级 payload 版本：改 `docker-compose.yml` 里对应的三行下载 URL，删掉 `ps5-www` 卷重新部署；或直接用 [selfhost/](../README.md) 完整版。
- 本文件由 [`gen.py`](gen.py) 生成——修改仓库前端文件后，在 `selfhost/onefile/` 下运行 `python gen.py` 重新生成（生成器自动校验内嵌内容与仓库文件一致）。
