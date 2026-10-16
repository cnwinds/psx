# PS5 Relapse · All-in-One

[Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) 的一站式整合版：原仓库只包含漏洞利用链（跑通后 elfldr 监听 `9021`），缺少需要手动发送的 payload。本仓库把它们全部打包进 `payloads/`，并在页面上实现了手动发送——**打开一个页面即可完成全部流程**。

```
PS5 浏览器打开本页
   │
   ├─ 1. WebKit 用户态漏洞（JSC 信息泄露 + 结构化克隆池错配）
   ├─ 2. 内核漏洞（aio_multi_wait UAF）→ 内核读写 + root + 沙箱逃逸
   ├─ 3. kexp 于内核上下文拉起 elfldr，监听 127.0.0.1:9021
   │
   ├─ 4. kstuff.elf          内核补丁：FSELF / FPKG 支持（一切的基础）
   ├─ 5. shadowmountplus.elf 游戏镜像自动挂载（依赖 kstuff 运行）
   ├─ 6. ftpsrv.elf          独立 FTP 服务，监听 2121
   └─ 7. panplay.elf         百度网盘安装器（8734，单独加载）
```

## 组件关系

| 组件 | 作用 | 依赖 | 来源 |
| --- | --- | --- | --- |
| Relapse 漏洞链 | 浏览器 + 内核双阶段提权 | FW 7.00 – 13.60 | [ntfargo/Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) |
| elfldr（已含） | 监听 9021，接收并执行 ELF | 由漏洞链自动拉起 | 随 Relapse 仓库 |
| kstuff.elf | 内核补丁：FSELF / FPKG、挂载支持 | 仅需内核漏洞 | [EchoStretch/kstuff-lite](https://github.com/EchoStretch/kstuff-lite) v1.11（FW 1.00 – 13.60） |
| shadowmountplus.elf | 自动扫描 / 挂载 / 安装游戏镜像（.ffpkg / .exfat / .ffpfs） | kstuff-lite v1.07+ 运行中 | [drakmor/ShadowMountPlus](https://github.com/drakmor/ShadowMountPlus) 1.7beta4（RetroArch 移植版要求 beta4+ 才能访问 USB 盘） |
| ftpsrv.elf | 独立 FTP 服务器（端口 2121），配 ftp.html 网页管理文件 | 仅需 elfldr | [ps5-payload-dev/ftpsrv](https://github.com/ps5-payload-dev/ftpsrv) v0.21.1 |
| panplay.elf | 百度网盘安装器（8734），网页端装游戏 | 仅需 elfldr | [cnwinds/pan-play](https://github.com/cnwinds/pan-play) v0.2.1 |

加载顺序说明：kstuff 先打内核补丁；ShadowMountPlus 需要 kstuff 处于运行状态；ftpsrv / panplay 按需手发（页面不自动加载）。

## 使用方法

### 方式一：一站式页面（推荐）

1. 用 GitHub Pages 或局域网托管本仓库（见下），PS5 浏览器打开 `index.html`。
2. 页面先探测各服务端口存活（elfldr 9021 / ftpsrv 2121 / panplay 8734），**不会自动开始破解**；点「一键破解」再跑漏洞链。
3. 破解成功后出现 payload 面板；插件全部手发——「一键加载」为 kstuff → SMP → ftpsrv（不含 panplay），或各卡片单独发送。
4. 传文件：电脑打开 `/ftp.html`，端口 **2121**；panplay 在页底单独加载，访问 `http://<PS5 IP>:8734`。

### 方式二：PC 手动发送

```bash
nc 192.168.1.100 9021 < kstuff.elf
nc 192.168.1.100 9021 < shadowmountplus.elf
nc 192.168.1.100 9021 < ftpsrv.elf       # 可选：独立 FTP（2121）
nc 192.168.1.100 9021 < panplay.elf      # 可选：百度网盘安装器（8734）
```

### 托管

- **局域网（Windows 一体化）**：双击 `start-host.bat`（或 `python serve.py`）。
- **传文件到 PS5**：`http://<电脑IP>/ftp.html`，端口 2121（ftpsrv）。
- **NAS 自托管**：见 [selfhost/README.md](selfhost/README.md)。

## License

MIT（见 LICENSE）。各 payload 遵循其上游项目协议：kstuff-lite（GPL）、ShadowMountPlus（GPL-3.0）、ftpsrv（随上游 ps5-payload-dev/ftpsrv）、panplay（见上游 cnwinds/pan-play）。
