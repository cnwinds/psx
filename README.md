# PS5 Relapse · All-in-One

[Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) 的一站式整合版：原仓库只包含漏洞利用链（跑通后 elfldr 监听 `9021`），缺少需要手动发送的 payload。本仓库把它们全部打包进 `payloads/`，并在页面上实现了自动发送——**打开一个页面即可完成全部流程**。

```
PS5 浏览器打开本页
   │
   ├─ 幕一 · 破解（检测已破解则自动跳过，绝不重复运行）
   │   ├─ 1. WebKit 用户态漏洞（JSC 信息泄露 + 结构化克隆池错配）
   │   ├─ 2. 内核漏洞（aio_multi_wait UAF）→ 内核读写 + root + 沙箱逃逸
   │   └─ 3. kexp 于内核上下文拉起 elfldr，监听 127.0.0.1:9021
   │
   └─ 幕二 · 加载 ELF（可排序、可勾选，按顺序自动发送，已加载的自动跳过）
       ├─ 4. kstuff.elf          内核补丁：FSELF / FPKG 支持（一切的基础）
       ├─ 5. shadowmountplus.elf 游戏镜像自动挂载（依赖 kstuff 运行）
       ├─ 6. zftpd.elf           FTP(2120) + ZHTTP 网页文件管理(8888)
       └─ 7. websrv.elf          网页发送器（8080，手机扫码追发任意 payload）
```

## 组件关系

| 组件 | 作用 | 依赖 | 来源 |
| --- | --- | --- | --- |
| Relapse 漏洞链 | 浏览器 + 内核双阶段提权 | FW 7.00 – 13.60 | [ntfargo/Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) |
| elfldr（已含） | 监听 9021，接收并执行 ELF | 由漏洞链自动拉起 | 随 Relapse 仓库 |
| kstuff.elf | 内核补丁：FSELF / FPKG、挂载支持 | 仅需内核漏洞 | [EchoStretch/kstuff-lite](https://github.com/EchoStretch/kstuff-lite) v1.11（FW 1.00 – 13.60） |
| shadowmountplus.elf | 自动扫描 / 挂载 / 安装游戏镜像（.ffpkg / .exfat / .ffpfs） | kstuff-lite v1.07+ 运行中 | [drakmor/ShadowMountPlus](https://github.com/drakmor/ShadowMountPlus) 1.7beta5-fix1（RetroArch 移植版要求 beta4+ 才能访问 USB 盘） |
| zftpd.elf | FTP 文件服务（端口 2120，任意账号可登录）+ ZHTTP 网页文件管理（8888），浏览器直连管理文件 | 仅需 elfldr | [seregonwar/zftpd](https://github.com/seregonwar/zftpd) v1.6.0 |
| websrv.elf | 网页发送器：PS5 端 8080 网页，手机/电脑扫码即可向主机追发任意 ELF/BIN payload | 仅需 elfldr | [ps5-payload-dev/websrv](https://github.com/ps5-payload-dev/websrv) v0.34 |

加载顺序说明：kstuff 先打内核补丁；ShadowMountPlus 需要 kstuff 处于运行状态，并自带 kstuff 自动暂停/恢复逻辑（游戏启动时暂停 kstuff、退出时恢复）；zftpd、websrv 独立运行，任何时候按需发送即可。

## 使用方法

### 方式一：一站式页面（推荐）

1. 用 GitHub Pages 或局域网托管本仓库（见下），PS5 浏览器打开 `index.html`。
2. 页面分两幕：**幕一「破解」**先探测本机是否已在破解状态（elfldr 9021 在线即整段跳过——重复运行内核漏洞可能死机，页面不会自动重跑）；确认未破解则**自动开始**漏洞链并**自动加载**幕二勾选的 ELF，全程无需按键。浏览器阶段偶发失败——刷新即可自动重跑，内核阶段若死机则重启主机再来。探测接口失灵时自动开始会退化为手动确认（防误判重复破解）。非 PS5 设备打开会显示电脑视图（下载、服务扫码、发送命令）。
3. 日志出现 `elfldr is listening on port 9021` 后幕二自动解锁。ELF 列表**可勾选（是否加载）、可排序（↑↓ 调整顺序）**并保存在本机；发送前会探测端口**跳过已加载的组件**（zftpd 监听 2120/8888、websrv 监听 8080 即视为已加载；kstuff / ShadowMountPlus 无监听端口、探测不到，始终照发）；页面通过 ROP 直接向 `127.0.0.1:9021` 发送字节流，全程无需 PC 参与。
4. 主机屏幕弹出 ShadowMount+ 通知、链尾端口验证显示 9021 与 2120 都在监听即成功；电脑/手机浏览器打开 zftpd 自带的 ZHTTP（`http://<PS5的IP>:8888`）即可传文件；websrv 加载后手机访问 `http://<PS5的IP>:8080` 可直接追发 payload。

### 方式二：PC 手动发送

页面跑完漏洞链后，用 PC 向主机 9021 端口发送（文件可在页面「文件下载」区或本仓库 `payloads/` 直接下载）：

```bash
# Linux / macOS（IP 换成你的 PS5）
nc 192.168.1.100 9021 < kstuff.elf
nc 192.168.1.100 9021 < shadowmountplus.elf
nc 192.168.1.100 9021 < zftpd.elf       # 可选：FTP(2120) + ZHTTP(8888)
nc 192.168.1.100 9021 < websrv.elf      # 可选：网页发送器（8080）
```

Windows 可用 [etaHEN 仓库](https://github.com/etaHEN/etaHEN) 的 `send_payload.ps1`。

### 托管

- **GitHub Pages**：Fork/推送到你的仓库 → Settings → Pages → 选择 main 分支 → 用 `https://<用户名>.github.io/psx/` 访问。
- **局域网（Windows 一体化）**：双击 `start-host.bat`（或 `python serve.py`）——一个进程全包：HTTP 80 站点 + HTTPS 443 用户指南入口（自动证书）+ DNS 53（索尼域名全拦、manuals 劫持；例外放行 `store.playstation.com` / `image.api.playstation.com` 供商店元数据与封面抓取）。需放行防火墙 53/80/443；若 53 被占多为 Windows 的 ICS/移动热点（管理员执行 `net stop sharedaccess` 释放，或在 services.msc 禁用 Internet Connection Sharing），代理客户端（Clash/mihomo）的 DNS 监听也会占 53。PS5 DNS 首选填电脑 IP 即启用拦截+指南入口。
- **传文件到 PS5（ZHTTP 网页文件管理）**：zftpd 加载后，与 PS5 同一局域网的电脑/手机浏览器直接打开 `http://<PS5的IP>:8888`（首页导航「构造体文件库」和 ZHTTP 二维码卡片都指向这里），无需安装客户端、也不经本机中转。支持文件夹拖拽上传（游戏镜像放 `/data/homebrew`，ShadowMountPlus 约 15 秒自动扫描；RetroArch、BIOS、ROM 都能传）、浏览/新建/重命名/复制/删除、下载与打包 zip。习惯 FTP 客户端（FileZilla 等）也可直连 `<PS5的IP>:2120`，任意账号可登录。
- **NAS 全套自托管（推荐）**：见 [selfhost/README.md](selfhost/README.md)——dnsmasq + nginx 容器（QNAP Container Station/macvlan），DNS 接管「用户指南」入口直达本页，并屏蔽索尼更新域名防手滑升级，不依赖任何公共 exploit DNS。NAS 不方便 SSH 的用 [selfhost/onefile/ 单文件版](selfhost/onefile/README.md)：一个 YAML 粘贴即部署。

## 游戏镜像（ShadowMountPlus）

- 推荐格式 `.ffpkg`（UFS）；`.exfat` 用于需要外接盘兼容性的游戏；`.ffpfs` 为实验性。
- 镜像根目录必须直接是游戏文件（如 `/sce_sys/param.json`），不能再套一层文件夹。
- 默认扫描 `/data/homebrew`（首选）、`/data/etaHEN/games`、`/data/shadowmount` 及全部 USB/扩展盘根目录，约每 15 秒自动扫描；可用 `/data/shadowmount/config.ini` 的 `scanpath=` 自定义。
- 配置详见 [ShadowMountPlus README](https://github.com/drakmor/ShadowMountPlus#readme)。

## 街机模拟器（RetroArch PS5 移植版）

破解态下可玩街机/复古游戏：[mihawk-99/PS5_RetroArch](https://github.com/mihawk-99/PS5_RetroArch)（原生移植，33 核心 44 平台），街机用 **FBNeo**（CPS1/CPS2/Neo Geo/世嘉 System16 等，推荐）或 **MAME 0.289**（ROM 集必须匹配该版本）核心。

安装（二选一）：

- **手动安装**：从 [Releases](https://github.com/mihawk-99/PS5_RetroArch/releases) 下载解压，把 `PPSA99169` 文件夹传到 `/data/homebrew/` 下——用 ZHTTP 网页（`http://<PS5的IP>:8888`）拖拽上传即可，也可用 FileZilla 连 FTP（端口 2120）

注意：

- **需要 ShadowMountPlus 1.7beta4+**（本仓库已打包）才能读到 USB 盘和扩展存储
- ROM 放 USB 盘（`/mnt/usb0` 起）或内置 `content/` 目录；街机 ROM 集：FBNeo 用对应版本的 ROM set（网上搜 "FBNeo romset"），MAME 必须是 **0.289 版**匹配集
- 部分 BIOS 放 `system/` 相应子目录，用 ZHTTP 网页或 FTP 上传
- RetroArch 自带 WebUI：`http://<PS5的IP>:6769`（仅内网使用）

## 稳定性提示

- WebKit 阶段可能需要多次尝试，浏览器卡死就刷新页面。
- 内核阶段可能挂起或 panic 主机，遇到就重启再试。
- 每次重启后 kstuff / ShadowMountPlus 均需重新加载（重跑本页流程即可），独立 FTP 按需再发。

## 稳定性提示之外的免责声明

本项目仅供**教育与安全研究用途**，仅限在自有/授权设备上使用，不支持盗版或未经授权的访问。使用风险（系统不稳定、数据丢失、账号封禁等）由使用者自行承担。请遵守当地法律法规。

## 致谢

- **Relapse 漏洞链**：Sonic_Iso（内核漏洞）、Jordy（WebKit 漏洞与内核 bug）、ntfargo、ufm42（漏洞开发）、Dr. Yenyen（测试），以及 TheFlow、SlidyBat、Flatz、cow、nhk、bollarz、Sleirsgoevy、EchoStretch、EarthOnion
- **kstuff 系列**：sleirsgoevy、zecoxao、flatz、idlesauce、buzzer-re、Al-Azif、EchoStretch、drakmor
- **zftpd**：Seregon（seregonwar）
- **websrv**：John Tornblom（ps5-payload-dev）
- **ShadowMountPlus**：drakmor（ShadowMount 的开源延续）
- 页面自动发送思路参考社区 all-in-one host（ps5jb 等）

## License

MIT（见 LICENSE，漏洞链部分版权 Nathan Fargo）。各 payload 遵循其上游项目协议：kstuff-lite（GPL）、ShadowMountPlus（GPL-3.0）、zftpd（见上游 seregonwar/zftpd）、websrv（见上游 ps5-payload-dev/websrv）。
