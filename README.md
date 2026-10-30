# PS5 Relapse · All-in-One

[Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) 的一站式整合版。PS5 上点击「开始提权」后开始：`127.0.0.1:9021` 已在监听就跳过内核，否则与上游相同并拉起 elfldr。本仓库只在其后按顺序加载 `payloads/` 里的 ELF。

```
PS5 浏览器打开本页
   │
   ├─ 幕一 · 破解（点击「开始提权」后开始）
   │   ├─ 1. WebKit 用户态漏洞（JSC 信息泄露 + 结构化克隆池错配）
   │   ├─ 2. 若 127.0.0.1:9021 已在监听，跳过内核，直接进入幕二
   │   └─ 3. 否则与 Relapse 相同：内核漏洞 → kexp 拉起 elfldr
   │
   └─ 幕二 · 加载 ELF（可排序、可勾选，按顺序自动发送，已加载的自动跳过）
       ├─ 4. kstuff.elf          内核补丁：FSELF / FPKG 支持（一切的基础）
       ├─ 5. ftpsrv.elf          FTP 文件服务（2121，一键链默认加载）
       └─ 6. panplay.elf         盘游 · 百度网盘直装（8734，一键链末尾）
```

## 组件关系

| 组件 | 作用 | 依赖 | 来源 |
| --- | --- | --- | --- |
| Relapse 漏洞链 | 浏览器 + 内核双阶段提权 | FW 7.00 – 13.60 | [ntfargo/Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) |
| elfldr（已含） | 监听 9021，接收并执行 ELF | 由漏洞链自动拉起 | 随 Relapse 仓库 |
| kstuff.elf | 内核补丁：FSELF / FPKG、挂载支持 | 仅需内核漏洞 | [EchoStretch/kstuff-lite](https://github.com/EchoStretch/kstuff-lite) v1.11（FW 1.00 – 13.60） |
| ftpsrv.elf | FTP 文件服务，监听 **2121**（任意账号可登录） | 仅需 elfldr | [ps5-payload-dev/ftpsrv](https://github.com/ps5-payload-dev/ftpsrv) v0.21.1 |
| panplay.elf | 百度网盘直装（盘游），浏览器打开 :8734 扫码登录网盘并安装游戏 | 仅需 elfldr；**勿与 ShadowMountPlus 同时运行** | [cnwinds/pan-play](https://github.com/cnwinds/pan-play) v0.16.4 |
| shadowmountplus.elf | 自动扫描 / 挂载 / 安装游戏镜像（.ffpkg / .exfat / .ffpfs） | kstuff-lite v1.07+ 运行中 | [drakmor/ShadowMountPlus](https://github.com/drakmor/ShadowMountPlus) 1.7beta11 |
| websrv.elf | 网页发送器：PS5 端 8080 网页，手机/电脑扫码即可向主机追发任意 ELF/BIN payload | 仅需 elfldr | [ps5-payload-dev/websrv](https://github.com/ps5-payload-dev/websrv) v0.34 |

**默认一键加载顺序**：`kstuff → ftpsrv → panplay`（panplay 固定最后）。elfldr 由提权链路拉起，不在这个列表里。ShadowMountPlus、websrv 仍在 `payloads/`，需要时从搜索加入。

**从目录加入：**幕二搜索框读取同源 `payloads/payload_map.js`。自建主机能联网时回源 <http://45.56.67.85/payloads/payload_map.js>，失败用仓库快照；GitHub Pages 使用快照。kstuff、ftpsrv、panplay 会混在搜索结果里，删掉后可以再加回来，用的是本站已有的文件。「加入」其他 ELF 时，本站把文件下载到 `payloads/library/`（容器里是 `ps5-library` 卷）。之后 elfldr 只从本站加载。「更新版本」按 GitHub 仓库对照目录，有新版本就把文件写进 `payloads/library/` 再改列表上的版本号。列表里还有 panplay 时，另向 GitHub 原站查 `cnwinds/pan-play` 的最新发行版，有新版本同样写入 `payloads/library/panplay.elf`。GitHub Pages 没有保存接口，只能加载仓库里自带的这三个。

**更新 panplay**：`python scripts/sync_panplay.py --readme`

**检查/同步全部 payload**（对照各仓库 GitHub Latest Release，默认 gh-proxy）：

```bash
python scripts/sync_payloads.py --check
python scripts/sync_payloads.py --sync
```

## 使用方法

### 方式一：一站式页面（推荐）

1. 用 GitHub Pages 或局域网托管本仓库（见下），PS5 浏览器打开 `index.html`。
2. 页面分两幕：**幕一「破解」**在 PS5 且固件可用时显示「开始提权」。点击后先做 WebKit，再连一次 `127.0.0.1:9021`。已经在监听就直接进入加载；没通才走与 [Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) 相同的内核链，拉起 elfldr。刷新页面后 elfldr 还在时，再点同一按钮会走前一条。
3. 提权前即可在幕二调整顺序、勾选，或搜索并把 ELF 存进本站，选择记在本机。日志出现 `elfldr is listening on port 9021` 后，幕二出现「一键加载」。点击后按勾选顺序加载（默认 `kstuff → ftpsrv → panplay`）。elfldr 只从本站下载，浏览器不读取 ELF。
4. 默认链跑完后 FTP 连 `<PS5 IP>:2121` 传文件，浏览器打开 `http://<PS5 IP>:8734` 使用盘游。ShadowMountPlus、websrv 从搜索加入后再用。

### 方式二：PC 手动发送

页面跑完漏洞链后，用 PC 向主机 9021 端口发送（文件可在页面「文件下载」区或本仓库 `payloads/` 直接下载）：

```bash
# Linux / macOS（IP 换成你的 PS5）
nc 192.168.1.100 9021 < kstuff.elf
nc 192.168.1.100 9021 < ftpsrv.elf
nc 192.168.1.100 9021 < panplay.elf         # 盘游 / 百度网盘直装（8734）
nc 192.168.1.100 9021 < shadowmountplus.elf  # 可选
nc 192.168.1.100 9021 < websrv.elf           # 可选：网页发送器（8080）
```

Windows 可用 [etaHEN 仓库](https://github.com/etaHEN/etaHEN) 的 `send_payload.ps1`。

### 托管

- **GitHub Pages**：Fork/推送到你的仓库 → Settings → Pages → 选择 main 分支 → 用 `https://<用户名>.github.io/psx/` 访问。
- **局域网（Windows 一体化）**：双击 `start-host.bat`（或 `python serve.py`）——一个进程全包：HTTP 80 站点 + HTTPS 443 用户指南入口（自动证书）+ DNS 53（索尼域名全拦、manuals 劫持；例外放行 `store.playstation.com` / `image.api.playstation.com` 供商店元数据与封面抓取）。需放行防火墙 53/80/443；若 53 被占多为 Windows 的 ICS/移动热点（管理员执行 `net stop sharedaccess` 释放，或在 services.msc 禁用 Internet Connection Sharing），代理客户端（Clash/mihomo）的 DNS 监听也会占 53。PS5 DNS 首选填电脑 IP 即启用拦截+指南入口。
- **NAS 全套自托管（推荐）**：见 [selfhost/README.md](selfhost/README.md)——dnsmasq + nginx 容器（QNAP Container Station/macvlan），DNS 接管「用户指南」入口直达本页，并屏蔽索尼更新域名防手滑升级，不依赖任何公共 exploit DNS。NAS 不方便 SSH 的用 [selfhost/onefile/ 单文件版](selfhost/onefile/README.md)：一个 YAML 粘贴即部署。

## 游戏镜像（ShadowMountPlus）

- 推荐格式 `.ffpkg`（UFS）；`.exfat` 用于需要外接盘兼容性的游戏；`.ffpfs` 为实验性。
- 镜像根目录必须直接是游戏文件（如 `/sce_sys/param.json`），不能再套一层文件夹。
- 默认扫描 `/data/homebrew`（首选）、`/data/etaHEN/games`、`/data/shadowmount` 及全部 USB/扩展盘根目录，约每 15 秒自动扫描；可用 `/data/shadowmount/config.ini` 的 `scanpath=` 自定义。
- 配置详见 [ShadowMountPlus README](https://github.com/drakmor/ShadowMountPlus#readme)。

## 街机模拟器（RetroArch PS5 移植版）

破解态下可玩街机/复古游戏：[mihawk-99/PS5_RetroArch](https://github.com/mihawk-99/PS5_RetroArch)（原生移植，33 核心 44 平台），街机用 **FBNeo**（CPS1/CPS2/Neo Geo/世嘉 System16 等，推荐）或 **MAME 0.289**（ROM 集必须匹配该版本）核心。

安装（二选一）：

- **手动安装**：从 [Releases](https://github.com/mihawk-99/PS5_RetroArch/releases) 下载解压，把 `PPSA99169` 文件夹传到 `/data/homebrew/` 下（可用 PC 经 9021 推送，或第三方文件管理方案）

注意：

- **需要 ShadowMountPlus 1.7beta4+**（本仓库已打包）才能读到 USB 盘和扩展存储
- ROM 放 USB 盘（`/mnt/usb0` 起）或内置 `content/` 目录；街机 ROM 集：FBNeo 用对应版本的 ROM set（网上搜 "FBNeo romset"），MAME 必须是 **0.289 版**匹配集
- 部分 BIOS 放 `system/` 相应子目录
- RetroArch 自带 WebUI：`http://<PS5的IP>:6769`（仅内网使用）

## 稳定性提示

- WebKit 阶段可能需要多次尝试，浏览器卡死就刷新页面。
- 内核阶段可能挂起或 panic 主机，遇到就重启再试。
- 每次重启后 kstuff / ShadowMountPlus 均需重新加载（重跑本页流程即可）。

## 稳定性提示之外的免责声明

本项目仅供**教育与安全研究用途**，仅限在自有/授权设备上使用，不支持盗版或未经授权的访问。使用风险（系统不稳定、数据丢失、账号封禁等）由使用者自行承担。请遵守当地法律法规。

## 致谢

- **Relapse 漏洞链**：Sonic_Iso（内核漏洞）、Jordy（WebKit 漏洞与内核 bug）、ntfargo、ufm42（漏洞开发）、Dr. Yenyen（测试），以及 TheFlow、SlidyBat、Flatz、cow、nhk、bollarz、Sleirsgoevy、EchoStretch、EarthOnion
- **kstuff 系列**：sleirsgoevy、zecoxao、flatz、idlesauce、buzzer-re、Al-Azif、EchoStretch、drakmor
- **panplay（盘游）**：cnwinds
- **ftpsrv / websrv**：John Tornblom（ps5-payload-dev）
- **ShadowMountPlus**：drakmor（ShadowMount 的开源延续）
- 页面自动发送思路参考社区 all-in-one host（ps5jb 等）

## License

MIT（见 LICENSE，漏洞链部分版权 Nathan Fargo）。各 payload 遵循其上游项目协议：kstuff-lite（GPL）、ShadowMountPlus（GPL-3.0）、pan-play（见上游 cnwinds/pan-play）、websrv（见上游 ps5-payload-dev/websrv）。
